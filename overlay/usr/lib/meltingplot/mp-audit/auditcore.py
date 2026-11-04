"""The audit log of one computer, on its own partition.

Requirements: docs/meltingplot-audit-log.md (AL-nn). This module holds the
logic and touches nothing but the directory it is given and the clock it is
handed, so the tests can run it on the build host with a simulated clock and
five years of operating time in seconds. The service (mp-auditd) wraps it
with the partition, the socket and the system's own events.

On the partition, in the directory given:

  own/log/NNNNNNNN.jsonl  the log, in segments of at most 4 MiB, append-only
                          in the filesystem (chattr +a, AL-14)
  own/keys/epoch-N.key    the private key of the open epoch N, 32 bytes; a
                          key is overwritten and removed as soon as the seal
                          of its epoch is written (AL-56)
  own/state.json          counters that would be costly to recompute: the
                          position up to which the log is known, budgets,
                          open summaries, operating time
  archive/                logs ended by a reset (AL-17)

The state file is a cache of the log, not part of the proof: everything in
it that concerns the log is recomputed from the lines written after the
position it names, and the whole log is read when it is missing.
"""

import hashlib
import json
import os
import subprocess
import threading
import time

import auditlog as al

MiB = 1 << 20
DAY = 86400
FIVE_YEARS = int(5 * 365.25 * DAY)

RESERVE = "reserve"
# Shares of the computer's own log (AL-40): 256 MiB of the 512 MiB partition;
# the other half is for the copy of the partner's log (AL-29). The reserve
# pays for the seals of the regular epochs (AL-61).
SHARES = {
    al.STATE: 32 * MiB,
    al.CHANGE: 96 * MiB,
    al.ATTEMPT: 52 * MiB,
    al.OPERATION: 24 * MiB,
    RESERVE: 52 * MiB,
}
# Part of a share that may be spent at once, for short peaks (AL-40). The
# rest arrives with the operating time, so that the share lasts five years.
BURST_DIVISOR = 64

FLUSH_INTERVAL = 5          # AL-51: other than state, written every 5 s
SAVE_INTERVAL = 60          # AL-51: counters at most once a minute
OPTIME_INTERVAL = 600       # AL-51: operating time at most every 10 minutes
EPOCH = 900                 # AL-55: 15 minutes of operating time
EPOCH_SPENT = 3600          # with the reserve spent: one seal an hour
WINDOWS = (60, 3600, DAY)   # AL-41: a summary waits a minute, an hour, a day
SEGMENT_MAX = 4 * MiB
TOP = 10                    # AL-41: the ten most frequent sources and objects
TRACK = 32                  # counted to find them (space-saving)
TOP_LEN = 40
PENDING_MAX = 10000         # entries held while the partition cannot be written
SEAL_COST = 300             # bytes of a seal, charged to whoever caused it


class Clock:
    """The clocks the log uses. Operating time (AL-49) is derived from
    CLOCK_BOOTTIME, which nobody can set; the system clock is only shown."""

    def boottime(self):
        return time.clock_gettime(time.CLOCK_BOOTTIME)

    def boot_id(self):
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip().replace("-", "")

    def utc(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def mono(self):
        return time.monotonic()

    def synced(self):
        return clock_synced()


def clock_synced():
    """Whether the kernel considers the system clock synchronised, as NTP
    clients (timesyncd on the printer SBC, chrony on the panel) report it:
    adjtimex answers TIME_ERROR (5) while it is not."""
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(512)     # struct timex, modes = 0
        return libc.adjtimex(buf) not in (-1, 5)
    except (OSError, AttributeError):
        return False


class Bucket:
    """Budget of one class (AL-40): refills with operating time so that the
    class can never spend more than its share in five years, whatever comes."""

    def __init__(self, share):
        self.cap = share // BURST_DIVISOR
        self.rate = (share - self.cap) / FIVE_YEARS
        self.tokens = float(self.cap)
        self.op = 0.0

    def refill(self, op):
        if op > self.op:
            self.tokens = min(float(self.cap), self.tokens + (op - self.op) * self.rate)
            self.op = op

    def take(self, n, op):
        self.refill(op)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def debit(self, n, op):
        self.refill(op)
        self.tokens -= n


class Summary:
    """Events of one class and id counted instead of written (AL-41). Fixed
    size, whatever and however many events arrive; grouped only by the
    class and id, which the system sets, never by what a caller chooses."""

    def __init__(self, cls, ev, opened):
        self.cls = cls
        self.ev = ev
        self.opened = opened
        self.window = 0
        self.n = 0
        self.first = self.last = None
        self.t0 = self.t1 = None
        self.op0 = self.op1 = None
        self.src = {}
        self.obj = {}
        self.digest = al.ZERO
        self.last_event = None

    @staticmethod
    def _count(table, key):
        key = key[:TOP_LEN]
        if key in table:
            table[key] += 1
        elif len(table) < TRACK:
            table[key] = 1
        else:
            low = min(table, key=lambda k: (table[k], k))
            table[key] = table.pop(low) + 1

    def add(self, e):
        self.n += 1
        if self.first is None:
            self.first, self.t0, self.op0 = e["seq"], e["t"], e["op"]
        self.last, self.t1, self.op1 = e["seq"], e["t"], e["op"]
        self._count(self.src, e.get("actor") or e.get("via") or "")
        self._count(self.obj, e.get("obj") or "")
        h = hashlib.sha256(al.canon(e).encode("ascii")).hexdigest()
        self.digest = hashlib.sha256((self.digest + h).encode("ascii")).hexdigest()
        self.last_event = {k: e[k] for k in ("seq", "t", "op", "res", "actor", "via", "obj", "msg") if k in e}
        for k in ("actor", "via", "obj", "msg"):
            if k in self.last_event:
                self.last_event[k] = self.last_event[k][:TOP_LEN]

    def due(self, op):
        return op >= self.opened + WINDOWS[self.window]

    @staticmethod
    def _top(table, n):
        top = sorted(table.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP]
        return [[k, c] for k, c in top], n - sum(c for _, c in top)

    def agg(self):
        src, src_other = self._top(self.src, self.n)
        obj, obj_other = self._top(self.obj, self.n)
        return {
            "n": self.n, "from": self.first, "to": self.last,
            "t0": self.t0, "t1": self.t1, "op0": self.op0, "op1": self.op1,
            "window": WINDOWS[self.window],
            "src": src, "src_other": src_other, "obj": obj, "obj_other": obj_other,
            "digest": self.digest, "last": self.last_event,
        }

    def to_json(self):
        return dict(self.__dict__)

    @classmethod
    def from_json(cls, d):
        s = cls(d["cls"], d["ev"], d["opened"])
        s.__dict__.update(d)
        return s


class AuditCore:
    """The log of this computer. Thread safe: every public method takes the
    lock, so the socket threads of the service can record concurrently."""

    def __init__(self, root, ident, clock=None, journal=None, shares=None,
                 append_only=True):
        self.root = root
        self.own = os.path.join(root, "own")
        self.logdir = os.path.join(self.own, "log")
        self.keydir = os.path.join(self.own, "keys")
        self.statefile = os.path.join(self.own, "state.json")
        self.ident = ident
        self.clock = clock or Clock()
        self.journal = journal or (lambda e, note=None: None)
        self.shares = dict(shares or SHARES)
        self.append_only = append_only
        self.lock = threading.RLock()
        self.stats = {"bytes": 0, "fsyncs": 0, "flushes": 0}
        self.healthy = True
        self.fault = None
        self.notes = []
        self.extra = {}
        self._reset_memory()

    def _reset_memory(self):
        self.start = None
        self.next_seq = 1
        self.acc = 0
        self.seg = 1
        self.off = 0
        self.prev = al.ZERO
        self.epoch = 0
        self.pub = None
        self.key = None
        self.unsealed = 0
        self.last_ev = {}
        self.used = {c: 0 for c in self.shares}
        self.buckets = {c: Bucket(s) for c, s in self.shares.items()}
        self.summaries = {}
        self.pending = []
        self.boot = 0
        self.bid = None
        self.op_base = 0.0
        self.op_saved = 0.0
        self.epoch_op = 0.0
        self.last_flush = self.clock.mono()
        self.last_save = self.clock.mono()
        self.dirty = False
        self.torn = None
        self.need_newline = False
        self.prev_clean = True
        self.prev_bid = None
        self.lost = 0
        self.recovered = []

    # --- time ------------------------------------------------------------------

    def op(self):
        """Operating time in seconds, summed over every boot (AL-49)."""
        return self.op_base + self.clock.boottime()

    # --- files -----------------------------------------------------------------

    def _segpath(self, n):
        return os.path.join(self.logdir, "%08d.jsonl" % n)

    def segments(self):
        try:
            names = sorted(n for n in os.listdir(self.logdir) if n.endswith(".jsonl"))
        except FileNotFoundError:
            return []
        return [int(n[:-6]) for n in names if n[:-6].isdigit()]

    @staticmethod
    def _fsync_dir(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _chattr(self, flag, path):
        if not self.append_only:
            return
        try:
            subprocess.run(["chattr", flag, path], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            self.notes.append(("chattr", "cannot set %s on %s" % (flag, path)))

    def _append(self, data):
        path = self._segpath(self.seg)
        if self.off and self.off + len(data) > SEGMENT_MAX:
            self.seg += 1
            self.off = 0
            path = self._segpath(self.seg)
        new = not os.path.exists(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            if new:
                self._fsync_dir(self.logdir)
                self._chattr("+a", path)
            written = 0
            while written < len(data):
                written += os.write(fd, data[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        self.off += len(data)
        self.stats["bytes"] += len(data)
        self.stats["fsyncs"] += 1

    def _write_lines(self, objs):
        """Chain, serialise and append entries or seals, durably."""
        lines = []
        prev = self.prev
        for obj in objs:
            obj["prev"] = prev
            line = al.canon(obj)
            prev = al.line_hash(line)
            lines.append(line)
        data = ("\n".join(lines) + "\n").encode("ascii")
        if self.need_newline:
            data = b"\n" + data
        self._append(data)
        self.need_newline = False
        self.prev = prev
        for obj, line in zip(objs, lines):
            self._account(obj, len(line) + 1)
        return lines

    def _account(self, obj, size, debit=False):
        """What a line written means for the counters. Shared by writing and
        by reading back what the state file does not know yet; reading back
        also charges the budgets, which were charged before the crash only
        in memory."""
        if "seal" in obj or "rekey" in obj:
            self.epoch = obj.get("seal", obj.get("rekey")) + 1
            self.pub = obj["next"]
            self.unsealed = 0
            self.used[RESERVE] = self.used.get(RESERVE, 0) + size
            if debit:
                self.buckets[RESERVE].tokens -= size
            return
        if "genesis" in obj:
            self.pub = obj["genesis"]["pub"]
        cls = obj.get("cls", al.OPERATION)
        if cls not in self.buckets:
            cls = al.OPERATION
        self.used[cls] = self.used.get(cls, 0) + size
        if debit:
            self.buckets[cls].tokens -= size
        self.unsealed += 1
        self.acc += 1
        agg = obj.get("agg")
        if isinstance(agg, dict):
            self.acc += agg.get("n", 0)
        data = obj.get("data")
        if obj.get("ev") == "E17" and isinstance(data, dict) and isinstance(data.get("lost"), int):
            self.acc += data["lost"]
        self.last_ev[obj["ev"]] = obj["seq"]
        self.next_seq = max(self.next_seq, obj["seq"] + 1)

    # --- keys ------------------------------------------------------------------

    def _keypath(self, n):
        return os.path.join(self.keydir, "epoch-%d.key" % n)

    def _store_key(self, n, key):
        path = self._keypath(n)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, al.key_to_bytes(key))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(path + ".tmp", path)
        self._fsync_dir(self.keydir)

    def _wipe_key(self, path):
        """Overwrite in place, then remove: the key of a sealed epoch must not
        be readable from the partition any more (AL-56)."""
        try:
            fd = os.open(path, os.O_WRONLY)
        except FileNotFoundError:
            return
        try:
            size = os.fstat(fd).st_size
            os.write(fd, b"\0" * max(size, 32))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.unlink(path)

    def _wipe_keys_except(self, keep):
        for name in os.listdir(self.keydir):
            path = os.path.join(self.keydir, name)
            if path != keep:
                self._wipe_key(path)
        self._fsync_dir(self.keydir)

    def _load_key(self):
        path = self._keypath(self.epoch)
        try:
            with open(path, "rb") as f:
                key = al.key_from_bytes(f.read())
            if al.public_text(key) == self.pub:
                self.key = key
                self._wipe_keys_except(path)
                return True
        except (OSError, ValueError):
            pass
        return False

    def _rekey(self):
        """The key of the open epoch is gone or does not match what the log
        announced. Without it the epoch cannot be sealed; the log goes on
        with a new key that nobody vouched for, and says so (AL-11)."""
        key = al.new_key()
        self._store_key(self.epoch + 1, key)
        old = self.epoch
        self._write_lines([{"rekey": old, "op": int(self.op()), "boot": self.boot,
                            "t": self.clock.utc(), "next": al.public_text(key)}])
        self.key = key
        self.epoch_op = self.op()
        self._wipe_keys_except(self._keypath(self.epoch))
        self.notes.append(("rekey", "key of epoch %d lost; it cannot be sealed" % old))

    # --- state -----------------------------------------------------------------

    def _state(self):
        return {
            "format": al.FORMAT, "start": self.start, "seq": self.next_seq,
            "acc": self.acc, "seg": self.seg, "off": self.off, "prev": self.prev,
            "epoch": self.epoch, "pub": self.pub, "unsealed": self.unsealed,
            "last_ev": self.last_ev, "used": self.used,
            "buckets": {c: [b.tokens, b.op] for c, b in self.buckets.items()},
            "summaries": {k: s.to_json() for k, s in self.summaries.items()},
            "boot": self.boot, "bid": self.bid, "op_base": self.op_base,
            "op": self.op(), "clean": False, "extra": self.extra,
            "saved": self.clock.utc(),
        }

    def save_state(self, clean=False):
        st = self._state()
        st["clean"] = clean
        tmp = self.statefile + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.statefile)
        self._fsync_dir(self.own)
        self.stats["fsyncs"] += 2
        self.op_saved = st["op"]
        self.last_save = self.clock.mono()
        self.dirty = False

    def _load_state(self):
        try:
            with open(self.statefile) as f:
                st = json.load(f)
            if st.get("format") != al.FORMAT:
                raise ValueError("format")
            return st
        except FileNotFoundError:
            return None
        except ValueError:
            self.notes.append(("state", "state file unreadable, log read in full"))
            return None

    # --- opening ---------------------------------------------------------------

    def open(self, recover=None):
        """Read what is there. Returns "new" when the log has to start with a
        genesis entry, "open" otherwise. Anomalies end up in self.notes for
        the service to record.

        recover(boot_id, first) lists the entries numbered from first on that
        the journal knows of a boot whose end was not clean, as (seq, entry)
        in order. It runs before this start numbers anything, so the numbers
        a crash left unaccounted are known (self.lost) and none is used
        twice; the service records them with E17 and puts back what the
        journal still had (self.recovered)."""
        with self.lock:
            self._reset_memory()
            self.notes = []
            for d in (self.own, self.logdir, self.keydir):
                os.makedirs(d, mode=0o750, exist_ok=True)
            st = self._load_state()
            segs = self.segments()
            if not segs or all(os.path.getsize(self._segpath(s)) == 0 for s in segs):
                if st and st.get("start"):
                    self.notes.append(("missing", "the log of start hash %s is gone" % st["start"]))
                self._boots(st)
                self.extra = (st or {}).get("extra", {})
                self.seg = 1
                return "new"

            known = st and st.get("seg") in segs and st.get("off", 0) <= os.path.getsize(self._segpath(st["seg"]))
            if known:
                self.start = st["start"]
                self.next_seq = st["seq"]
                self.acc = st["acc"]
                self.seg, self.off = st["seg"], st["off"]
                self.prev = st["prev"]
                self.epoch, self.pub = st["epoch"], st["pub"]
                self.unsealed = st["unsealed"]
                self.last_ev = st["last_ev"]
                self.used.update(st["used"])
                for c, (tokens, op) in st["buckets"].items():
                    if c in self.buckets:
                        self.buckets[c].tokens, self.buckets[c].op = tokens, op
                self.summaries = {k: Summary.from_json(v) for k, v in st["summaries"].items()}
                self.extra = st.get("extra", {})
            else:
                if st:
                    # A log shorter than the state remembers was cut off
                    # from outside; worth an entry either way.
                    self.notes.append(("state", "state file does not match the log, log read in full"))
                    self.extra = st.get("extra", {})
                else:
                    self.notes.append(("state", "state file missing, log read in full"))
                self.seg, self.off = segs[0], 0
            self._scan(segs)

            self._boots(st)
            self.epoch_op = self.op()

            seen = []
            if not self.prev_clean and self.prev_bid and recover:
                seen = recover(self.prev_bid, self.next_seq)
            known = max([self.next_seq - 1] + [seq for seq, _ in seen])
            counted = self.acc + sum(s.n for s in self.summaries.values())
            self.lost = max(0, known - counted)
            self.recovered = seen
            self.next_seq = known + 1

            # Right after the unreadable rest of a crashed write, before
            # anything else, so the check can step over it.
            if self.torn:
                n, h = self.torn
                self.record("E17", "info", force=True,
                            msg="incomplete line at the end of the log, left by a crash",
                            data={"torn": n, "torn_sha256": h})
                self.flush()
            if not self._load_key():
                self._rekey()
            return "open"

    def _boots(self, st):
        """Boot counter and operating time (AL-49). A new boot starts from
        the operating time last written; within the same boot the service
        was restarted and carries on from the base of this boot."""
        st = st or {}
        bid = self.clock.boot_id()
        if st.get("bid") == bid:
            self.boot = st["boot"]
            self.op_base = st["op_base"]
        else:
            self.boot = st.get("boot", 0) + 1
            self.op_base = st.get("op", 0.0)
        self.bid = bid
        self.prev_clean = bool(st.get("clean"))
        self.prev_bid = st.get("bid")

    def _scan(self, segs):
        """Read the lines after the known position into the counters."""
        self.torn = None
        for s in segs:
            if s < self.seg:
                continue
            path = self._segpath(s)
            with open(path, "rb") as f:
                f.seek(self.off if s == self.seg else 0)
                data = f.read()
            if s != self.seg:
                self.seg, self.off = s, 0
            pos = 0
            while pos < len(data):
                end = data.find(b"\n", pos)
                complete = end >= 0
                raw = data[pos:end] if complete else data[pos:]
                text = raw.decode("utf-8", "surrogateescape")
                try:
                    obj = json.loads(text) if raw.strip(b"\0") else None
                    if not isinstance(obj, dict):
                        raise ValueError
                except ValueError:
                    obj = None
                if obj is None or not complete:
                    if raw:
                        # Only a crash in the middle of a write leaves this,
                        # and only at the end. Not chained into anything.
                        self.torn = (len(raw), al.line_hash(text))
                        self.need_newline = not complete
                    pos = (end + 1) if complete else len(data)
                    self.off += len(raw) + (1 if complete else 0)
                    continue
                self.torn = None
                if self.start is None:
                    self.start = al.line_hash(text)
                self._account(obj, len(raw) + 1, debit=True)
                self.prev = al.line_hash(text)
                pos = end + 1
                self.off += len(raw) + 1
        if self.torn is None:
            self.need_newline = False

    # --- entries ---------------------------------------------------------------

    def _entry(self, ev, res, actor="", via="", obj="", msg="", data=None):
        idt = self.ident()
        e = {
            "seq": self.next_seq, "boot": self.boot, "bid": self.bid,
            "t": self.clock.utc(), "sync": bool(self.clock.synced()),
            "op": int(self.op()),
            "sys": al.clean(idt.get("sys", ""), 16), "host": al.clean(idt.get("host", ""), 64),
            "mach": al.clean(idt.get("mach", ""), 64), "img": al.clean(idt.get("img", ""), 64),
            "ev": ev, "cls": al.class_of(ev, res) if res != al.AGGREGATED else None, "res": res,
        }
        if actor:
            e["actor"] = al.clean(actor, 64)
        if via:
            e["via"] = al.clean(via, 32)
        if obj:
            e["obj"] = al.clean(obj, 256)
        if msg:
            e["msg"] = al.clean(msg, 256)
        if data:
            e["data"] = al.clean_data(data)
        self.next_seq += 1
        return e

    @staticmethod
    def _cost(e):
        return len(al.canon(dict(e, prev=al.ZERO))) + 1

    def genesis(self, msg="audit log created", data=None):
        """The first entry (E01, AL-57): the public key of epoch 0, the
        identity of the computer and whatever the caller adds. Its hash is
        the start hash."""
        with self.lock:
            key = al.new_key()
            self._store_key(0, key)
            self._wipe_keys_except(self._keypath(0))
            self.key = key
            self.epoch = 0
            e = self._entry("E01", "done", msg=msg, data=data)
            e["genesis"] = {"format": al.FORMAT, "alg": al.ALG, "pub": al.public_text(key)}
            self.prev = al.ZERO
            lines = self._write_lines([e])
            self.start = al.line_hash(lines[0])
            self.epoch_op = self.op()
            self.journal(e, "genesis")
            self.save_state()
            return self.start

    def record(self, ev, res, actor="", via="", obj="", msg="", data=None,
               sync=False, force=False):
        """Accept one event. Returns its sequence number.

        Written at the next flush, within five seconds (AL-51); with sync,
        or for the class state, written and sealed before this returns
        (AL-56). Over the budget of its class it is counted in a summary
        instead (AL-41)."""
        if ev not in al.EVENTS:
            raise ValueError("unknown event %r" % ev)
        if res not in al.RESULTS:
            raise ValueError("unknown result %r" % res)
        with self.lock:
            e = self._entry(ev, res, actor, via, obj, msg, data)
            cls = e["cls"]
            op = self.op()
            key = cls + "/" + ev
            s = self.summaries.get(key)
            if s is not None:
                s.add(e)
                self.dirty = True
                return e["seq"]
            cost = self._cost(e)
            first = ev not in self.last_ev and not any(p["ev"] == ev for p in self.pending)
            if cls == al.STATE or force or first:
                # The class state has room for five years of every change
                # (AL-42); the first entry of each id is always kept (AL-41).
                self.buckets[cls].debit(cost, op)
            elif not self.buckets[cls].take(cost, op):
                self._open_summary(key, cls, ev, e, op)
                return e["seq"]
            self.pending.append(e)
            self.journal(e)
            if len(self.pending) > PENDING_MAX:
                self._drop_pending()
            if cls == al.STATE:
                self.flush()
                self.buckets[cls].debit(SEAL_COST, op)
                self.seal()
            elif sync:
                self.flush()
                self._seal_if_affordable(cls)
            return e["seq"]

    def _open_summary(self, key, cls, ev, e, op):
        s = Summary(cls, ev, op)
        s.add(e)
        self.summaries[key] = s
        self.dirty = True
        self.journal(e, "counted in a summary")
        if ev != "E19":
            # One E19 per id and window (AL-43).
            self.record("E19", "info", obj=key,
                        msg="%s over the budget of class %s, counted in a summary" % (ev, cls),
                        data={"class": cls, "event": ev})

    def _close_summaries(self, op):
        for key in sorted(self.summaries):
            s = self.summaries[key]
            if not s.due(op):
                continue
            e = self._entry(s.ev, al.AGGREGATED, msg="%d events counted" % s.n)
            e["cls"] = s.cls
            e["agg"] = s.agg()
            cost = self._cost(e)
            last = s.window == len(WINDOWS) - 1
            if self.buckets[s.cls].take(cost, op):
                pass
            elif last:
                # After a day the summary is written whatever the budget says:
                # it never waits longer (AL-41). Its fixed size keeps that
                # within the share, see the test.
                self.buckets[s.cls].debit(cost, op)
            else:
                s.window += 1
                self.next_seq -= 1      # the number was not used
                self.dirty = True
                continue
            del self.summaries[key]
            self.pending.append(e)
            self.journal(e)
            self.dirty = True

    def _drop_pending(self):
        """The partition cannot be written and entries pile up. Keep the
        first of them; the rest is lost, and counted as such (AL-11)."""
        lost = self.pending[PENDING_MAX // 2:]
        del self.pending[PENDING_MAX // 2:]
        e = self._entry("E17", "failed", msg="audit log not writable, %d entries lost" % len(lost),
                        data={"lost": len(lost)})
        self.pending.append(e)
        self.journal(e)

    def flush(self):
        with self.lock:
            if not self.pending:
                return
            batch = self.pending
            try:
                self._write_lines(batch)
            except OSError as exc:
                self._failed(exc)
                return
            self.pending = []
            self.last_flush = self.clock.mono()
            self.stats["flushes"] += 1
            if not self.healthy:
                self.healthy = True
                self.fault = None

    def _failed(self, exc):
        if self.healthy:
            self.notes.append(("write", str(exc)))
        self.healthy = False
        self.fault = str(exc)

    # --- epochs ----------------------------------------------------------------

    def _seal_if_affordable(self, cls):
        """An entry that has to be sealed at once pays for its seal from its
        own class (AL-61). Without budget it waits for the regular seal."""
        if self.buckets[cls].take(SEAL_COST, self.op()):
            self.seal()

    def seal(self):
        """Close the open epoch (AL-55, AL-56): the next key first, then the
        signed seal, then the key of this epoch overwritten and removed. A
        crash between the steps leaves either the old key matching the last
        seal or the new one, never neither."""
        with self.lock:
            self.flush()
            if self.unsealed == 0 or self.key is None or not self.healthy:
                return False
            nxt = al.new_key()
            n = self.epoch
            try:
                self._store_key(n + 1, nxt)
                seal = {"seal": n, "op": int(self.op()), "boot": self.boot,
                        "t": self.clock.utc(), "next": al.public_text(nxt)}
                seal["prev"] = self.prev
                seal["sig"] = al.sign(self.key, al.seal_payload(seal))
                self._write_lines([seal])
                self._wipe_key(self._keypath(n))
                self._fsync_dir(self.keydir)
            except OSError as exc:
                self._failed(exc)
                return False
            self.key = nxt
            self.epoch_op = self.op()
            return True

    # --- the clock of the service ------------------------------------------------

    def tick(self):
        """Called by the service about once a second."""
        with self.lock:
            op = self.op()
            mono = self.clock.mono()
            self._close_summaries(op)
            if self.pending and mono - self.last_flush >= FLUSH_INTERVAL:
                self.flush()
            self.buckets[RESERVE].refill(op)
            spent = self.buckets[RESERVE].tokens <= 0
            if self.unsealed and op - self.epoch_op >= (EPOCH_SPENT if spent else EPOCH):
                self.buckets[RESERVE].debit(SEAL_COST, op)
                self.seal()
            if ((self.dirty and mono - self.last_save >= SAVE_INTERVAL)
                    or op - self.op_saved >= OPTIME_INTERVAL):
                self.flush()
                if self.healthy:
                    try:
                        self.save_state()
                    except OSError as exc:
                        self._failed(exc)

    def close(self):
        """A clean stop: everything written and sealed, so the next start
        knows the boot ended in order (AL-11)."""
        with self.lock:
            self.flush()
            self.seal()
            if self.healthy:
                self.save_state(clean=True)

    # --- reading ---------------------------------------------------------------

    def snapshot(self):
        """The segments as they are now, for reading while the log goes on."""
        with self.lock:
            return [(self._segpath(s), os.path.getsize(self._segpath(s))) for s in self.segments()]

    def lines(self):
        for path, size in self.snapshot():
            with open(path, "rb") as f:
                data = f.read(size)
            for raw in data.split(b"\n"):
                if raw:
                    yield raw.decode("utf-8", "surrogateescape")

    def status(self):
        with self.lock:
            op = self.op()
            for b in self.buckets.values():
                b.refill(op)
            return {
                "start": self.start,
                "fingerprint": al.fingerprint(self.start) if self.start else None,
                "seq": self.next_seq - 1, "epoch": self.epoch, "boot": self.boot,
                "op": int(op), "healthy": self.healthy, "fault": self.fault,
                "pending": len(self.pending), "summaries": sorted(self.summaries),
                "used": dict(self.used),
                "shares": dict(self.shares),
                "budget": {c: int(b.tokens) for c, b in self.buckets.items()},
            }

    # --- reset (AL-17) -----------------------------------------------------------

    def reset(self, reason, actor, data=None):
        """End this log and start a new one. The old one is kept under
        archive/; the new one begins with E01 and an E18 that names the old
        start hash, last number and last hash, the reason and who asked."""
        with self.lock:
            self.close()
            old = {"old_start": self.start, "old_seq": self.next_seq - 1, "old_hash": self.prev}
            boot, bid, op_base, extra = self.boot, self.bid, self.op_base, self.extra
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            archive = os.path.join(self.root, "archive")
            os.makedirs(archive, exist_ok=True)
            os.rename(self.own, os.path.join(archive, "%s-%s" % (stamp, (self.start or "none")[:16])))
            self._fsync_dir(archive)
            self._fsync_dir(self.root)
            self._reset_memory()
            for d in (self.own, self.logdir, self.keydir):
                os.makedirs(d, mode=0o750, exist_ok=True)
            self.boot, self.bid, self.op_base, self.extra = boot, bid, op_base, extra
            start = self.genesis(msg="audit log created after a reset", data=data)
            d = dict(old)
            d["reason"] = reason
            self.record("E18", "done", actor=actor, msg="audit log reset: " + reason, data=d, sync=True)
            self.flush()
            self.seal()
            self.save_state()
            return start
