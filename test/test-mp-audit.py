"""Tests for the audit log (layer mp-audit), runnable on the build host.

The core runs on a temporary directory with a simulated clock, so days and
years of operating time pass in seconds; the service runs once on a plain
directory instead of its partition, with the command line tool against it.

What matters (docs/meltingplot-audit-log.md):
- the chain and the seals: an entry changed, removed or inserted is found,
  also when everything on the device was used to cover it up (AL-13, AL-55
  to AL-61); only the key of the open epoch is ever on disk (AL-56);
- nothing gets lost unnoticed: a restart carries on, a crash leaves numbers
  that the next start declares lost, a torn write is stepped over (AL-11);
- a flood stays within the budgets, and what matters is still there
  afterwards (AL-39 to AL-48), with bounded writes to the drive (AL-50);
- strings from outside are bounded and stripped of control characters
  (AL-02), only root records (AL-10), the service takes over what was
  queued in the journal (AL-35), a reset leaves a trace (AL-17) and a
  closed old log behind;
- a summary still open is no gap for the check (AL-41);
- a change is on the drive when record returns, attempts and operation
  within five seconds (AL-51, decision 21); only root records, also
  into the journal (decision 23);
- the image and the outcome of its trial boot are recorded also in the
  boot that creates the log (E02), a stop of the service while the system
  runs is recorded (E17, T36).
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

# The modules are imported from the overlay, which goes into the image as it
# is: no __pycache__ may be left there.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.realpath(__file__))
OVERLAY = os.path.join(HERE, "..", "overlay")
LIB = os.path.realpath(os.path.join(OVERLAY, "usr", "lib", "meltingplot", "mp-audit"))
CLI = os.path.realpath(os.path.join(OVERLAY, "usr", "bin", "mp-audit"))
DAEMON = os.path.join(LIB, "mp-auditd")
sys.path.insert(0, LIB)

import auditcore as ac  # noqa: E402
import auditlog as al  # noqa: E402

failed = 0
# fsync is cheap on a tmpfs; the flood test writes for thirty simulated days
SCRATCH = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None


def mkdtemp():
    return tempfile.mkdtemp(dir=SCRATCH)


def check(name, want, got, detail=None):
    global failed
    if want == got:
        print("ok   %-60s %s" % (name, got if detail is None else detail))
    else:
        print("FAIL %-60s expected=%r got=%r %s" % (name, want, got, "" if detail is None else detail))
        failed = 1


class Clock:
    def __init__(self):
        self.bt = 0.0
        self.bid = "b" * 31 + "1"
        self.m = 0.0
        self.realtime = 1_793_000_000

    def boottime(self):
        return self.bt

    def boot_id(self):
        return self.bid

    def utc(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.realtime + self.bt))

    def mono(self):
        return self.m

    def synced(self):
        return True

    def advance(self, s):
        self.bt += s
        self.m += s

    def reboot(self, n):
        self.bid = "b" * 30 + "%02d" % n
        self.bt = 1.0


def ident():
    return {"sys": "hmi", "host": "meltingplot-chx-350-001-hmi", "mach": "chx-350-001", "img": "0.0.0-test"}


def new_core(d, clk, journal=None):
    return ac.AuditCore(d, ident, clk, journal=journal, append_only=False)


def lines_of(core):
    return list(core.lines())


def entries(core):
    return [json.loads(x) for x in core.lines() if x.startswith("{") and '"seq"' in x]


def fresh(journal=None):
    d = mkdtemp()
    clk = Clock()
    core = new_core(d, clk, journal)
    assert core.open() == "new"
    core.genesis(data={"serial": "001"})
    return d, clk, core


def write_segment(core, lines):
    seg = core._segpath(core.segments()[0])
    with open(seg, "w") as f:
        f.write("\n".join(lines) + "\n")


# --- chain and seals --------------------------------------------------------------


def test_chain():
    d, clk, core = fresh()
    start = core.start
    for i in range(5):
        core.record("E10", "refused", actor="1-%d" % i, obj="046a:0011", msg="keyboard")
    clk.advance(6)
    core.tick()
    core.record("E13", "done", actor="mpadmin", msg="systemctl status")
    core.close()
    rep = al.verify(lines_of(core), start)
    check("chain: valid with its start hash", "valid", rep.result)
    check("chain: every number accounted", [], rep.problems)
    check("chain: other start hash is foreign", "foreign", al.verify(lines_of(core), "0" * 64).result)
    keys = os.listdir(os.path.join(d, "own", "keys"))
    check("keys: only the open epoch's key on disk", ["epoch-%d.key" % core.epoch], keys)
    last_seal = [json.loads(x) for x in lines_of(core) if '"seal"' in x][-1]
    with open(os.path.join(d, "own", "keys", keys[0]), "rb") as f:
        check(
            "keys: it is the one the last seal announced",
            last_seal["next"],
            al.public_text(al.key_from_bytes(f.read())),
        )
    shutil.rmtree(d)


def test_tamper():
    """An attacker with root and everything on the partition changes an
    entry of a sealed epoch and recomputes the chain. The seal of that epoch
    cannot be redone: its key is gone."""
    d, clk, core = fresh()
    start = core.start
    core.record("E05", "done", obj="0:/sys/config.g", msg="changed via DWC")
    core.seal()
    core.record("E13", "done", actor="mpadmin", msg="later")
    core.close()
    lines = lines_of(core)
    objs = [json.loads(x) for x in lines]
    i = next(n for n, o in enumerate(objs) if o.get("ev") == "E05")
    objs[i]["msg"] = "nothing happened"
    # the chain recomputed from there on, and every seal re-signed with the
    # only key there is on disk, that of the open epoch
    keyfile = os.path.join(d, "own", "keys", "epoch-%d.key" % core.epoch)
    with open(keyfile, "rb") as f:
        cur = al.key_from_bytes(f.read())
    prev = al.ZERO
    out = []
    for o in objs:
        o["prev"] = prev
        if "seal" in o:
            o["sig"] = al.sign(cur, al.seal_payload(o))
        line = al.canon(o)
        prev = al.line_hash(line)
        out.append(line)
    rep = al.verify(out, start)
    check("tamper: changed entry in a sealed epoch found", "changed", rep.result)
    check("tamper: named as a seal that does not verify", True, any("not signed" in t for _, _, t in rep.problems))

    # without recomputing: the chain breaks at the next line
    objs = [json.loads(x) for x in lines]
    objs[i]["msg"] = "nothing happened"
    rep = al.verify([al.canon(o) for o in objs], start)
    check("tamper: plain edit breaks the chain", True, any("does not chain" in t for _, _, t in rep.problems))

    # a line taken out
    rep = al.verify(lines[:i] + lines[i + 1 :], start)
    check("tamper: removed line found", "changed", rep.result)

    # a new log from scratch has another start hash
    d2, clk2, core2 = fresh()
    core2.close()
    check("tamper: rebuilt log does not match the anchor", "foreign", al.verify(lines_of(core2), start).result)
    shutil.rmtree(d)
    shutil.rmtree(d2)


# --- restarts, crashes, torn writes -------------------------------------------------


def test_restart():
    d, clk, core = fresh()
    start = core.start
    core.record("E02", "done", msg="image started")
    core.close()
    clk.reboot(2)
    c2 = new_core(d, clk)
    check("restart: opens the existing log", "open", c2.open())
    check("restart: previous boot was clean", True, c2.prev_clean)
    check("restart: boot counter", 2, c2.boot)
    check("restart: operating time carried over", True, c2.op() >= clk.bt)
    c2.record("E13", "done", actor="mpadmin")
    c2.close()
    check("restart: still valid", "valid", al.verify(lines_of(c2), start).result)

    # the state file lost: everything is read back from the log
    os.unlink(os.path.join(d, "own", "state.json"))
    clk.reboot(3)
    c3 = new_core(d, clk)
    c3.open()
    check("restart: without state the numbers go on", c2.next_seq, c3.next_seq)
    shutil.rmtree(d)


def test_crash():
    mirrored = []
    d, clk, core = fresh(journal=lambda e, note=None: mirrored.append(e))
    start = core.start
    core.record("E13", "done", actor="mpadmin", msg="written")
    # a change right before the power cut is on the drive already (decision 21)
    sudo = core.record("E13", "done", actor="mpadmin", msg="sudo right before the power cut")
    for i in range(3):
        core.record("E12", "refused", actor="x%d" % i, msg="accepted, not yet written %d" % i)
    # power cut: nothing flushed, nothing saved
    pending = [(e["seq"], e) for e in mirrored if e["ev"] == "E12"]
    clk.reboot(5)
    c2 = new_core(d, clk)
    c2.open(recover=lambda bid, first: [(s, e) for s, e in pending if s >= first])
    check("crash: a change before the power cut kept", True, any(e["seq"] == sudo for e in entries(c2)))
    check("crash: previous boot not clean", False, c2.prev_clean)
    check("crash: numbers left by the crash", 3, c2.lost)
    check("crash: recovered from the journal", 3, len(c2.recovered))
    check("crash: numbering goes on after them", pending[-1][0] + 1, c2.next_seq)
    c2.record("E17", "failed", msg="lost", data={"lost": c2.lost}, force=True)
    for s, e in c2.recovered:
        c2.record(e["ev"], e["res"], actor=e.get("actor", ""), msg=e.get("msg", ""), data={"orig_seq": s})
    c2.close()
    rep = al.verify(lines_of(c2), start)
    check("crash: valid, the gap is declared", "valid", rep.result)
    check("crash: lost counted", 3, rep.lost)

    # torn write: half a line at the end
    seg = c2._segpath(c2.segments()[-1])
    with open(seg, "ab") as f:
        f.write(b'{"seq":99,"ev":"E1')
    clk.reboot(6)
    c3 = new_core(d, clk)
    c3.open()
    c3.record("E13", "done", actor="mpadmin")
    c3.close()
    rep = al.verify(lines_of(c3), start)
    check("torn: stepped over", "valid", rep.result)
    check("torn: counted", 1, rep.torn)
    # the same junk without the service's E17 after it is damage
    with open(seg, "ab") as f:
        f.write(b"garbage in the middle\n")
    clk.reboot(7)
    with open(seg, "rb") as f:
        raw = f.read()
    tail = '{"seq":1000,"ev":"E13","prev":"x"}'
    rep = al.verify(raw.decode().splitlines() + [tail], start)
    check("torn: junk inside the log is a problem", "changed", rep.result)
    shutil.rmtree(d)


def test_lost_key():
    d, clk, core = fresh()
    start = core.start
    core.record("E13", "done", actor="mpadmin")
    core.close()
    for n in os.listdir(os.path.join(d, "own", "keys")):
        os.unlink(os.path.join(d, "own", "keys", n))
    clk.reboot(2)
    c2 = new_core(d, clk)
    c2.open()
    check("lost key: noted", True, any(k == "rekey" for k, _ in c2.notes))
    c2.record("E13", "done", actor="mpadmin")
    c2.close()
    rep = al.verify(lines_of(c2), start)
    check("lost key: the unvouched epoch is reported", "changed", rep.result)
    check("lost key: chain itself intact", False, any("does not chain" in t for _, _, t in rep.problems))
    shutil.rmtree(d)


# --- strings, writers, reset --------------------------------------------------------


def test_strings():
    d, clk, core = fresh()
    core.record("E10", "refused", actor="1-1", obj="\x1b[2J" + "A" * 1000, msg="name\nwith\tcontrol\x07")
    core.flush()
    e = entries(core)[-1]
    check("strings: escape sequence neutralised", True, "\x1b" not in e["obj"] and e["obj"].startswith("\\x1b"))
    check("strings: bounded", True, len(e["obj"]) <= 260)
    check("strings: no control characters", True, all(ord(c) >= 0x20 for c in e["msg"]))
    try:
        core.record("E99", "done")
        check("strings: unknown event refused", True, False)
    except ValueError:
        check("strings: unknown event refused", True, True)
    shutil.rmtree(d)


def test_parallel():
    d, clk, core = fresh()
    start = core.start

    def writer(n):
        for i in range(200):
            core.record("E13", "done", actor="t%d" % n, msg=str(i))

    ts = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    core.close()
    rep = al.verify(lines_of(core), start)
    check("parallel: valid", "valid", rep.result)
    seqs = [e["seq"] for e in entries(core)]
    check("parallel: numbers unique and in order", True, seqs == sorted(set(seqs)), "%d entries" % len(seqs))
    shutil.rmtree(d)


def flood_until_summary(core, ev="E12", res="refused"):
    """Records refused logins until their class is over budget and a summary
    opens. Returns how many were sent."""
    n = 0
    while not core.summaries:
        n += 1
        core.record(ev, res, actor="user%d" % n, obj="10.0.0.%d" % (n % 250))
    for i in range(100):
        core.record(ev, res, actor="user%d" % (n + i), obj="10.0.1.%d" % i)
    return n + 100


def test_reset():
    d, clk, core = fresh()
    old = core.start
    core.record("E13", "done", actor="mpadmin")
    flood_until_summary(core)
    new = core.reset("drive replaced in the lab", "mpadmin")
    check("reset: new start hash", True, new != old)
    archived = os.listdir(os.path.join(d, "archive"))
    check("reset: old log archived", 1, len(archived))
    arch = os.path.join(d, "archive", archived[0])
    with open(os.path.join(arch, "log", "00000001.jsonl")) as f:
        rep = al.verify(f.read().splitlines(), old)
    check(
        "reset: old log closed, its open summary written",
        ("valid", 0, True),
        (rep.result, rep.pending, rep.aggregated > 0),
        rep.problems[:2],
    )
    check("reset: no key of the old log left", [], os.listdir(os.path.join(arch, "keys")))
    e18 = [e for e in entries(core) if e["ev"] == "E18"]
    check("reset: E18 names the old log", old, e18[0]["data"]["old_start"] if e18 else None)
    check(
        "reset: E18 names who and why",
        ("mpadmin", "drive replaced in the lab"),
        (e18[0].get("actor"), e18[0]["data"]["reason"]) if e18 else None,
    )
    check("reset: new log valid", "valid", al.verify(lines_of(core), new).result)
    shutil.rmtree(d)


# --- floods and budgets -------------------------------------------------------------


def test_open_summary():
    """A check while a summary is still open (after a flood it waits up to a
    day) finds the log valid: from the service exactly, from files as far
    as E19 announces it. Found on the bench panel with hmi rc.12."""
    d, clk, core = fresh()
    start = core.start
    core.seal()
    sent = flood_until_summary(core)
    core.record("E13", "done", actor="mpadmin", msg="after the flood")
    core.flush()
    e19 = [e for e in entries(core) if e["ev"] == "E19"]
    first = core.summaries["attempt/E12"].first
    check("open: E19 names the first number of its summary", first, e19[0]["data"].get("from") if e19 else None)
    opened, snap = core.read_snapshot()
    lines = list(core.lines(snap))
    rep = al.verify(lines, start, opened)
    check("open: valid with the open summaries from the service", ("valid", []), (rep.result, rep.problems[:2]))
    check("open: every number counted", core.next_seq - 1, rep.last_seq)
    check("open: the open summary holds the rest", core.summaries["attempt/E12"].n, rep.pending)
    rep = al.verify(lines, start)
    check(
        "open: from files pending, announced by E19",
        ("pending", ["attempt/E12"]),
        (rep.result, rep.pending_keys),
        rep.problems[:2],
    )
    bad = [dict(o, n=o["n"] - 1) for o in opened]
    check("open: a summary short of a number is found", "changed", al.verify(lines, start, bad).result)
    check("open: a gap the service does not explain is found", "changed", al.verify(lines, start, []).result)
    # Numbers handed out but never written before the summary opened: an
    # open summary announced later cannot hold them.
    d2, clk2, c2 = fresh()
    c2.seal()
    c2.record("E13", "done", actor="mpadmin")
    c2.next_seq += 5
    c2.record("E13", "done", actor="mpadmin")
    flood_until_summary(c2)
    c2.record("E13", "done", actor="mpadmin", msg="after the flood")
    opened2, snap2 = c2.read_snapshot()
    rep = al.verify(list(c2.lines(snap2)), c2.start)
    check("open: from files, a gap before the open summary is found", "changed", rep.result, rep.problems[:1])
    shutil.rmtree(d2)
    # a restart keeps it open, and the check still holds
    core.close()
    clk.reboot(2)
    c2 = new_core(d, clk)
    c2.open()
    opened, snap = c2.read_snapshot()
    check("open: still valid after a restart", "valid", al.verify(list(c2.lines(snap)), start, opened).result)
    for _ in range(2 * 24 * 60):
        clk.advance(60)
        c2.tick()
    c2.close()
    rep = al.verify(lines_of(c2), start, c2.open_summaries())
    check(
        "open: once written, nothing pending",
        ("valid", 0, [], True),
        (rep.result, rep.pending, c2.open_summaries(), rep.aggregated >= sent - 3000),
        rep.aggregated,
    )
    shutil.rmtree(d)


def summary_max():
    s = ac.Summary(al.ATTEMPT, "E10", 0)
    for i in range(1000):
        s.add(
            {
                "seq": 10**9 + i,
                "t": "2026-11-04T12:00:00Z",
                "op": 10**9,
                "res": "refused",
                "actor": "x" * 64 + str(i),
                "via": "y" * 32,
                "obj": "z" * 256 + str(i),
                "msg": "m" * 256,
            }
        )
    d, clk, core = fresh()
    e = core._entry("E10", al.AGGREGATED, msg="%d events counted" % (10**9))
    e["cls"] = al.ATTEMPT
    e["agg"] = s.agg()
    size = core._cost(e)
    shutil.rmtree(d)
    return size


def test_budget_design():
    """AL-41: a summary is written after a day at the latest, budget or not.
    That stays within a share only if a class earns, each day, enough for one
    summary of each of its ids."""
    smax = summary_max()
    check("budget: a summary has a fixed upper size (bytes)", True, smax <= 1600, smax)
    for cls in al.CLASSES:
        if cls == al.STATE:
            continue
        ids = [
            ev
            for ev in al.EVENTS
            if al.EVENTS[ev][0] == cls
            or (cls == al.ATTEMPT and ev in al.ATTEMPT_WHEN_REFUSED)
            or (cls == al.OPERATION and ev == "E03")
        ]
        b = ac.Bucket(ac.SHARES[cls])
        daily = b.rate * ac.DAY
        check(
            "budget: %-9s earns a day's summaries (%d ids)" % (cls, len(ids)),
            True,
            daily >= len(ids) * smax,
            "earns %d B a day, needs %d" % (daily, len(ids) * smax),
        )


def test_flood():
    """Thirty days of a flood with rolling sources and objects in every
    class a stranger can reach, with a login and a configuration change
    before, in the middle and at the end (Nachweis, T36/T42 gegen Fluten)."""
    d, clk, core = fresh()
    start = core.start
    marks = []

    def mark(tag):
        marks.append(core.record("E12", "allowed", actor="mpadmin", obj="SHA256:abc", msg="login " + tag))
        marks.append(core.record("E05", "done", obj="0:/sys/config.g", msg="changed " + tag))

    mark("before")
    n = 0
    days = 30
    step = 20
    for i in range(days * 86400 // step):
        n += 1
        core.record(
            "E10", "refused", actor="1-%d" % (n % 7), obj="%04x:%04x" % (n % 65536, n % 9973), msg="device %d" % n
        )
        core.record("E12", "refused", actor="user%d" % n, obj="10.0.%d.%d" % (n % 250, n % 13))
        core.record("E11", "info", obj="stick%d" % n)
        clk.advance(step)
        core.tick()
        if i == days * 86400 // step // 2:
            mark("middle")
    mark("after")
    clk.advance(2 * 86400)
    for _ in range(60 * 48):
        clk.advance(60)
        core.tick()
    core.close()
    rep = al.verify(lines_of(core), start)
    check("flood: log valid, every number accounted", "valid", rep.result)
    check("flood: problems", [], rep.problems[:3])
    es = entries(core)
    seqs = {e["seq"] for e in es}
    check("flood: every login and change kept individually", True, all(m in seqs for m in marks))
    check("flood: summaries written", True, rep.aggregated > 0.9 * 3 * n)
    check("flood: E19 recorded", True, any(e["ev"] == "E19" for e in es))
    op = core.op()
    for cls in (al.ATTEMPT, al.OPERATION):
        b = ac.Bucket(ac.SHARES[cls])
        allowance = b.cap + b.rate * op + 2 * summary_max()
        check(
            "flood: %-9s within its budget" % cls,
            True,
            core.used[cls] <= allowance,
            "used %d B, allowed %d" % (core.used[cls], allowance),
        )
    first = {}
    for e in es:
        first.setdefault(e["ev"], e)
    check("flood: first E10 kept as itself", "device 1", first["E10"].get("msg"))
    sums = [e for e in es if e.get("agg")]
    check("flood: summaries keep the last event", True, all(e["agg"].get("last") for e in sums))
    shutil.rmtree(d)


def test_change_at_once():
    """Decision 21: a change is written before record returns, so a power
    cut right after it cannot lose it. Attempts and operation wait for the
    next flush (AL-51)."""
    d, clk, core = fresh()
    f0 = core.stats["fsyncs"]
    seq = core.record("E13", "done", actor="mpadmin", msg="sudo")
    check("change: on the drive at once", True, any(e["seq"] == seq for e in entries(core)))
    check("change: one write for it", 1, core.stats["fsyncs"] - f0)
    seq = core.record("E12", "refused", actor="x")
    check("attempt: not yet on the drive", False, any(e["seq"] == seq for e in entries(core)))
    clk.advance(ac.FLUSH_INTERVAL)
    core.tick()
    check("attempt: on the drive after the flush interval", True, any(e["seq"] == seq for e in entries(core)))
    check("change: still valid", "unsealed", al.verify(lines_of(core), core.start).result)
    shutil.rmtree(d)


def test_wear():
    """AL-50: an hour of 100 events a second writes a bounded amount, in a
    bounded number of writes."""
    d, clk, core = fresh()
    b0, f0 = core.stats["bytes"], core.stats["fsyncs"]
    for s in range(3600):
        for i in range(100):
            core.record("E10", "refused", actor="1-%d" % i, obj="%d" % s)
        clk.advance(1)
        core.tick()
    written = core.stats["bytes"] - b0
    syncs = core.stats["fsyncs"] - f0
    cap = ac.Bucket(ac.SHARES[al.ATTEMPT]).cap
    check("wear: bytes within the burst of the class", True, written <= cap + 64 * 1024, "%d B" % written)
    check(
        "wear: at most one flush per 5 s, state once a minute",
        True,
        syncs <= 3600 // 5 + 3 * 60 + 20,
        "%d fsyncs" % syncs,
    )
    shutil.rmtree(d)


def test_clock():
    """AL-49: budgets follow operating time, not the system clock."""
    d, clk, core = fresh()
    core.record("E12", "refused", actor="a")
    before = core.buckets[al.ATTEMPT].tokens
    clk.realtime += 6 * 365 * 86400
    core.tick()
    core.buckets[al.ATTEMPT].refill(core.op())
    check("clock: a clock six years ahead adds no budget", True, core.buckets[al.ATTEMPT].tokens - before < 1)
    shutil.rmtree(d)


# --- the service and the command line ------------------------------------------------

# --- the image and its trial boot (E02) ----------------------------------------------


def load_daemon():
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("mp_auditd", DAEMON)
    spec = importlib.util.spec_from_loader("mp_auditd", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class FakePC:
    def __init__(self, version, slot, tried=False, committed=False):
        self.version, self.slot, self.tried, self.done = version, slot, tried, committed

    def image(self):
        return {"name": "mp-hmi-pi5", "version": self.version, "slot": self.slot}

    def trybooted(self):
        return self.tried

    def committed(self):
        return self.done


def test_trial():
    D = load_daemon()

    def service(core, pc):
        svc = D.Service()
        svc.core, svc.pc, svc.mode = core, pc, "log"
        return svc

    def e02(core):
        core.flush()
        return [(e["res"], e["msg"]) for e in entries(core) if e["ev"] == "E02"]

    # The log begins in the trial boot of the first image that has it (the
    # bench panel, OTA from hmi rc.11 to rc.12).
    d, clk, core = fresh()
    pc = FakePC("0.1.0-rc.12", "system_b", tried=True)
    svc = service(core, pc)
    svc.boot_events(new=True)
    got = e02(core)
    check("trial: a new log records its image", [("done", "image 0.1.0-rc.12 started in system_b")], got)
    check("trial: ... started as a trial", True, core.extra.get("trial", {}).get("tryboot"))
    pc.done = True
    svc.watch_trial()
    check(
        "trial: and the commit",
        ("done", "image 0.1.0-rc.12 committed after its trial boot"),
        e02(core)[-1] if e02(core) else None,
    )
    shutil.rmtree(d)

    # Committed in the last minute of the trial boot, before the service saw it.
    d, clk, core = fresh()
    service(core, FakePC("0.1.0-rc.12", "system_b", tried=True)).boot_events(new=True)
    clk.reboot(2)
    svc = service(core, FakePC("0.1.0-rc.12", "system_b", committed=True))
    svc.boot_events()
    check(
        "trial: a commit seen only at the next start",
        ("done", "image 0.1.0-rc.12 committed after its trial boot"),
        e02(core)[-1] if e02(core) else None,
    )
    check("trial: ... is not a new image", 2, len(e02(core)))
    shutil.rmtree(d)

    # Rolled back to an image without the audit log, then the next update.
    d, clk, core = fresh()
    service(core, FakePC("0.1.0-rc.12", "system_b", tried=True)).boot_events(new=True)
    clk.reboot(2)
    svc = service(core, FakePC("0.1.0-rc.13", "system_a", tried=True))
    svc.boot_events()
    got = e02(core)
    check(
        "trial: a trial that did not stay, when the log comes back",
        ("failed", "trial boot of 0.1.0-rc.12 in system_b was not committed, now 0.1.0-rc.13 in system_a"),
        got[1] if len(got) > 1 else None,
    )
    check(
        "trial: ... then the new image",
        ("done", "image 0.1.0-rc.13 started in system_a"),
        got[2] if len(got) > 2 else None,
    )
    shutil.rmtree(d)

    # Rolled back to the image before, which has the log (as before the fix).
    d, clk, core = fresh()
    svc = service(core, FakePC("0.1.0-rc.12", "system_b"))
    svc.boot_events(new=True)
    svc = service(core, FakePC("0.1.0-rc.13", "system_a", tried=True))
    svc.boot_events()
    clk.reboot(2)
    service(core, FakePC("0.1.0-rc.12", "system_b")).boot_events()
    check(
        "trial: back on the image before",
        [
            ("failed", "trial boot of 0.1.0-rc.13 in system_a was not committed, now 0.1.0-rc.12 in system_b"),
            ("done", "image 0.1.0-rc.12 started in system_b"),
        ],
        e02(core)[-2:],
    )
    shutil.rmtree(d)


def cli(env, *args):
    p = subprocess.run(
        [sys.executable, "-I", "-B", CLI] + list(args),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, p.stdout, p.stderr


def test_service():
    # Not on SCRATCH: the stubs below have to run, and a container mounts
    # /dev/shm noexec. This test does not write enough for fsync to matter.
    tmp = tempfile.mkdtemp()
    run = os.path.join(tmp, "run")
    store = os.path.join(tmp, "store")
    os.makedirs(store)
    with open(os.path.join(tmp, "device.conf"), "w") as f:
        f.write("MP_ROLE=hmi\nMP_PRODUCT=chx-350\nMP_IMAGE=mp-hmi-pi5\nMP_VERSION=0.0.0-test\n")
    with open(os.path.join(tmp, "identity"), "w") as f:
        f.write("PRINTER_SERIAL=001\nPRINTER_NAME=Halle 2\n")
    with open(os.path.join(tmp, "installer.txt"), "w") as f:
        f.write("image=mp-hmi-pi5-0.0.0-test\ninstaller=0.0.0-test\nlayout_before=gen2\nkeep_part=audit\nkept=no\n")
    stub = os.path.join(tmp, "journalctl")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(stub, 0o755)
    sysstate = os.path.join(tmp, "system-state")
    with open(sysstate, "w") as f:
        f.write("running\n")
    systemctl = os.path.join(tmp, "systemctl")
    with open(systemctl, "w") as f:
        f.write("#!/bin/sh\ncat '%s'\n" % sysstate)
    os.chmod(systemctl, 0o755)
    jsock = os.path.join(tmp, "journal.sock")
    journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    journal.bind(jsock)
    journal.settimeout(0.2)
    env = dict(
        os.environ,
        MP_AUDIT_RUN=run,
        MP_AUDIT_STORE=store,
        MP_DEVICE_CONF=os.path.join(tmp, "device.conf"),
        MP_IDENTITY_FILE=os.path.join(tmp, "identity"),
        MP_AUDIT_INSTALLER=os.path.join(tmp, "installer.txt"),
        MP_AUDIT_JOURNAL=jsock,
        MP_AUDIT_JOURNALCTL=stub,
        MP_AUDIT_SYSTEMCTL=systemctl,
        MP_AUDIT_SOCKET=os.path.join(run, "socket"),
    )
    env.pop("NOTIFY_SOCKET", None)

    def start():
        p = subprocess.Popen(
            [sys.executable, "-I", "-B", DAEMON], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        for _ in range(100):
            if cli(env, "status")[0] in (0, 2):
                break
            time.sleep(0.1)
        return p

    p = start()
    rc, out, err = cli(env, "status", "--json")
    st = json.loads(out) if out else {}
    check("service: runs on its store", "log", st.get("mode"))
    check("service: has a start hash", 64, len(st.get("start") or ""))
    rc, out, _ = cli(env, "show", "--all", "--json")
    evs = [json.loads(x)["ev"] for x in out.splitlines()]
    check("service: begins with E01, then the installation (E18)", ["E01", "E18"], evs[:2])
    e18 = json.loads(out.splitlines()[1])
    check(
        "service: E18 says what the card found", "installation over layout gen2, no earlier audit log", e18.get("msg")
    )
    check("service: machine from the identity", "chx-350-001", e18.get("mach"))
    check("service: the first start records the image (E02)", "E02", evs[2] if len(evs) > 2 else None)
    rc, _, err = cli(dict(env, MP_AUDIT_UID="1000"), "record", "E10", "refused", "--actor", "1-1")
    check("service: only root records", (2, "mp-audit: only root records"), (rc, err.strip()))
    rc, out, _ = cli(env, "verify", "--start", st.get("start", ""))
    check("service: verify on the device", 0, rc)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=30)
    check("service: clean stop", 0, p.returncode)

    def msgs():
        rc, out, _ = cli(env, "show", "--all", "--json")
        return [(json.loads(x)["ev"], json.loads(x).get("msg", "")) for x in out.splitlines()]

    # T36: a stop while the system runs is recorded when it happens, and the
    # start after it within the same boot says how long the gap was
    stopped = ("E17", "the audit service was stopped while the system runs")
    p = start()
    got = msgs()
    again = [m for e, m in got if e == "E17" and m.startswith("the audit service started again within this boot")]
    check("service: a stop while the system runs is an E17", 1, got.count(stopped), [e for e, _ in got])
    check(
        "service: the start after it in the same boot too, no E15",
        (1, False),
        (len(again), any(e == "E15" for e, _ in got)),
    )
    with open(sysstate, "w") as f:
        f.write("stopping\n")
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=30)
    p = start()
    check("service: a stop at shutdown adds no E17", 1, msgs().count(stopped))
    with open(sysstate, "w") as f:
        f.write("running\n")
    p.kill()
    p.wait()
    p = start()
    got = msgs()
    check(
        "service: a killed service is an E17 at the next start",
        True,
        ("E17", "the audit service was restarted without a clean stop") in got,
        [e for e, _ in got],
    )
    rc, out, _ = cli(env, "verify", "--start", st.get("start", ""))
    check("service: still valid after the kill", 0, rc)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=30)

    # AL-35: the service not there, the entry waits in the journal
    while True:
        try:
            journal.recv(65536)
        except TimeoutError:
            break
    nowhere = dict(env, MP_AUDIT_SOCKET=os.path.join(tmp, "nowhere"))
    rc, _, err = cli(
        dict(nowhere, MP_AUDIT_UID="0"), "record", "E10", "refused", "--actor", "1-1", "--obj", "046a:0011"
    )
    got = b""
    try:
        got = journal.recv(65536)
    except TimeoutError:
        pass
    check("record: without the service it queues in the journal", (0, True), (rc, b"MP_AUDIT_PENDING=1" in got))
    # Decision 23: without root nothing goes into the journal; the service
    # would not take it over anyway
    rc, _, err = cli(dict(nowhere, MP_AUDIT_UID="1000"), "record", "E10", "refused", "--actor", "1-1")
    got = b""
    try:
        got = journal.recv(65536)
    except TimeoutError:
        pass
    check(
        "record: without root it refuses and queues nothing",
        (2, False),
        (rc, b"MP_AUDIT_PENDING=1" in got),
        err.strip(),
    )
    journal.close()
    shutil.rmtree(tmp)


def main():
    for t in (
        test_chain,
        test_tamper,
        test_restart,
        test_crash,
        test_lost_key,
        test_strings,
        test_parallel,
        test_reset,
        test_open_summary,
        test_budget_design,
        test_flood,
        test_change_at_once,
        test_wear,
        test_clock,
        test_trial,
        test_service,
    ):
        t()
    sys.exit(failed)


if __name__ == "__main__":
    main()
