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
  queued in the journal (AL-35), a reset leaves a trace (AL-17).
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

# The modules are imported from the layer's overlay, which goes into the
# image as it is: no __pycache__ may be left there.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.realpath(__file__))
OVERLAY = os.path.join(HERE, "..", "layer", "mp-audit.d", "customize.overlay")
LIB = os.path.realpath(os.path.join(OVERLAY, "usr", "lib", "meltingplot", "mp-audit"))
CLI = os.path.realpath(os.path.join(OVERLAY, "usr", "sbin", "mp-audit"))
DAEMON = os.path.join(LIB, "mp-auditd")
sys.path.insert(0, LIB)

import auditcore as ac   # noqa: E402
import auditlog as al    # noqa: E402

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
        check("keys: it is the one the last seal announced", last_seal["next"],
              al.public_text(al.key_from_bytes(f.read())))
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
    check("tamper: named as a seal that does not verify", True,
          any("not signed" in t for _, _, t in rep.problems))

    # without recomputing: the chain breaks at the next line
    objs = [json.loads(x) for x in lines]
    objs[i]["msg"] = "nothing happened"
    rep = al.verify([al.canon(o) for o in objs], start)
    check("tamper: plain edit breaks the chain", True,
          any("does not chain" in t for _, _, t in rep.problems))

    # a line taken out
    rep = al.verify(lines[:i] + lines[i + 1:], start)
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
    core.flush()
    for i in range(3):
        core.record("E13", "done", actor="mpadmin", msg="accepted, not yet written %d" % i)
    # power cut: nothing flushed, nothing saved
    pending = [(e["seq"], e) for e in mirrored if e["seq"] > 2]
    clk.reboot(5)
    c2 = new_core(d, clk)
    c2.open(recover=lambda bid, first: [(s, e) for s, e in pending if s >= first])
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


def test_reset():
    d, clk, core = fresh()
    old = core.start
    core.record("E13", "done", actor="mpadmin")
    new = core.reset("drive replaced in the lab", "mpadmin")
    check("reset: new start hash", True, new != old)
    archived = os.listdir(os.path.join(d, "archive"))
    check("reset: old log archived", 1, len(archived))
    e18 = [e for e in entries(core) if e["ev"] == "E18"]
    check("reset: E18 names the old log", old, e18[0]["data"]["old_start"] if e18 else None)
    check("reset: E18 names who and why", ("mpadmin", "drive replaced in the lab"),
          (e18[0].get("actor"), e18[0]["data"]["reason"]) if e18 else None)
    check("reset: new log valid", "valid", al.verify(lines_of(core), new).result)
    shutil.rmtree(d)


# --- floods and budgets -------------------------------------------------------------

def summary_max():
    s = ac.Summary(al.ATTEMPT, "E10", 0)
    for i in range(1000):
        s.add({"seq": 10 ** 9 + i, "t": "2026-11-04T12:00:00Z", "op": 10 ** 9, "res": "refused",
               "actor": "x" * 64 + str(i), "via": "y" * 32, "obj": "z" * 256 + str(i), "msg": "m" * 256})
    d, clk, core = fresh()
    e = core._entry("E10", al.AGGREGATED, msg="%d events counted" % (10 ** 9))
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
        ids = [ev for ev in al.EVENTS if al.EVENTS[ev][0] == cls
               or (cls == al.ATTEMPT and ev in al.ATTEMPT_WHEN_REFUSED)
               or (cls == al.OPERATION and ev == "E03")]
        b = ac.Bucket(ac.SHARES[cls])
        daily = b.rate * ac.DAY
        check("budget: %-9s earns a day's summaries (%d ids)" % (cls, len(ids)), True,
              daily >= len(ids) * smax, "earns %d B a day, needs %d" % (daily, len(ids) * smax))


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
        core.record("E10", "refused", actor="1-%d" % (n % 7), obj="%04x:%04x" % (n % 65536, n % 9973),
                    msg="device %d" % n)
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
        check("flood: %-9s within its budget" % cls, True, core.used[cls] <= allowance,
              "used %d B, allowed %d" % (core.used[cls], allowance))
    first = {}
    for e in es:
        first.setdefault(e["ev"], e)
    check("flood: first E10 kept as itself", "device 1", first["E10"].get("msg"))
    sums = [e for e in es if e.get("agg")]
    check("flood: summaries keep the last event", True, all(e["agg"].get("last") for e in sums))
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
    check("wear: at most one flush per 5 s, state once a minute", True, syncs <= 3600 // 5 + 3 * 60 + 20,
          "%d fsyncs" % syncs)
    shutil.rmtree(d)


def test_clock():
    """AL-49: budgets follow operating time, not the system clock."""
    d, clk, core = fresh()
    core.record("E12", "refused", actor="a")
    before = core.buckets[al.ATTEMPT].tokens
    clk.realtime += 6 * 365 * 86400
    core.tick()
    core.buckets[al.ATTEMPT].refill(core.op())
    check("clock: a clock six years ahead adds no budget", True,
          core.buckets[al.ATTEMPT].tokens - before < 1)
    shutil.rmtree(d)


# --- the service and the command line ------------------------------------------------

def cli(env, *args):
    p = subprocess.run([sys.executable, "-I", "-B", CLI] + list(args), env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


def test_service():
    tmp = mkdtemp()
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
    jsock = os.path.join(tmp, "journal.sock")
    journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    journal.bind(jsock)
    journal.settimeout(0.2)
    env = dict(os.environ, MP_AUDIT_RUN=run, MP_AUDIT_STORE=store,
               MP_DEVICE_CONF=os.path.join(tmp, "device.conf"),
               MP_IDENTITY_FILE=os.path.join(tmp, "identity"),
               MP_AUDIT_INSTALLER=os.path.join(tmp, "installer.txt"),
               MP_AUDIT_JOURNAL=jsock, MP_AUDIT_JOURNALCTL=stub,
               MP_AUDIT_SOCKET=os.path.join(run, "socket"))
    env.pop("NOTIFY_SOCKET", None)

    def start():
        p = subprocess.Popen([sys.executable, "-I", "-B", DAEMON], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    check("service: E18 says what the card found", "installation over layout gen2, no earlier audit log",
          e18.get("msg"))
    check("service: machine from the identity", "chx-350-001", e18.get("mach"))
    if os.geteuid() != 0:
        rc, _, err = cli(env, "record", "E10", "refused", "--actor", "1-1")
        check("service: only root records", 2, rc)
    rc, out, _ = cli(env, "verify", "--start", st.get("start", ""))
    check("service: verify on the device", 0, rc)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=30)
    check("service: clean stop", 0, p.returncode)

    p = start()
    rc, out, _ = cli(env, "show", "--all", "--json")
    evs = [json.loads(x)["ev"] for x in out.splitlines()]
    check("service: a clean restart adds no E15/E17", True, evs[:2] == ["E01", "E18"] and "E15" not in evs and "E17" not in evs,
          " ".join(evs))
    p.kill()
    p.wait()
    p = start()
    rc, out, _ = cli(env, "show", "--all", "--json")
    evs = [json.loads(x)["ev"] for x in out.splitlines()]
    check("service: a killed service is an E17 at the next start", True, "E17" in evs, " ".join(evs))
    rc, out, _ = cli(env, "verify", "--start", st.get("start", ""))
    check("service: still valid after the kill", 0, rc)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=30)

    # AL-35: the service not there, the entry waits in the journal
    while True:
        try:
            journal.recv(65536)
        except socket.timeout:
            break
    rc, _, err = cli(dict(env, MP_AUDIT_SOCKET=os.path.join(tmp, "nowhere")), "record", "E10", "refused",
                     "--actor", "1-1", "--obj", "046a:0011")
    got = b""
    try:
        got = journal.recv(65536)
    except socket.timeout:
        pass
    check("record: without the service it queues in the journal", (0, True), (rc, b"MP_AUDIT_PENDING=1" in got))
    journal.close()
    shutil.rmtree(tmp)


def main():
    for t in (test_chain, test_tamper, test_restart, test_crash, test_lost_key, test_strings,
              test_parallel, test_reset, test_budget_design, test_flood, test_wear, test_clock,
              test_service):
        t()
    sys.exit(failed)


if __name__ == "__main__":
    main()
