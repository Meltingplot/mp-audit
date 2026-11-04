"""Format, hash chain and signatures of the Meltingplot audit log.

The requirements are in docs/meltingplot-audit-log.md; the AL-nn numbers
below refer to it. This module is shared by the service (mp-auditd), the
command line tool (mp-audit) and the check of a log off the device. It needs
Python 3.11 or later and python3-cryptography, nothing else, so a copy of it
next to an exported log is enough to check that log on any computer.

A log is a sequence of lines, one JSON object each, in canonical form (keys
sorted, no spaces, ASCII only). Every line carries the SHA-256 of the line
before it in "prev" (AL-13); the first line has 64 zeros there. There are
two kinds of line:

- an entry, with a sequence number "seq" and an event id "ev" (AL-01);
- a seal, with an epoch number "seal", which closes an epoch (AL-55).

The first line is the genesis entry (E01). It carries the public key of
epoch 0, and its hash is the start hash that is anchored outside the device
(AL-57, AL-58). Each seal is signed with the private key of the epoch it
closes and announces the public key of the next one in "next"; the service
destroys the private key once the seal is written (AL-56). The signature
covers the seal without its "sig" field, and through "prev" the whole log up
to it. Whoever has the start hash can check every sealed epoch without any
secret (AL-59, AL-61).

Sequence numbers count events, not lines (AL-41): an event that arrives
while its class is over budget is only counted, in a summary entry ("agg")
written later. An event the service accepted but lost in a crash is counted
in an E17 entry ("data": {"lost": n}). So every number up to the highest is
an entry, inside a summary or declared lost, and the check counts that.
"""

import base64
import hashlib
import json

FORMAT = 1
ALG = "ecdsa-p256-sha256"
ZERO = "0" * 64

# Classes (AL-39). Only the service decides the class of an event, from its
# id and result; a caller cannot choose it.
STATE = "state"
CHANGE = "change"
ATTEMPT = "attempt"
OPERATION = "operation"
CLASSES = (STATE, CHANGE, ATTEMPT, OPERATION)

# Event ids (docs/meltingplot-audit-log.md, "Ereignisse") with the class of
# their usual result and a short title. The list is fixed and short: it is
# what floods are grouped by, so nobody outside the image can lengthen it.
EVENTS = {
    "E01": (CHANGE, "commissioning, audit log created"),
    "E02": (CHANGE, "new image started"),
    "E03": (OPERATION, "update order"),
    "E04": (CHANGE, "board firmware flashed"),
    "E05": (CHANGE, "file under 0:/sys changed"),
    "E06": (CHANGE, "mainboard reset after update"),
    "E07": (CHANGE, "plugin installed or removed"),
    "E08": (OPERATION, "printer network profile reset"),
    "E10": (CHANGE, "USB device"),
    "E11": (OPERATION, "USB stick mounted or removed"),
    "E12": (CHANGE, "SSH login"),
    "E13": (CHANGE, "root via sudo"),
    "E14": (CHANGE, "remote access via Raspberry Pi Connect"),
    "E15": (OPERATION, "unexpected restart"),
    "E16": (OPERATION, "system clock set or synchronised"),
    "E17": (OPERATION, "audit log fault"),
    "E18": (CHANGE, "audit log deleted, or carried over by an installation"),
    "E19": (OPERATION, "flood, events aggregated"),
    "E20": (STATE, "state of the security relevant objects"),
    "E21": (OPERATION, "wear of the storage"),
    "E22": (OPERATION, "audit log exported"),
    "E23": (CHANGE, "camera changed"),
}

# A refused update, plugin start, USB device or login is an attempt, not a
# change (AL-39).
ATTEMPT_WHEN_REFUSED = frozenset({"E03", "E07", "E10", "E12"})

# Results (AL-01). "aggregated" marks a summary and is the service's own.
RESULTS = ("allowed", "refused", "done", "failed", "deferred", "info")
AGGREGATED = "aggregated"


def class_of(ev, res):
    if ev in ATTEMPT_WHEN_REFUSED and res == "refused":
        return ATTEMPT
    return EVENTS[ev][0]


# --- canonical form -----------------------------------------------------------

def canon(obj):
    """The one serialisation that is hashed and signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def line_hash(line):
    """Lines are read with surrogateescape, so this hashes the bytes on disk,
    also of a line that is not ASCII or not even UTF-8."""
    return hashlib.sha256(line.encode("utf-8", "surrogateescape")).hexdigest()


def fingerprint(start):
    """The first 128 bits of a start hash in groups of four (AL-58)."""
    return " ".join(start[i:i + 4] for i in range(0, 32, 4))


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- strings from outside (AL-02) ---------------------------------------------

def clean(value, limit):
    """Bounded and free of control characters. Never interpreted."""
    text = str(value)
    out = []
    for ch in text[:limit]:
        o = ord(ch)
        if o < 0x20 or o == 0x7f or 0x80 <= o < 0xa0:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    text = "".join(out)[:limit]
    if len(str(value)) > limit:
        text += "..."
    return text


def clean_data(data, keys=16, limit=256):
    """A small dict of extra details: bounded keys, scalar values."""
    out = {}
    if not isinstance(data, dict):
        return out
    for k in sorted(data)[:keys]:
        key = clean(k, 24)
        v = data[k]
        if isinstance(v, bool) or v is None:
            out[key] = v
        elif isinstance(v, int) and abs(v) < 2 ** 63:
            out[key] = v
        else:
            out[key] = clean(v, limit)
    return out


# --- keys ----------------------------------------------------------------------

def _ec():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec


def new_key():
    ec = _ec()
    return ec.generate_private_key(ec.SECP256R1())


def key_to_bytes(key):
    return key.private_numbers().private_value.to_bytes(32, "big")


def key_from_bytes(raw):
    ec = _ec()
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def public_text(key):
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return b64(raw)


def sign(key, payload):
    from cryptography.hazmat.primitives import hashes
    return b64(key.sign(payload.encode("ascii"), _ec().ECDSA(hashes.SHA256())))


def signature_valid(pub, sig, payload):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    ec = _ec()
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(pub))
        key.verify(unb64(sig), payload.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def seal_payload(seal):
    return canon({k: v for k, v in seal.items() if k != "sig"})


# --- check (AL-61) -------------------------------------------------------------

class Report:
    """What the check found. "result" is the verdict:

    valid     every line chains, every seal is signed by the key the previous
              epoch announced, sequence numbers are accounted for;
    changed   a line does not chain, a seal is not validly signed, or an epoch
              is missing: something was altered after it was written;
    unsealed  valid, but nothing is sealed yet;
    empty     no lines at all.

    A start hash given to the check that differs from the log's makes the
    result "foreign": the log does not begin where the anchor says.

    Numbers counted in a summary that is not written yet (AL-41) are in
    "pending": exactly, when the service said which summaries are open;
    otherwise as far as the log itself announces them with E19.
    """

    def __init__(self):
        self.start = None
        self.start_expected = None
        self.lines = 0
        self.entries = 0
        self.seals = 0
        self.epochs_valid = 0
        self.problems = []      # (line number, epoch, text)
        self.unsealed = 0       # entries after the last seal
        self.last_seq = 0
        self.last_hash = ZERO
        self.accounted = 0
        self.lost = 0
        self.aggregated = 0
        self.torn = 0
        self.rekeys = 0
        self.pending = 0        # numbers in summaries not written yet
        self.pending_keys = []  # their class/id

    @property
    def result(self):
        if self.lines == 0:
            return "empty"
        if self.start_expected and self.start != self.start_expected:
            return "foreign"
        if self.problems:
            return "changed"
        if self.seals == 0:
            return "unsealed"
        return "valid"

    def as_dict(self):
        return {
            "result": self.result,
            "start": self.start,
            "start_expected": self.start_expected,
            "lines": self.lines,
            "entries": self.entries,
            "seals": self.seals,
            "epochs_valid": self.epochs_valid,
            "unsealed": self.unsealed,
            "last_seq": self.last_seq,
            "last_hash": self.last_hash,
            "aggregated": self.aggregated,
            "lost": self.lost,
            "pending": self.pending,
            "pending_keys": self.pending_keys,
            "torn": self.torn,
            "problems": [{"line": n, "epoch": e, "text": t} for n, e, t in self.problems],
        }


def verify(lines, start=None, open_summaries=None):
    """Check a log given as an iterable of lines (with or without newline).

    Goes on after a problem, so the report names every place, and keeps
    checking the chain from the altered line onwards.

    open_summaries is what the service reports along with the lines it
    hands out: [{"key", "from", "to", "n"}] of the summaries it has not
    written yet. With it every number is accounted for exactly; without it,
    for a log read from files, a shortfall is accepted only as far as E19
    entries announce summaries that no summary entry has closed yet.
    """
    rep = Report()
    announced = {}          # E19 not yet followed by its summary entry
    rep.start_expected = start
    prev = ZERO
    pub = None
    epoch = 0
    epoch_ok = True
    pending_torn = None     # (line number, hash) of an unreadable line
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line:
            continue
        rep.lines += 1
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("not an object")
        except ValueError:
            # A write cut short by a crash. The service writes an E17 right
            # after it that names its hash and chains past it; anything else
            # is damage.
            if pending_torn:
                rep.problems.append((pending_torn[0], epoch, "unreadable line"))
                epoch_ok = False
            pending_torn = (n, line_hash(line))
            continue
        if pending_torn:
            torn_hash = obj.get("data", {}).get("torn_sha256") if isinstance(obj.get("data"), dict) else None
            if obj.get("ev") == "E17" and torn_hash == pending_torn[1]:
                rep.torn += 1
            else:
                rep.problems.append((pending_torn[0], epoch, "unreadable line"))
                epoch_ok = False
            pending_torn = None

        if obj.get("prev") != prev:
            rep.problems.append((n, epoch, "does not chain to the line before"))
            epoch_ok = False
        h = line_hash(line)

        if rep.lines == 1:
            gen = obj.get("genesis")
            if obj.get("ev") != "E01" or not isinstance(gen, dict):
                rep.problems.append((n, epoch, "first line is not a genesis entry"))
                epoch_ok = False
            else:
                if gen.get("alg") != ALG or gen.get("format") != FORMAT:
                    rep.problems.append((n, epoch, "unknown format or algorithm"))
                    epoch_ok = False
                pub = gen.get("pub")
            rep.start = h

        if "seal" in obj:
            rep.seals += 1
            if obj.get("seal") != epoch:
                rep.problems.append((n, epoch, "seal of epoch %s where %d was due" % (obj.get("seal"), epoch)))
                epoch_ok = False
            if pub is None or not signature_valid(pub, obj.get("sig", ""), seal_payload(obj)):
                rep.problems.append((n, epoch, "seal not signed by the key of its epoch"))
                epoch_ok = False
            if epoch_ok:
                rep.epochs_valid += 1
            pub = obj.get("next")
            epoch += 1
            epoch_ok = True
            rep.unsealed = 0
        elif "rekey" in obj:
            # The service lost the key of the open epoch and continues with
            # a new one nobody vouched for. Valid in form, but whatever the
            # epoch held can no longer be shown to be unaltered.
            rep.rekeys += 1
            rep.problems.append((n, epoch, "new key without a seal: epoch %d is not verifiable" % epoch))
            pub = obj.get("next")
            epoch += 1
            epoch_ok = True
            rep.unsealed = 0
        else:
            seq = obj.get("seq")
            if not isinstance(seq, int) or seq <= rep.last_seq:
                rep.problems.append((n, epoch, "sequence number %r out of order" % (seq,)))
                epoch_ok = False
            else:
                rep.last_seq = seq
            rep.entries += 1
            rep.unsealed += 1
            rep.accounted += 1
            agg = obj.get("agg")
            if isinstance(agg, dict) and isinstance(agg.get("n"), int):
                rep.accounted += agg["n"]
                rep.aggregated += agg["n"]
            data = obj.get("data")
            if obj.get("ev") == "E17" and isinstance(data, dict) and isinstance(data.get("lost"), int):
                rep.accounted += data["lost"]
                rep.lost += data["lost"]
            if obj.get("ev") == "E19" and isinstance(data, dict):
                key = "%s/%s" % (data.get("class"), data.get("event"))
                first = data.get("from")
                announced[first if isinstance(first, int) else key] = key
            if isinstance(agg, dict):
                # closed: by its first number, or, in logs from before
                # E19 named it, by class and id
                key = "%s/%s" % (obj.get("cls"), obj.get("ev"))
                first = agg.get("from")
                if isinstance(first, int) and first in announced:
                    del announced[first]
                elif key in announced:
                    del announced[key]
        prev = h
        rep.last_hash = h

    if pending_torn:
        # Cut short at the very end, nothing written after: the crash the
        # service has not yet come back from. Not an alteration.
        rep.torn += 1
    short = rep.last_seq - rep.accounted
    if open_summaries is not None:
        # From the service, at the moment the lines were read: each number up
        # to the highest it handed out is on the disk or in one of these.
        top = max([rep.last_seq] + [o.get("to") or 0 for o in open_summaries])
        held = sum(o.get("n", 0) for o in open_summaries)
        if rep.accounted + held != top:
            rep.problems.append((rep.lines, epoch, "%d events counted and %d in open summaries, %d numbered"
                                 % (rep.accounted, held, top)))
        else:
            rep.last_seq = top
            rep.pending = held
            rep.pending_keys = [o.get("key", "") for o in open_summaries]
    elif short > 0 and announced and short >= len(announced):
        # Each announced summary holds at least the number before its E19.
        rep.pending = short
        rep.pending_keys = sorted(set(announced.values()))
    elif short != 0:
        rep.problems.append((rep.lines, epoch,
                             "%d events counted, %d numbered" % (rep.accounted, rep.last_seq)))
    return rep
