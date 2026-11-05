# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The audit log of the Meltingplot printer computers, a compliance record under the Machinery Regulation (EU 2023/1230, Annex III 1.1.9): a Python service and command line tool that go into the Raspberry Pi images. There is no build step, lint configuration or CI here. [Meltingplot/rpi-image-gen](https://github.com/Meltingplot/rpi-image-gen) pins this repository as the submodule `meltingplot/mp-audit` and runs `test/*.sh` in its CI at the pinned commit.

Requirements and proof: `docs/meltingplot-audit-log.md`. What is done and what comes next: `docs/phase-plan.md`.

## Commands

```sh
sh test/test-mp-audit.sh    # everything, about 40 s; prints ok/FAIL per check, exit 0 when nothing failed
```

The tests need `python3` (3.11 or later) and `python3-cryptography`, not root. There is no test runner or filter, so to run one test:

```sh
python3 -I -B -c "
import importlib.util as u, sys
s = u.spec_from_file_location('t', 'test/test-mp-audit.py'); t = u.module_from_spec(s); s.loader.exec_module(t)
t.test_chain(); sys.exit(t.failed)"
```

`test_flood` (25 s) and `test_wear` (9 s) take nearly all the time. A new test has to be added to the tuple in `main()` or it never runs.

Check a log off the device, with nothing but the tool and `auditlog.py`:

```sh
python3 -I -B overlay/usr/bin/mp-audit verify --start HASH FILE...
```

Always use `-B` here. Everything under `overlay/` goes into the image as it is, and there is no `.gitignore`, so a `__pycache__` beside the modules could get committed and shipped.

To run the service by hand, copy the environment from `test_service()`: `MP_AUDIT_STORE` puts the log in a plain directory instead of on the partition, and the other `MP_*` variables redirect its paths and stub `journalctl` and `systemctl`.

## Architecture

Paths are under `overlay/usr/`. Each layer knows less than the one above it, and those boundaries are what make the simulated tests and the off-device check possible.

| File | Job | May use |
| --- | --- | --- |
| `bin/mp-audit` | CLI: talks to the socket, or reads files for `show` and `verify` | `auditlog` only |
| `lib/meltingplot/mp-audit/mp-auditd` | Ties the log to the computer: partition, socket, journal, its own events (E01, E02, E15 to E18) | `auditcore`, `auditlog` |
| `lib/meltingplot/mp-audit/auditcore.py` | `AuditCore`: budgets, summaries, epochs, keys, state | `auditlog`, the directory and the `ident`, `clock`, `journal` and `recover` callables it is handed; no sockets or mounting |
| `lib/meltingplot/mp-audit/auditlog.py` | Line format, chain, signatures, event table, `verify()` | stdlib; `cryptography` only inside functions |

Coupling that is easy to miss:

- `mp-audit` and `auditlog.py` must keep working on any computer with only `python3-cryptography` (AL-61).
- The image build imports `auditcore` and reads `SHARES`: its hook `customize90-audit-capacity` requires `2 * sum(SHARES)` to fit the partition, and stops if `mp-auditd` is not at its path. Renaming either breaks a build in the other repository.
- The tool and the service start with `python3 -I`, so they add their library path themselves. They rely on neither the working directory nor `PYTHONPATH`, and on their executable bits in git.
- On a device the service also needs `e2fsprogs` and `/usr/lib/meltingplot/mp-common.sh`. Packages are set in the image's layer `meltingplot/layer/mp-audit.yaml`.

### Rules that span the files

**Numbers count events, not lines.** Every sequence number up to the highest is an entry, inside a summary (`agg.n`), or declared lost (E17 with `data.lost`). `_entry()` takes a number as soon as it is called, so code that builds an entry and does not write it has to give the number back, as `_close_summaries()` does. `AuditCore._account()` and `auditlog.verify()` do this count independently and have to agree.

**The class decides durability.** `class_of(ev, res)` sets it; a caller cannot. `state` is written and sealed before `record()` returns. `change` is written before it returns and sealed with its epoch (decision 21). `attempt` and `operation` are batched for up to 5 s. `sync=True` writes, and seals if the class can afford it.

**Over budget lowers detail, never retention.** Each class has a `Bucket` that refills with operating time, which is `CLOCK_BOOTTIME` summed over boots and never the system clock (AL-49). Events over budget go into a fixed-size `Summary`, grouped only by class and event id, never by anything a caller chooses. E19 announces it, with `from` naming its first number. A summary waits a minute, an hour, then a day, and after a day it is written whatever the budget says. `test_budget_design` requires each class to earn a day's summaries for each of its ids, so a new event id or a smaller share can fail it.

**Only the open epoch's private key is on disk.** `seal()` stores the next key, writes the signed seal, then wipes the old key, in that order, so a crash always leaves a usable key. The signature covers the whole chain through `prev`. A lost key produces a `rekey` line, which `verify` reports as `changed` on purpose.

**`state.json` is a cache, not proof.** Everything in it about the log is recomputed from the lines after the position it names, or from the whole log if it is missing. Writing and `_scan()` share `_account()`, so new counters go there.

**Crashes leave declared gaps.** Each entry goes to the journal at once (`mirror`). The next start recovers what the journal still has (`lost_in_crash`) and declares the rest with E17 `lost`. A torn last line gets an E17 naming its `torn_sha256`, and `verify` steps over only a line named that way.

**A check through the service is exact, a check of files is not.** The service hands out its open summaries, so every number is accounted for and the result is `valid`. From files, a gap is accepted only as far as E19 announces open summaries, and the result is `pending`. `mp-audit verify` exits 0 for `valid`, `unsealed` and `pending`, 3 otherwise.

**The proof is never put at risk to keep going.** The service formats only when `blkid` finds no signature at all (exit 2), never repairs by force, and falls back to journal-only mode when the partition is missing or the log cannot be opened (AL-36, AL-37). `start()` catches everything from opening the log, so it cannot become a restart loop.

**Written logs stay checkable.** Lines are hashed as they are on disk, in the form `canon()` gives them, and logs last at least five years (AL-05). `verify` accepts only a genesis with `format == FORMAT`, so bumping `FORMAT` means teaching it the old format too. It already handles E19 entries from before `from` existed.

**Trust boundaries.** The service enforces "only root records" with `SO_PEERCRED`; the check in the CLI is a courtesy, which is why `MP_AUDIT_UID` opens nothing. Reading the journal back trusts only fields journald sets itself (`_UID`, `_SYSTEMD_UNIT`). Strings from outside go through `al.clean` and `al.clean_data` (AL-02). The `MP_*` variables exist for the tests only.

## Tests

`test/test-mp-audit.py` is plain Python around `check(name, want, got)`. Most tests drive `AuditCore` on a temporary directory (`/dev/shm` when writable) with the simulated `Clock` (`advance`, `reboot`). `test_service` runs the real `mp-auditd` and `mp-audit` as subprocesses, with stubs for `journalctl` and `systemctl` and a datagram socket as the journal.

They do not cover `mount_store` (`blkid`, `mkfs`, `e2fsck`, `mount`), `chattr +a`, the unit's sandbox or real journald. Bugs there have only shown up on a device, such as the `blkid` one in 6a7cbd0.

## Lab devices

Claude may use the bench HMI and the lab printer to check what the tests cannot. Their addresses are in local memory and must never appear in this public repository, its commits or its PRs.

Ask Tim first before anything destructive: a log reset, `mkfs`, a reflash or a reboot. Earlier fixes were checked by bind-mounting the changed file over the installed one. Whatever happens on a device stays in its audit log for good, a service restart included.

## Working here

- **Every change goes through a PR, and Tim merges.** Run the tests, open the PR and stop there.
- **The image follows separately.** After the merge, a PR of its own in rpi-image-gen moves the submodule (commands in the README). A final image release needs a tag on that commit.
- **Commit subjects are `area: what changed`**, such as `auditcore:`, `mp-auditd:` or `docs:`. The `meltingplot:` prefix on older commits comes from the import. Bodies are prose: why, the AL-nn and decisions concerned, and what was seen on a device.
- **Requirements:** if a change would depart from them or needs a new numbered decision, ask Tim before coding. Then requirement text, code and tests change in one PR, with the decision recorded as "(Tim, date)". Numbers are never reused or renumbered, because the source cites them.
- **Citations:** AL-nn, E01 to E23, T-nn and decision nn ("Festlegung nn") refer to `docs/meltingplot-audit-log.md`; LY-nn refers to `docs/meltingplot-layout.md` in rpi-image-gen. Cite them in comments the way the code does.
- **Language:** source, comments, README and commits are in English; the requirements and the phase plan are in German.
- **Phase plan:** completed steps and deviations from its sketch are recorded in `docs/phase-plan.md`.
- **Overlay:** anything that should not be on the device stays outside `overlay/`. A change inside it reaches devices with the next image.
