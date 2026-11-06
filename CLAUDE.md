# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The audit log of the Meltingplot printer computers, a compliance record under the Machinery Regulation (EU 2023/1230, Annex III 1.1.9): a Python service and command line tool that go into the Raspberry Pi images. There is no build step. [Meltingplot/rpi-image-gen](https://github.com/Meltingplot/rpi-image-gen) pins this repository as the submodule `meltingplot/mp-audit` and runs every `test/*.sh` in its CI under `dash` at the pinned commit.

Requirements and proof: `docs/meltingplot-audit-log.md`. What is done and what comes next: `docs/phase-plan.md`.

Working rules, commands and how a change lands are in @CONTRIBUTING.md.

## Commands

`make check` runs what the CI runs; `make test T=test_chain` runs only the tests named. `test_flood` (25 s) and `test_wear` (9 s) take nearly all the time of a full run. `ruff` finds `mp-audit` and `mp-auditd` only through `extend-include` in `pyproject.toml`, because they have no file extension.

Without `make`, the tests need only `python3` (3.11 or later) and `python3-cryptography`, not root: `sh test/test-mp-audit.sh [test_name...]`.

Check a log off the device, with nothing but the tool and `auditlog.py`:

```sh
python3 -I -B overlay/usr/bin/mp-audit verify --start HASH FILE...
```

`.github/workflows/ci.yml` runs on every PR: the hooks and `systemd-analyze verify` on the unit, the tests on arm64 Debian trixie with apt's `python3-cryptography`, as on a device, and on Python 3.11 and 3.14 for the off-device check. Its actions are pinned to a commit, with the version beside it.

Always use `-B` when running Python by hand. Everything under `overlay/` goes into the image as it is, so a `__pycache__` beside the modules would ship in a local build, even though `.gitignore` keeps it out of commits.

To run the service by hand, copy the environment from `Bench` in `test/test-mp-audit.py`: `MP_AUDIT_STORE` puts the log in a plain directory instead of on the partition, and the other `MP_*` variables redirect its paths and stub `journalctl` and `systemctl`.

## Architecture

Paths are under `overlay/usr/`. Each layer knows less than the one above it, and those boundaries are what make the simulated tests and the off-device check possible.

| File | Job | May use |
| --- | --- | --- |
| `bin/mp-audit` | CLI: talks to the socket, or reads files for `show` and `verify` | `auditlog` only |
| `lib/meltingplot/mp-audit/mp-auditd` | Ties the log to the computer: partition, socket, journal, its own events (E01, E02, E15 to E18) | `auditcore`, `auditlog` |
| `lib/meltingplot/mp-audit/auditcore.py` | `AuditCore`: budgets, summaries, epochs, keys, state | `auditlog`, the directory and the `ident`, `clock`, `journal` and `recover` callables it is handed; no sockets or mounting |
| `lib/meltingplot/mp-audit/auditlog.py` | Line format, chain, signatures, event table, `verify()` and its `_Check` | stdlib; `cryptography` only inside functions |

Coupling that is easy to miss:

- `mp-audit` and `auditlog.py` must keep working on any computer with only `python3-cryptography` (AL-61).
- The image build imports `auditcore` and reads `SHARES`: its hook `customize90-audit-capacity` requires `2 * sum(SHARES)` to fit the partition, and stops if `mp-auditd` is not at its path. Renaming either breaks a build in the other repository. That import must not need `cryptography`, which is why `auditlog.py` imports it inside functions and `PLC0415` is waived for that file.
- The tool and the service start with `python3 -I`, so they add their library path themselves. They rely on neither the working directory nor `PYTHONPATH`, and on their executable bits in git.
- On a device the service also needs `e2fsprogs` and `/usr/lib/meltingplot/mp-common.sh`. Packages are set in the image's layer `meltingplot/layer/mp-audit.yaml`.

### Rules that span the files

**Numbers count events, not lines.** Every sequence number up to the highest is an entry, inside a summary (`agg.n`), or declared lost (E17 with `data.lost`). `_entry()` takes a number as soon as it is called, so code that builds an entry and does not write it has to give the number back, as `_close_summaries()` does. `AuditCore._account()` and `_Check` in `auditlog.py` do this count independently and have to agree.

**The class decides durability.** `class_of(ev, res)` sets it; a caller cannot. `state` is written and sealed before `record()` returns. `change` is written before it returns and sealed with its epoch (decision 21). `attempt` and `operation` are batched for up to 5 s. `sync=True` writes, and seals if the class can afford it.

**Over budget lowers detail, never retention.** Each class has a `Bucket` that refills with operating time, which is `CLOCK_BOOTTIME` summed over boots and never the system clock (AL-49). Events over budget go into a fixed-size `Summary`, grouped only by class and event id, never by anything a caller chooses. E19 announces it, with `from` naming its first number. A summary waits a minute, an hour, then a day, and after a day it is written whatever the budget says. `test_budget_design` requires each class to earn a day's summaries for each of its ids, so a new event id or a smaller share can fail it.

**Only the open epoch's private key is on disk.** `seal()` stores the next key, writes the signed seal, then wipes the old key, in that order, so a crash always leaves a usable key. The signature covers the whole chain through `prev`. A lost key produces a `rekey` line, which `verify` reports as `changed` on purpose.

**`state.json` is a cache, not proof.** Everything in it about the log is recomputed from the lines after the position it names, or from the whole log if it is missing. Writing and `_scan()` share `_account()`, so new counters go there.

**Crashes leave declared gaps.** Each entry goes to the journal at once (`mirror`). The next start recovers what the journal still has (`lost_in_crash`) and declares the rest with E17 `lost`. A torn last line gets an E17 naming its `torn_sha256`, and `verify` steps over only a line named that way.

**A check through the service is exact, a check of files is not.** The service hands out its open summaries, so every number is accounted for and the result is `valid`. From files, a gap is accepted only as far as E19 announces open summaries, and the result is `pending`. `mp-audit verify` exits 0 for `valid`, `unsealed` and `pending`, 3 otherwise.

**The proof is never put at risk to keep going.** The service formats only when `blkid` finds no signature at all (`holds_ext4`), never repairs by force (`passes_fsck`), and falls back to journal-only mode when the partition is missing or the log cannot be opened (AL-36, AL-37). `start()` catches everything from opening the log, so it cannot become a restart loop.

**Written logs stay checkable.** Lines are hashed as they are on disk, in the form `canon()` gives them, and logs last at least five years (AL-05). `verify` accepts only a genesis with `format == FORMAT`, so bumping `FORMAT` means teaching it the old format too. It already handles E19 entries from before `from` existed.

**Trust boundaries.** The service enforces "only root records" with `SO_PEERCRED`; the check in the CLI is a courtesy, which is why `MP_AUDIT_UID` opens nothing. Reading the journal back trusts only fields journald sets itself (`_UID`, `_SYSTEMD_UNIT`). Strings from outside go through `al.clean` and `al.clean_data` (AL-02), and anything from the socket can be any JSON, not only what the tool sends. The `MP_*` variables exist for the tests only.

## Tests

`test/test-mp-audit.py` is plain Python around `check(name, want, got)`. Most tests drive `AuditCore` on a temporary directory (`/dev/shm` when writable) with the simulated `Clock` (`advance`, `reboot`). `test_service` runs the real `mp-auditd` and `mp-audit` as subprocesses through `Bench`, with stubs for `journalctl` and `systemctl` and a datagram socket as the journal.

They do not cover `mount_store` (`blkid`, `mkfs`, `e2fsck`, `mount`), `chattr +a`, the unit's sandbox or real journald. Bugs there have only shown up on a device, such as the `blkid` one in 6a7cbd0. When refactoring the core or the check, passing tests are not enough: compare old and new directly, as the commits that split `verify()` and `mount_store()` describe.

## Lab devices

Claude may use the bench HMI and the lab printer to check what the tests cannot. Their addresses are in local memory and must never appear in this public repository, its commits or its PRs.

Ask Tim first before anything destructive: a log reset, `mkfs`, a reflash or a reboot. Earlier fixes were checked by bind-mounting the changed file over the installed one. Whatever happens on a device stays in its audit log for good, a service restart included.

## Working with Tim

Tim is the maintainer that CONTRIBUTING.md names. Run `make check`, open the PR, see the CI pass and stop there: Tim merges. If a change would depart from the requirements or needs a new numbered decision, ask Tim before coding.
