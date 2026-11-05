# Contributing

mp-audit is a compliance record: what it writes has to stand up as proof for years, on machines in the field. So a change here is held to more than most code. It must not alter what a written log means, and anything that does change has to be shown not to break the check.

## Setting up

You need Python 3.11 or later and `make`. `make` installs the pinned tools into `.venv` when it needs them.

| Command | What it does |
| --- | --- |
| `make check` | everything below, as the CI does |
| `make test` | all tests, about 40 s |
| `make test T=test_chain` | only the tests named |
| `make lint` | `ruff format`, `ruff check` and `shellcheck` |
| `make format` | format the Python |
| `make unit` | check the systemd unit |

To run the hooks on every commit, activate `.venv` and run `pre-commit install`. They need that environment active when you commit.

## Changing the code

- **Style:** `ruff` decides, with the rules in `pyproject.toml`. That includes the complexity limits, so split a function that outgrows them.
- **`overlay/`:** everything in it goes into the image as it is, at the same path. Anything that should not be on a device stays outside it.
- **New tests:** add them to `TESTS` at the end of `test/test-mp-audit.py`, or they never run. Every `test/*.sh` also runs in the image's CI under `dash`, so a script there has to be a test and POSIX.
- **Device behaviour:** the tests do not reach mounting, `blkid`, `mkfs`, `e2fsck`, `chattr +a`, the unit's sandbox or the real journal. Say in your PR how you checked a change there.
- **The core:** [CLAUDE.md](CLAUDE.md) describes the rules that span the files, such as how sequence numbers are accounted for. Read it before changing the log or the check.

## Requirements

The requirements and their numbered decisions are in [docs/meltingplot-audit-log.md](docs/meltingplot-audit-log.md). If a change would depart from them or needs a new decision, ask the maintainer before you start. Then requirement text, code and tests change in one PR, with the decision recorded as "(name, date)". Numbers are never reused or renumbered, because the source cites them.

AL-nn, E01 to E23, T-nn and decision nn ("Festlegung nn") refer to that document, and LY-nn to [docs/meltingplot-layout.md](https://github.com/Meltingplot/rpi-image-gen/blob/meltingplot/docs/meltingplot-layout.md) in rpi-image-gen. Cite them in comments the way the code does.

Completed steps and deviations from the sketch go into [docs/phase-plan.md](docs/phase-plan.md).

Source, comments, README and commits are in English. The requirements and the phase plan are in German.

## Commits and pull requests

- **Subjects** are `area: what changed`, such as `auditcore:`, `mp-auditd:`, `docs:` or `ci:`. The `meltingplot:` prefix on older commits comes from their import.
- **Bodies** are prose: why, the AL-nn and decisions concerned, and what was seen on a device.
- **Formatting-only changes** go in a commit of their own, listed in `.git-blame-ignore-revs`.
- **Every change goes through a PR.** The CI has to pass, and the maintainer merges, with a merge commit and not a squash, because `.git-blame-ignore-revs` names commits by their hash.

## Releases and the image

The version in `pyproject.toml` and an annotated tag `v<version>` on its merge commit go together. A final image release needs the pinned commit to carry a tag, which the release gate of the image checks.

After a merge, a PR of its own in rpi-image-gen moves the submodule, as the [README](README.md) describes.
