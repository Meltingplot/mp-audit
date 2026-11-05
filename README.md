# mp-audit

The audit log of the Meltingplot printer computers: a lasting record of every
intervention in software, configuration and access, as the Machinery Regulation
asks (Annex III 1.1.9).

Entries are chained by hash and sealed in epochs of operating time, each with a
key that is destroyed after use, so the log can be checked with nothing but its
start hash. `mp-audit.service` keeps the log on a partition of its own, and the
`mp-audit` tool records, shows and checks it.

The image repository [Meltingplot/rpi-image-gen](https://github.com/Meltingplot/rpi-image-gen)
pins this repository as the submodule `meltingplot/mp-audit`. These parts stay
there:

- the requirements, [docs/meltingplot-audit-log.md](https://github.com/Meltingplot/rpi-image-gen/blob/meltingplot/docs/meltingplot-audit-log.md).
  The `docs/...` paths and the numbers AL-nn, E01 to E23 and "decision nn" in
  the source refer to it;
- the layer `meltingplot/layer/mp-audit.yaml`, which takes the packages and
  enables the service;
- the build's check that the budgets fit the partition, the hook
  `customize90-audit-capacity` of that layer.

## Layout

| Path | Contents |
| --- | --- |
| `overlay/usr/bin/mp-audit` | the command line tool |
| `overlay/usr/lib/meltingplot/mp-audit/mp-auditd` | the service |
| `overlay/usr/lib/meltingplot/mp-audit/auditcore.py` | the logic of the log: budgets, epochs and what is on the partition |
| `overlay/usr/lib/meltingplot/mp-audit/auditlog.py` | format, hash chain and signatures, also for checking a log off the device |
| `overlay/usr/lib/systemd/system/mp-audit.service` | the unit |
| `test/` | the tests, which run on a build host |

Everything under `overlay/` goes into the image as it is, at the same path.
Anything that should not be on the device belongs outside that directory.

On the device the service also uses `python3-cryptography`, `e2fsprogs` and
`/usr/lib/meltingplot/mp-common.sh` from the image's layer `mp-identity`.

## Tests

The tests need `python3` and `python3-cryptography`. The core runs on a
temporary directory with a simulated clock, so years of operating time pass in
seconds.

```sh
sh test/test-mp-audit.sh
```

The image's CI runs them at the pinned commit.

## Getting a change into the image

Merge the change here, then move the submodule in the image repository with a
pull request of its own:

```sh
git -C meltingplot/mp-audit fetch origin
git -C meltingplot/mp-audit checkout <commit>
git add meltingplot/mp-audit
```

A final image release needs that commit to carry a tag, which the release gate
of the image checks.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
