#!/bin/sh
# Tests for the audit log (layer mp-audit). The checks are in Python, like
# the service; see test-mp-audit.py for what they cover. Needs python3 and
# python3-cryptography on the build host.
set -eu
here=$(dirname "$(readlink -f "$0")")
exec python3 -I -B "$here/test-mp-audit.py" "$@"
