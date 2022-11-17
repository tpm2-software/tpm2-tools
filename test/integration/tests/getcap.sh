# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

out=out.yaml

cleanup() {
    rm -f $out

    shut_down
}
trap cleanup EXIT

function yaml_to_list() {

python << pyscript
from __future__ import print_function

import sys
import yaml

with open("$1") as f:
    try:
        y = yaml.safe_load(f)
        print(' '.join(y))
    except yaml.YAMLError as exc:
        sys.exit(exc)
pyscript
}

tpm2 getcap -l | grep -v 'vendor' > $out

caplist=$(yaml_to_list $out)

for c in $caplist; do
    tpm2 getcap "$c" > $out
    yaml_verify $out
done;

# negative tests
trap - ERR

# Regression test, ensure that getcap -c never accepts prefix matches
tpm2 getcap -Q --capability="comma" 2>/dev/null
if [ $? -eq -1 ]; then
  echo "Expected \"tpm2 getcap -Q --capability=\"comma\"\" to fail."
  exit 1
fi

exit 0
