# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f secret.data ek.pub ak.pub ak.name mkcred.out actcred.out ak.out \
    ak.ctx session.ctx

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2 evictcontrol -Q -C o -c 0x81010009 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo 12345678 > secret.data

tpm2 createek -Q -c 0x81010009 -G rsa -u ek.pub

tpm2 createak -C 0x81010009 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub \
-n ak.name -p akpass> ak.out

file_size=`ls -l ak.name | awk {'print $5'}`
loaded_key_name=`cat ak.name | xxd -p -c $file_size` # Use -c in xxd so there is no line wrapping

tpm2 readpublic -c 0x81010009 -o ek.pem -f pem -Q

echo "12345678" | tpm2 makecredential -Q -u ek.pem -s - -n $loaded_key_name \
-o mkcred.out -G rsa

# Test the secret data matches after credential activation process
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c e
tpm2 activatecredential -Q -c ak.ctx -C 0x81010009 -i mkcred.out \
-o actcred.out -p akpass -P"session:session.ctx"
tpm2 flushcontext session.ctx

diff actcred.out secret.data

# Capture the yaml output and verify that its the same as the name output
loaded_key_name_yaml=`python << pyscript
from __future__ import print_function

import yaml

with open('ak.out', 'r') as f:
    doc = yaml.safe_load(f)
    print(doc['loaded-key']['name'])
pyscript`

test "$loaded_key_name_yaml" == "$loaded_key_name"

exit 0
