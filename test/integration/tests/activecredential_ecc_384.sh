# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f secret.data ek.pub ak.pub ak.name mkcred.out actcred.out ak.out \
    ak.ctx session.ctx policyA.sha384 policyC.sha384

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

# Policies for high range EKs
policy_a_hex="8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53"
echo -n "$policy_a_hex" | xxd -r -p > policyA.sha384
policy_c_hex="d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165"
echo -n "$policy_c_hex" | xxd -r -p > policyC.sha384

tpm2 createek -Q -c 0x81010009 -G ecc384 -u ek.pub

tpm2 createak -C 0x81010009 -c ak.ctx -G rsa -g sha384 -s rsassa -u ak.pub \
-n ak.name -p akpass> ak.out

file_size=`ls -l ak.name | awk {'print $5'}`
loaded_key_name=`cat ak.name | xxd -p -c $file_size` # Use -c in xxd so there is no line wrapping

tpm2 readpublic -c 0x81010009 -o ek.pem -f pem -Q

tpm2 makecredential -Q -u ek.pem -s secret.data -n $loaded_key_name \
-o mkcred.out -G ecc --tcti=none

# Test the secret data matches after credential activation process
tpm2 startauthsession --policy-session -S session.ctx -g sha384
tpm2 policysecret -S session.ctx -c e
tpm2 policyor -S session.ctx sha384:policyA.sha384,policyC.sha384
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
