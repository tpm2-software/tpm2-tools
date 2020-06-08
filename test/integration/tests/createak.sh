# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f ek.pub ak.pub ak.name ak.name ak.log

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2 evictcontrol -Q -C o -c 0x8101000b 2>/dev/null || true
    tpm2 evictcontrol -Q -C o -c 0x8101000c 2>/dev/null || true

    # clear tpm state
    tpm2 clear

    if [ "$1" != "no-shut-down" ]; then
      shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 createek -Q -c 0x8101000b -G rsa -u ek.pub

tpm2 createak -Q -C 0x8101000b -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub \
-n ak.name -q ak.qname

# Validate the qname
tpm2 readpublic -c ak.ctx -q ak.qname2
diff ak.qname ak.qname2

# Find a vacant persistent handle
tpm2 createak -C 0x8101000b -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub \
-n ak.name
tpm2 evictcontrol -c ak.ctx > ak.log
phandle=`yaml_get_kv ak.log "persistent-handle"`
tpm2 evictcontrol -Q -C o -c $phandle

# Test tpm2 createak with endorsement password
cleanup "no-shut-down"
tpm2 changeauth -c e endauth
tpm2 createek -Q -P endauth -c 0x8101000b -G rsa -u ek.pub
tpm2 createak -Q -P endauth -C 0x8101000b -c ak.ctx -G rsa -u ak.pub -n ak.name

exit 0
