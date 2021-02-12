# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f ek.pub ek.log ek.template ek.nonce ek.ctx

    # Evict persistent handles, we want them to always succeed and never trip
    # the onerror trap.
    tpm2 evictcontrol -Q -C o -c 0x81010005 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
      shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 createek -c 0x81010005 -G rsa -u ek.pub

cleanup "no-shut-down"

tpm2 createek -c - -G rsa -u ek.pub > ek.log
phandle=`yaml_get_kv ek.log "persistent-handle"`
tpm2 evictcontrol -Q -C o -c $phandle

cleanup "no-shut-down"

tpm2 createek -G rsa -u ek.pub -c ek.ctx

cleanup "no-shut-down"

ek_nonce_index=0x01c00003
ek_template_index=0x01c00004

# Define RSA EK template
nbytes=$(wc -c ${abs_srcdir}/test/integration/fixtures/ek-template-default.bin | awk {'print $1'})
tpm2 nvdefine -Q $ek_template_index -C o -s $nbytes \
-a "ownerread|policywrite|ownerwrite"
tpm2 nvwrite -Q $ek_template_index -C o \
-i ${abs_srcdir}/test/integration/fixtures/ek-template-default.bin

# Define RSA EK nonce
echo -n -e '\0' > ek.nonce
tpm2 nvdefine -Q $ek_nonce_index -C o -s 1 \
-a "ownerread|policywrite|ownerwrite"
tpm2 nvwrite -Q $ek_nonce_index -C o -i ek.nonce

tpm2 createek -t -G rsa -u ek.pub -c ek.ctx

cleanup "no-shut-down"

exit 0
