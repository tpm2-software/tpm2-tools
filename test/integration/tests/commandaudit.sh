# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    rm -f \
    prim.ctx signing_key.ctx signing_key.pub signing_key.priv \
    att.data att.sig

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 clear

#
# Audit counter should be zero at reset
#
AUDIT_COUNTER_ZERO=0x0
tpm2 getcap properties-variable | \
grep TPM2_PT_AUDIT_COUNTER_1 | awk -F " " '{print $2}' | \
grep $AUDIT_COUNTER_ZERO

#
# Audit counter increments when setting up the audit digest algorithm
# other than the default. In simulator the default is sha512.
#
tpm2 setcommandauditstatus -g sha256

AUDIT_COUNTER_ONE=0x1
tpm2 getcap properties-variable | \
grep TPM2_PT_AUDIT_COUNTER_1 | awk -F " " '{print $2}' | \
grep $AUDIT_COUNTER_ONE

tpm2 createprimary -C o -c prim.ctx
tpm2 create -C prim.ctx -c signing_key.ctx -u signing_key.pub -r signing_key.priv
#
# Check TPM2_CC_SetCommandAuditStatus is included by default
#
tpm2 getcommandauditdigest -g sha256 -f plain -m att.data -s att.sig \
-c signing_key.ctx

TPM2_CC_SetCommandAuditStatus=00000140
diff -B \
<( echo $TPM2_CC_SetCommandAuditStatus | xxd -r -p | \
openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Check if TPM2_CC_GetRandom is added to the setlist
#
tpm2 setcommandauditstatus TPM2_CC_GetRandom
tpm2 getcommandauditdigest -g sha256 -f plain -m att.data -s att.sig \
-c signing_key.ctx
TPM2_CC_GetRandom=0000017B
diff -B \
<( echo $TPM2_CC_SetCommandAuditStatus$TPM2_CC_GetRandom | \
xxd -r -p | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

tpm2 print -t TPMS_ATTEST att.data
#
# Check TPM2_CC_GetRandom is removed from the audit list
#
tpm2 setcommandauditstatus --clear-list TPM2_CC_GetRandom
tpm2 getcommandauditdigest -g sha256 -f plain -m att.data -s att.sig \
-c signing_key.ctx
diff -B \
<( echo $TPM2_CC_SetCommandAuditStatus | xxd -r -p | \
openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

exit 0
