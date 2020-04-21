# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2_clear

#
# Audit counter should be zero at reset
#
AUDIT_COUNTER_ZERO=0x0
tpm2_getcap properties-variable | \
grep TPM2_PT_AUDIT_COUNTER_1 | awk -F " " '{print $2}' | \
grep $AUDIT_COUNTER_ZERO

#
# Audit counter increments when setting up the audit digest algorithm
# other than the default
#
tpm2_setcommandauditstatus -g sha1

AUDIT_COUNTER_ONE=0x1
tpm2_getcap properties-variable | \
grep TPM2_PT_AUDIT_COUNTER_1 | awk -F " " '{print $2}' | \
grep $AUDIT_COUNTER_ONE

exit 0
