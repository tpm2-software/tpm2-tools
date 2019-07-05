# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    shut_down
}
trap cleanup EXIT

start_up

lockPasswd=lockoutpass
platPasswd=platformpass

#Test tpm2_clear works with blank lockout auth as default
tpm2_clear

#Test tpm2_clear works with non-empy lockout auth as default
tpm2_changeauth -c l $lockPasswd
tpm2_clear $lockPasswd

#Test tpm2_clear works with non-empy lockout auth and specified auth hierarchy
tpm2_changeauth -c l $lockPasswd
tpm2_clear -c l $lockPasswd

#Test tpm2_clear works with non-empy platform auth and specified auth hierarchy
tpm2_changeauth -c p $platPasswd
tpm2_clear -c p $platPasswd

#Undo change of platform auth
tpm2_changeauth -c p -p $platPasswd

exit 0
