# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    shut_down
}
trap cleanup EXIT

start_up

lockPasswd=lockoutpass
platPasswd=platformpass

#Test tpm2 clear works with blank lockout auth as default
tpm2 clear

#Test tpm2 clear works with non-empy lockout auth as default
tpm2 changeauth -c l $lockPasswd
tpm2 clear $lockPasswd

#Test tpm2 clear works with non-empy lockout auth and specified auth hierarchy
tpm2 changeauth -c l $lockPasswd
tpm2 clear -c l $lockPasswd

#Test tpm2 clear works with non-empy platform auth and specified auth hierarchy
tpm2 changeauth -c p $platPasswd
tpm2 clear -c p $platPasswd

#Undo change of platform auth
tpm2 changeauth -c p -p $platPasswd

exit 0
