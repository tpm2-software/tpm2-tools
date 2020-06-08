# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

cleanup() {
    rm -f saved_session.ctx

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

cleanup "no-shut-down"
tpm2 clear

# Test for flushing the specified handle
tpm2 createprimary -Q -C o -g sha256 -G rsa
# tpm2-abrmd may save the transient object and restore it when using
res=`tpm2 getcap handles-transient`
if [ -n "$res" ]; then
    tpm2 flushcontext -Q -c 0x80000000
fi

# Test for flushing a transient object
tpm2 createprimary -Q -C o -g sha256 -G rsa
tpm2 flushcontext -Q -t

# Test for flushing a loaded session
tpm2 createpolicy -Q --policy-session --policy-pcr -l sha256:0
tpm2 flushcontext -Q -l

cleanup "no-shut-down"

exit 0
