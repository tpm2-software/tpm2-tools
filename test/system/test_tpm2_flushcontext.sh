#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2017, Alibaba Group
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat key.ctx
}
trap cleanup EXIT

cleanup

# Test for flushing the specified handle
tpm2_createprimary -Q -H o -g sha256 -G rsa
# tpm2-abrmd may save the transient object and restore it when using
res=`tpm2_getcap -c handles-transient`
if [ -n "$res" ]; then
    tpm2_flushcontext -Q -c 0x80000000
fi

# Test for flushing a transient object
tpm2_createprimary -Q -H o -g sha256 -G rsa
tpm2_flushcontext -Q -t

# Test for flushing a loaded session
tpm2_createpolicy -Q -L sha256:0 -F pcr.in -f policy.out
tpm2_flushcontext -Q -l

cleanup "no-shut-down"

exit 0
