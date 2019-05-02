#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat key.dat evict.log

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -Q -a e -g sha256 -G rsa -o primary.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv  -C primary.ctx

tpm2_load -Q -C primary.ctx  -u key.pub  -r key.priv -n key.name -o key.dat

# Load the context into a specific handle, delete it
tpm2_evictcontrol -Q -c key.dat -p 0x81010003

tpm2_evictcontrol -Q -c 0x81010003 -p 0x81010003

# Load the context into a specific handle, delete it without an explicit -p
tpm2_evictcontrol -Q -a o -c key.dat -p 0x81010003

tpm2_evictcontrol -Q -a o -c 0x81010003

# Load the context into an available handle, delete it
tpm2_evictcontrol -a o -c key.dat > evict.log
phandle=`grep "persistentHandle: " evict.log | awk '{print $2}'`
tpm2_evictcontrol -Q -a o -c $phandle

yaml_verify evict.log

exit 0
