#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;
#
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
#;**********************************************************************;

source helpers.sh

pcr_ids="0"
alg_pcr_policy=sha256
file_pcr_value=pcr.bin
file_policy=policy.data
file_authorized_policy_1=auth_policy_1.data
file_authorized_policy_2=auth_policy_2.data
file_session_file="session.dat"
file_private_key="private.pem"
file_public_key="public.pem"
file_verifying_key_public="verifying_key_public"
file_verifying_key_name="verifying_key_name"
file_verifying_key_ctx="verifying_key_ctx"
file_policyref="policyref"

cleanup() {
    rm -f  $file_pcr_value $file_policy $file_session_file $file_private_key \
    $file_public_key $file_verifying_key_public $file_verifying_key_name \
    $file_verifying_key_ctx $file_policyref $file_authorized_policy_1 \
    $file_authorized_policy_2

    tpm2_flushcontext -S $file_session_file 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

generate_policy_authorize () {
    tpm2_startauthsession -Q -S $file_session_file
    tpm2_policyauthorize -Q -S $file_session_file  -o $3 -i $1 -q $2 -n $4
    tpm2_flushcontext -S $file_session_file
    rm $file_session_file
}

openssl genrsa -out $file_private_key 2048 2>/dev/null
openssl rsa -in $file_private_key -out $file_public_key -pubout 2>/dev/null
tpm2_loadexternal -G rsa -a n -u $file_public_key -o $file_verifying_key_ctx \
  -n $file_verifying_key_name

dd if=/dev/urandom of=$file_policyref bs=1 count=32 2>/dev/null

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value
tpm2_startauthsession -Q -S $file_session_file
tpm2_policypcr -Q -S $file_session_file -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -o $file_policy
tpm2_flushcontext -S $file_session_file
rm $file_session_file

generate_policy_authorize $file_policy $file_policyref $file_authorized_policy_1 \
  $file_verifying_key_name

tpm2_pcrextend  \
  0:sha256=e7011b851ee967e2d24e035ae41b0ada2decb182e4f7ad8411f2bf564c56fd6f

tpm2_pcrlist -Q -L ${alg_pcr_policy}:${pcr_ids} -o $file_pcr_value
tpm2_startauthsession -Q -S $file_session_file
tpm2_policypcr -Q -S $file_session_file -L ${alg_pcr_policy}:${pcr_ids} -F $file_pcr_value -o $file_policy
tpm2_flushcontext -S $file_session_file
rm $file_session_file

generate_policy_authorize $file_policy $file_policyref $file_authorized_policy_2 \
  $file_verifying_key_name

diff $file_authorized_policy_1 $file_authorized_policy_2

exit 0
