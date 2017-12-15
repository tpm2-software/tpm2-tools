#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

#
# codes was generated from the TPM2_RC constants in:
# https://github.com/01org/tpm2-tss/blob/master/include/sapi/tss2_tpm2_types.h#L68
# Some of these may not be used correctly, which is OK, as tpm2_rc_decode never
# fails and should attempt to decode it or print some unkown status. This gives
# us coverage for both known and unkown/malformed inputs.
#
# Details on error code encoding can be found at:
# Section 6.6.2 of t "Trusted Platform Module Library Part 2: Structures Family “2.0” Level 00 Revision 01.38"
#  - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
#
declare -A codes
codes=(
  [TPM2_RC_SUCCESS]=0x0
  [TPM2_RC_BAD_TAG]=0x1E
  [TPM2_RC_INITIALIZE]=0x100
  [TPM2_RC_FAILURE]=0x101
  [TPM2_RC_SEQUENCE]=0x103
  [TPM2_RC_PRIVATE]=0x10B
  [TPM2_RC_HMAC]=0x119
  [TPM2_RC_DISABLED]=0x120
  [TPM2_RC_EXCLUSIVE]=0x121
  [TPM2_RC_AUTH_TYPE]=0x124
  [TPM2_RC_AUTH_MISSING]=0x125
  [TPM2_RC_POLICY]=0x126
  [TPM2_RC_PCR]=0x127
  [TPM2_RC_PCR_CHANGED]=0x128
  [TPM2_RC_UPGRADE]=0x12D
  [TPM2_RC_TOO_MANY_CONTEXTS]=0x12E
  [TPM2_RC_AUTH_UNAVAILABLE]=0x12F
  [TPM2_RC_REBOOT]=0x130
  [TPM2_RC_UNBALANCED]=0x131
  [TPM2_RC_COMMAND_SIZE]=0x142
  [TPM2_RC_COMMAND_CODE]=0x143
  [TPM2_RC_AUTHSIZE]=0x144
  [TPM2_RC_AUTH_CONTEXT]=0x145
  [TPM2_RC_NV_RANGE]=0x146
  [TPM2_RC_NV_SIZE]=0x147
  [TPM2_RC_NV_LOCKED]=0x148
  [TPM2_RC_NV_AUTHORIZATION]=0x149
  [TPM2_RC_NV_UNINITIALIZED]=0x14A
  [TPM2_RC_NV_SPACE]=0x14B
  [TPM2_RC_NV_DEFINED]=0x14C
  [TPM2_RC_BAD_CONTEXT]=0x150
  [TPM2_RC_CPHASH]=0x151
  [TPM2_RC_PARENT]=0x152
  [TPM2_RC_NEEDS_TEST]=0x153
  [TPM2_RC_NO_RESULT]=0x154
  [TPM2_RC_SENSITIVE]=0x155
  [TPM2_RC_ASYMMETRIC]=0x81
  [TPM2_RC_ATTRIBUTES]=0x82
  [TPM2_RC_HASH]=0x83
  [TPM2_RC_VALUE]=0x84
  [TPM2_RC_HIERARCHY]=0x85
  [TPM2_RC_KEY_SIZE]=0x87
  [TPM2_RC_MGF]=0x88
  [TPM2_RC_MODE]=0x89
  [TPM2_RC_TYPE]=0x8A
  [TPM2_RC_HANDLE]=0x8B
  [TPM2_RC_KDF]=0x8C
  [TPM2_RC_RANGE]=0x8D
  [TPM2_RC_AUTH_FAIL]=0x8E
  [TPM2_RC_NONCE]=0x8F
  [TPM2_RC_PP]=0x90
  [TPM2_RC_SCHEME]=0x92
  [TPM2_RC_SIZE]=0x95
  [TPM2_RC_SYMMETRIC]=0x96
  [TPM2_RC_TAG]=0x97
  [TPM2_RC_SELECTOR]=0x98
  [TPM2_RC_INSUFFICIENT]=0x9A
  [TPM2_RC_SIGNATURE]=0x9B
  [TPM2_RC_KEY]=0x9C
  [TPM2_RC_POLICY_FAIL]=0x9D
  [TPM2_RC_INTEGRITY]=0x9F
  [TPM2_RC_TICKET]=0xA0
  [TPM2_RC_RESERVED_BITS]=0xA1
  [TPM2_RC_BAD_AUTH]=0xA2
  [TPM2_RC_EXPIRED]=0xA3
  [TPM2_RC_POLICY_CC]=0xA4
  [TPM2_RC_BINDING]=0xA5
  [TPM2_RC_CURVE]=0xA6
  [TPM2_RC_ECC_POINT]=0xA7
  [TPM2_RC_CONTEXT_GAP]=0x901
  [TPM2_RC_OBJECT_MEMORY]=0x902
  [TPM2_RC_SESSION_MEMORY]=0x903
  [TPM2_RC_MEMORY]=0x904
  [TPM2_RC_SESSION_HANDLES]=0x905
  [TPM2_RC_OBJECT_HANDLES]=0x906
  [TPM2_RC_LOCALITY]=0x907
  [TPM2_RC_YIELDED]=0x908
  [TPM2_RC_CANCELED]=0x909
  [TPM2_RC_TESTING]=0x90A
  [TPM2_RC_REFERENCE_H0]=0x910
  [TPM2_RC_REFERENCE_H1]=0x911
  [TPM2_RC_REFERENCE_H2]=0x912
  [TPM2_RC_REFERENCE_H3]=0x913
  [TPM2_RC_REFERENCE_H4]=0x914
  [TPM2_RC_REFERENCE_H5]=0x915
  [TPM2_RC_REFERENCE_H6]=0x916
  [TPM2_RC_REFERENCE_S0]=0x918
  [TPM2_RC_REFERENCE_S1]=0x919
  [TPM2_RC_REFERENCE_S2]=0x91A
  [TPM2_RC_REFERENCE_S3]=0x91B
  [TPM2_RC_REFERENCE_S4]=0x91C
  [TPM2_RC_REFERENCE_S5]=0x91D
  [TPM2_RC_REFERENCE_S6]=0x91E
  [TPM2_RC_NV_RATE]=0x920
  [TPM2_RC_LOCKOUT]=0x921
  [TPM2_RC_RETRY]=0x922
  [TPM2_RC_NV_UNAVAILABLE]=0x923
  [TPM2_RC_NOT_USED]=0x97F

  [INVALID_1ST_PARAM]=0x1c4
)

for key in "${!codes[@]}"; do
  value=${codes[$key]}
  tpm2_rc_decode $value &>/dev/null
done;

#
# Negative tests
# clear the ERR trap before continuing.
#
trap - ERR
cmd="tpm2_rc_decode 0x6666329840938498293849238 &>/dev/null"
eval "$cmd"
if [ $? -eq 0 ]; then
  echo "Expected \"$cmd\" to fail."
  exit 1
fi

exit 0
