#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017, Intel Corporation
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

declare -A alg_hashes=(
  ["sha1"]="f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"
  ["sha256"]="6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38"
  ["sha384"]="ecf669bad80a9b2b267d8671bd7d012d92e8cd30fd28d88dcdbcc2ddffbb995c7f226011ac24ae92dcfb493e0a5ecf89"
  ["sha512"]="18b7381f36cdf5dd7c0b64835e0bf5041a52a38e3c3f4cbabcc4099d52590bf9916808138de511fb172cb64fcc11601f07d114f03e95e3d5ceacb330ce0f856a"
  ["sm3_256"]="2b14a1fc49869413b0beb707069cffc0c6b0a51f3fedb9ce072c80709652b3ae"
)

onerror() {
    echo "$BASH_COMMAND on line ${BASH_LINENO[0]} failed: $?"
    exit 1
}
trap onerror ERR

digests=""
# test a single algorithm based on what is supported
for alg in `tpm2_pcrlist -s | cut -d\  -f 3-`; do
  alg=`echo $alg | cut -d\( -f 1-1`;

  hash=${alg_hashes[$alg]}

  if [ ! -z  $digests ]; then
      digests="$digests,"
  fi

  digests="$digests$alg=$hash"

  tpm2_pcrextend 9:$alg=$hash

done;

#
# To keep things simple, compound specifications are just done with
# the supported sha1 algorithms to guarantee the command to succeed.
#
tpm2_pcrextend 8:$digests

# Extend a PCR for all supported banks like in the previous test but
# try extending two PCR in the same command.
tpm2_pcrextend 8:$digests 9:$digests

trap - ERR

# Over-length spec should fail
tpm2_pcrextend 8:$digests,sha1=$sha1hash 2>/dev/null
if [ $? != 1 ]; then
  echo "tpm2_pcrextend with over-length spec didn't fail!"
  exit 1
fi

exit 0
