# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

declare -A alg_hashes=(
  ["sha1"]="f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"
  ["sha256"]="6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38"
  ["sha384"]="ecf669bad80a9b2b267d8671bd7d012d92e8cd30fd28d88dcdbcc2ddffbb995c7f226011ac24ae92dcfb493e0a5ecf89"
  ["sha512"]="18b7381f36cdf5dd7c0b64835e0bf5041a52a38e3c3f4cbabcc4099d52590bf9916808138de511fb172cb64fcc11601f07d114f03e95e3d5ceacb330ce0f856a"
  ["sm3_256"]="2b14a1fc49869413b0beb707069cffc0c6b0a51f3fedb9ce072c80709652b3ae"
)

digests=""
# test a single algorithm based on what is supported
for alg in `tpm2 getcap pcrs | grep sha |awk {'print $2'} | awk -F: {'print $1'}`; do

  hash=${alg_hashes[$alg]}

  if [ ! -z $digests ]; then
      digests="$digests,"
  fi

  digests="$digests$alg=$hash"

  tpm2 pcrextend 9:$alg=$hash

done;

#
# To keep things simple, compound specifications are just done with
# the supported sha1 algorithms to guarantee the command to succeed.
#
tpm2 pcrextend 8:$digests

# Extend a PCR for all supported banks like in the previous test but
# try extending two PCR in the same command.
tpm2 pcrextend 8:$digests 9:$digests

# Over-length hash should fail
if tpm2 pcrextend 8:$digests,sha1=${alg_hashes["sha256"]}; then
    echo "tpm2 pcrextend with over-length hash didn't fail!"
    exit 1
else
    true
fi

exit 0
