# SPDX-License-Identifier: BSD-3-Clause

# shellcheck disable=SC1091
source helpers.sh

cleanup() {
    rm -f ek.ctx ak.ctx nonce.bin \
      quote.pcr quote.pcr.serialized quote.pcr.values \
      pcr.read, pcr.read.serialized, pcr.read.values
    [[ "$1" = "no-shut-down" ]] || shut_down
}

fail() {
  echo "$*" > /dev/stderr
  exit 1
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Generate artifacts necessary to make a quote
tpm2 createek -G ecc -c ek.ctx
tpm2 createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa
tpm2 getrandom -o nonce.bin 20

readonly pcrs_selection="sha1:15,16,22+sha256:15,16,22"
tpm2 quote -c ak.ctx -l $pcrs_selection -q nonce.bin -m /dev/null -s /dev/null \
  -g sha256 -o quote.pcr

tpm2 quote -c ak.ctx -l $pcrs_selection -q nonce.bin -m /dev/null -s /dev/null \
  -g sha256 -o quote.pcr.serialized -F serialized

tpm2 quote -c ak.ctx -l $pcrs_selection -q nonce.bin -m /dev/null -s /dev/null \
  -g sha256 -o quote.pcr.values -F values

tpm2 pcrread $pcrs_selection -o pcr.read
tpm2 pcrread $pcrs_selection -o pcr.read.serialized -F serialized
tpm2 pcrread $pcrs_selection -o pcr.read.values -F values

diff quote.pcr quote.pcr.serialized >& /dev/null ||
  fail "default pcrs output format of tpm2 quote is expected to be 'serialized'"

diff quote.pcr.serialized quote.pcr.values >& /dev/null &&
  fail "pcrs output in 'serialized' format must be different from that" \
    "in 'values' format for tpm2 quote"

diff quote.pcr.serialized pcr.read.serialized >& /dev/null ||
  fail "pcrs output in 'serialized' format of tpm2 quote and tpm2 pcrread" \
    "must be identical"

diff quote.pcr.values pcr.read.values >& /dev/null ||
  fail "pcrs output in 'values' format of tpm2 quote and tpm2 pcrread" \
    "must be identical"

diff pcr.read pcr.read.values >& /dev/null ||
  fail "default pcrs output format of tpm2 pcrread is expected to be 'values'"

exit 0
