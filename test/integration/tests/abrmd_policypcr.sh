# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f pcr.bin pcr.policy1 pcr.policy2 pcr.policy3

    tpm2 flushcontext session.ctx 2>/dev/null || true

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

tpm2 clear

tpm2 pcrread sha1:0,1,2+sha256:0,1,2 -o pcr.bin

# Policy PCR values calculated by specifying the expected pcr data in a file
tpm2 startauthsession -S session.ctx

tpm2 policypcr -Q -l sha1:0,1,2+sha256:0,1,2 -S session.ctx \
-L pcr.policy1 -f pcr.bin

tpm2 flushcontext session.ctx

# Policy PCR values calculated by reading pcr data from the TPM
tpm2 startauthsession -S session.ctx

tpm2 policypcr -Q -l sha1:0,1,2+sha256:0,1,2 -S session.ctx \
-L pcr.policy2

tpm2 flushcontext session.ctx

# Policy PCR values calculated by specifying digest of all PCRs directly
tpm2 startauthsession -S session.ctx

PCRDIGEST=`openssl dgst -sha256 -binary pcr.bin | xxd -p -c 32`
tpm2 policypcr -Q -l sha1:0,1,2+sha256:0,1,2 -S session.ctx \
-L pcr.policy3 $PCRDIGEST

tpm2 flushcontext session.ctx

# Check if policy pcr values match for all possible methods to specify PCR
diff pcr.policy1 pcr.policy2
diff pcr.policy2 pcr.policy3

exit 0
