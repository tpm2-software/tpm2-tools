# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f session.ctx

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Start a session and test if session attributes can be modified
tpm2 startauthsession -S session.ctx

## Check default session attribute has continuesession set
DEFAULT_SESSION_ATTRIBUTE=continuesession
tpm2 sessionconfig session.ctx | grep $DEFAULT_SESSION_ATTRIBUTE

# Check if session can be marked for encryption
SESSION_ENCRYPT_SET=encrypt
tpm2 sessionconfig session.ctx --enable-encrypt
tpm2 sessionconfig session.ctx | grep $SESSION_ENCRYPT_SET

# Check if session can be marked for decryption
SESSION_DECRYPT_SET=decrypt
tpm2 sessionconfig session.ctx --enable-decrypt
tpm2 sessionconfig session.ctx | grep $SESSION_DECRYPT_SET

tpm2 flushcontext session.ctx

exit 0
