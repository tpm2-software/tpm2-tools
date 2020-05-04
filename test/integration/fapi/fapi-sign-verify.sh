#!/bin/bash

set -e
source helpers.sh

start_up

setup_fapi

function cleanup {
    tss2_delete --path /
    shut_down
}

trap cleanup EXIT

KEY_PATH=HS/SRK/myRSASign
DIGEST_FILE=$TEMP_DIR/digest.file
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
IMPORTED_KEY_NAME="importedPubKey"
PUB_KEY_DIR="ext"

tss2_provision
echo -n "01234567890123456789" > $DIGEST_FILE
tss2_createkey --path $KEY_PATH --type "noDa, sign" --authValue ""
echo -n `cat $DIGEST_FILE` | tss2_sign --digest=- --keyPath $KEY_PATH \
    --padding "RSA_PSS" --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE

tss2_import --path $IMPORTED_KEY_NAME --importData $PUBLIC_KEY_FILE
tss2_verifysignature --keyPath $PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest $DIGEST_FILE --signature $SIGNATURE_FILE


expect <<EOF
# Try with missing keyPath
spawn tss2_sign --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing digest
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" \
    --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --publicKey $PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins with publicKey and without certificate
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature=- --publicKey=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins with publicKey and with certificate
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature=- --publicKey=- --certificate=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins without publicKey and with certificate
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature=- --certificate=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing digest file
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest abc \
    --signature $SIGNATURE_FILE --publicKey $PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature file
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature abc --publicKey $PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing public key file
spawn tss2_sign --keyPath $KEY_PATH --padding "RSA_PSS" --digest $DIGEST_FILE \
    --signature $SIGNATURE_FILE --publicKey abc
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing keyPath
spawn tss2_verifysignature \
    --digest $DIGEST_FILE --signature $SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing digest
spawn tss2_verifysignature --keyPath $PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --signature $SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2_verifysignature --keyPath $PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest $DIGEST_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins
spawn tss2_verifysignature --keyPath $PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest=- --signature=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

tpm2_sign -Q -c "tss2:${KEY_PATH}" -g sha1 \
    -o "${DIGEST_FILE}.sig" "${DIGEST_FILE}"

exit 0
