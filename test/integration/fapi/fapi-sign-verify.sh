
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

KEY_PATH=HS/SRK/myRSASign
DIGEST_FILE=$TEMP_DIR/digest.file
SIGNATURE_FILE=$TEMP_DIR/signature.file
PUBLIC_KEY_FILE=$TEMP_DIR/public_key.file
IMPORTED_KEY_NAME="importedPubKey"
PUB_KEY_DIR="ext"

tss2 provision
echo -n "01234567890123456789" > $DIGEST_FILE
tss2 createkey --path=$KEY_PATH --type="noDa, sign" --authValue=""

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
echo -n `cat $DIGEST_FILE` | tss2 sign --digest=- --keyPath=$KEY_PATH \
    --padding="RSA_PSS" --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
else
echo -n `cat $DIGEST_FILE` | tss2 sign --digest=- --keyPath=$KEY_PATH \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
fi

tss2 import --path=$IMPORTED_KEY_NAME --importData=$PUBLIC_KEY_FILE
tss2 verifysignature --keyPath=$PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest=$DIGEST_FILE --signature=$SIGNATURE_FILE

# Try without certificate
if [ "$CRYPTO_PROFILE" = "RSA" ]; then
tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE --force
else
tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE --force
fi

# Try without public key
if [ "$CRYPTO_PROFILE" = "RSA" ]; then
tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --force
else
tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --force
fi

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with missing keyPath
spawn tss2 sign --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with missing keyPath
spawn tss2 sign --digest=$DIGEST_FILE \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with missing digest
spawn tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with missing digest
spawn tss2 sign --keyPath=$KEY_PATH \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with missing signature
spawn tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with missing signature
spawn tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
    --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi


if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with multiple stdins with publicKey and with certificate
spawn tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --signature=- --publicKey=- --certificate -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with multiple stdins with publicKey and with certificate
spawn tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
    --signature=- --publicKey=- --certificate -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with multiple stdins without publicKey and with certificate
spawn tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=$DIGEST_FILE \
    --signature=- --certificate=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with multiple stdins without publicKey and with certificate
spawn tss2 sign --keyPath=$KEY_PATH --digest=$DIGEST_FILE \
    --signature=- --certificate=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi

if [ "$CRYPTO_PROFILE" = "RSA" ]; then
expect <<EOF
# Try with missing digest file
spawn tss2 sign --keyPath=$KEY_PATH --padding="RSA_PSS" --digest=abc \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
else
expect <<EOF
# Try with missing digest file
spawn tss2 sign --keyPath=$KEY_PATH --digest=abc \
    --signature=$SIGNATURE_FILE --publicKey=$PUBLIC_KEY_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF
fi

expect <<EOF
# Try with missing keyPath
spawn tss2 verifysignature \
    --digest=$DIGEST_FILE --signature=$SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing digest
spawn tss2 verifysignature --keyPath=$PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --signature=$SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2 verifysignature --keyPath=$PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest=$DIGEST_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins
spawn tss2 verifysignature --keyPath=$PUB_KEY_DIR/$IMPORTED_KEY_NAME \
    --digest=- --signature=-
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
