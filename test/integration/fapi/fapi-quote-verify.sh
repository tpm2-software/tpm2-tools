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

KEY_PATH=HS/SRK/quotekey
NONCE_FILE=$TEMP_DIR/nonce.file
PUBLIC_QUOTE_KEY=$TEMP_DIR/public_quote.key
QUOTE_INFO=$TEMP_DIR/quote.info
SIGNATURE_FILE=$TEMP_DIR/signature.file
CERTIFICATE_FILE=$TEMP_DIR/certificate.file
PCR_LOG=$TEMP_DIR/pcr.log

printf "01234567890123456789" > $NONCE_FILE
printf "01234567890123456789" > $PCR_LOG

tss2_provision

tss2_createkey --path $KEY_PATH --type "noDa, restricted, sign" --authValue ""

tss2_quote --keyPath $KEY_PATH --pcrList "16" --qualifyingData $NONCE_FILE \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG \
    --certificate $CERTIFICATE_FILE --quoteInfo $QUOTE_INFO --force

tss2_exportkey --pathOfKeyToDuplicate $KEY_PATH --exportedData $PUBLIC_QUOTE_KEY --force
tss2_import --path "ext/myNewParent" --importData $PUBLIC_QUOTE_KEY

tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo $QUOTE_INFO \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG

expect <<EOF
# Try with missing keyPath
spawn tss2_quote --pcrList "16" \
    --qualifyingData $NONCE_FILE --signature $SIGNATURE_FILE \
    --pcrLog $PCR_LOG --certificate $CERTIFICATE_FILE \
    --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing pcrList
spawn tss2_quote \
    --qualifyingData $NONCE_FILE --signature $SIGNATURE_FILE \
    --pcrLog $PCR_LOG --certificate $CERTIFICATE_FILE \
    --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData $NONCE_FILE \
    --pcrLog $PCR_LOG --certificate $CERTIFICATE_FILE \
    --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing quoteInfo
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData $NONCE_FILE --signature $SIGNATURE_FILE \
    --pcrLog $PCR_LOG --certificate $CERTIFICATE_FILE \
    --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (1)
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData $NONCE_FILE --signature - \
    --pcrLog - --certificate $CERTIFICATE_FILE \
    --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (2)
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData $NONCE_FILE --signature $SIGNATURE_FILE \
    --pcrLog - --certificate - \
    --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (3)
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData $NONCE_FILE --signature $SIGNATURE_FILE \
    --pcrLog $PCR_LOG --certificate - \
    --quoteInfo - --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdout (4)
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" \
    --qualifyingData - --signature $SIGNATURE_FILE \
    --pcrLog - --certificate $CERTIFICATE_FILE \
    --quoteInfo - --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong pcrs
spawn tss2_quote --keyPath $KEY_PATH --pcrList abc --qualifyingData $NONCE_FILE \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG \
    --certificate $CERTIFICATE_FILE --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Fail quote
spawn tss2_quote --keyPath "/abc/def" --pcrList "16" --qualifyingData $NONCE_FILE \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG \
    --certificate $CERTIFICATE_FILE --quoteInfo $QUOTE_INFO --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with already existing directory
spawn tss2_quote --keyPath $KEY_PATH --pcrList "16" --qualifyingData $NONCE_FILE \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG \
    --certificate $CERTIFICATE_FILE --quoteInfo $QUOTE_INFO
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing publicKeyPath
spawn tss2_verifyquote \
    --qualifyingData $NONCE_FILE --quoteInfo $QUOTE_INFO \
    --signature $SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing quoteInfo
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE \
    --signature $SIGNATURE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing signature
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo $QUOTE_INFO
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (1)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData - --quoteInfo - \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (2)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo - \
    --signature - --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (3)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo $QUOTE_INFO \
    --signature - --pcrLog -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (4)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData - --quoteInfo $QUOTE_INFO \
    --signature $SIGNATURE_FILE --pcrLog -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (5)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo - \
    --signature - --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with multiple stdins (6)
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData - --quoteInfo - \
    --signature - --pcrLog -
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong qualifyingData file
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData abc --quoteInfo $QUOTE_INFO \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong signature file
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo $QUOTE_INFO \
    --signature abc --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong quoteInfo file
spawn tss2_verifyquote --publicKeyPath "ext/myNewParent" \
    --qualifyingData $NONCE_FILE --quoteInfo abc \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try failing tss2_verifyquote
spawn tss2_verifyquote --publicKeyPath "ext/abc" \
    --qualifyingData $NONCE_FILE --quoteInfo abc \
    --signature $SIGNATURE_FILE --pcrLog $PCR_LOG
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0