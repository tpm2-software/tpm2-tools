
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

PATH=${abs_builddir}/tools/fapi:$PATH

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

CERTIFICATES_OUTPUT_FILE=$TEMP_DIR/certificates_output.file

tss2 provision

expect <<EOF
# Try with missing certificates
spawn tss2 getplatformcertificates
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try normal command; should fail since no certificates present
spawn tss2 getplatformcertificates --certificates=$CERTIFICATES_OUTPUT_FILE \
    --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
