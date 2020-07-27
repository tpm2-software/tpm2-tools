
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

NV_PATH="/nv/Owner/NvBitmap"
BITMAP="0x0102030405060608"

tss2 provision

tss2 createnv --path=$NV_PATH --type="noDa, bitfield" --size=0 --authValue=""

tss2 nvsetbits --nvPath=$NV_PATH --bitmap=$BITMAP

expect <<EOF
# Try with missing nvPath
spawn tss2 nvsetbits --bitmap=$BITMAP
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing bitmap
spawn tss2 nvsetbits --nvPath=$NV_PATH
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with wrong bitmap
spawn tss2 nvsetbits --nvPath=$NV_PATH --bitmap=abc
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
