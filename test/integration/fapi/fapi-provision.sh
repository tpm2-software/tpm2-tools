
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    # Since clean up should already been done during normal run of the test, a
    # failure is expected here. Therefore, we need to pass a successful
    # execution in any case
    tss2 delete --path=/ || true
    shut_down
}

trap cleanup EXIT

tss2 provision

PROFILE_NAME=$( tss2 list --searchPath=/ --pathList=- | cut -d "/" -f2 )

tss2 delete --path=/

expect <<EOF
# Test if still objects in path
spawn tss2 list --searchPath=/
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    send_user "Still objects in path\n"
    exit 1
}
EOF

if [ -s $PROFILE_NAME ];then
    echo "Directory still existing"
    exit 99
fi

exit 0
