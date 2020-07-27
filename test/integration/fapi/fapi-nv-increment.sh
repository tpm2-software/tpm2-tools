
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

NV_PATH=/nv/Owner/myNVcounter
NV_COUNTER_READ_FILE=$TEMP_DIR/nv_counter_read_data.file
PCR_POLICY_DATA=$TEMP_DIR/pol_pcr16_0.json
POLICY_PCR=policy/pcr-policy

tss2 provision

tss2 import --path=$POLICY_PCR --importData=$PCR_POLICY_DATA

tss2 createnv --path=$NV_PATH --policyPath=$POLICY_PCR --type="counter, noDa" \
    --size=0 --authValue=""

tss2 nvincrement --nvPath=$NV_PATH

tss2 nvread --nvPath=$NV_PATH --data=$NV_COUNTER_READ_FILE --force

tss2 nvincrement --nvPath=$NV_PATH

tss2 nvread --nvPath=$NV_PATH --data=$NV_COUNTER_READ_FILE --force

expect <<EOF
# Try with missing nvPath
spawn tss2 nvincrement
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
