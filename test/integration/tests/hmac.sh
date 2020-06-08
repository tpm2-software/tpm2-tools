# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_key=hmac

handle_hmac_key=0x81010013

file_primary_key_ctx=primary.ctx
file_hmac_key_pub=key.pub
file_hmac_key_priv=key.priv
file_hmac_key_name=name.dat
file_hmac_key_ctx=key.ctx
file_hmac_output=hmac.out
file_hmac_key_handle=key.handle

file_input_data=secret.data

cleanup() {
  rm -f $file_primary_key_ctx $file_hmac_key_pub $file_hmac_key_priv \
        $file_hmac_key_name $file_hmac_output ticket.out

  if [ $(ina "$@" "keep-context") -ne 0 ]; then
    rm -f $file_hmac_key_ctx $file_input_data
    # attempt to evict the hmac persistent key handle, but don't cause failures
    # if this fails as it may not be loaded.
    tpm2 evictcontrol -c $file_hmac_key_handle 2>/dev/null || true
  fi

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > $file_input_data

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -Q -G $alg_create_key -u $file_hmac_key_pub -r $file_hmac_key_priv \
-C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_hmac_key_pub \
-r $file_hmac_key_priv -n $file_hmac_key_name -c $file_hmac_key_ctx

# verify that persistent object can be used via a serialized handle
tpm2 evictcontrol -C o -c $file_hmac_key_ctx -o $file_hmac_key_handle

cat $file_input_data | tpm2 hmac -Q -c $file_hmac_key_handle \
-o $file_hmac_output

cleanup "keep-context" "no-shut-down"

# Test large file, ie sequence hmac'ing.
dd if=/dev/urandom of=$file_input_data bs=2093 count=1 2>/dev/null
tpm2 hmac -Q -c $file_hmac_key_ctx -o $file_hmac_output $file_input_data

####handle test
rm -f $file_hmac_output

cleanup "no-shut-down"

# Test stdin
echo "12345678" > $file_input_data

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -Q -G $alg_create_key -u $file_hmac_key_pub -r $file_hmac_key_priv \
-C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_hmac_key_pub \
-r $file_hmac_key_priv -n $file_hmac_key_name -c $file_hmac_key_ctx

cat $file_input_data | tpm2 hmac -Q -c $file_hmac_key_ctx -o $file_hmac_output

# test ticket option
cat $file_input_data | tpm2 hmac -Q -c $file_hmac_key_ctx -o $file_hmac_output \
-t ticket.out
test -f ticket.out

# test no output file
cat $file_input_data | tpm2 hmac -c $file_hmac_key_ctx 1>/dev/null

# verify that silent is indeed silent
stdout=`cat $file_input_data | tpm2 hmac -Q -c $file_hmac_key_ctx`
if [ -n "$stdout" ]; then
    echo "Expected no output when run in quiet mode, got\"$stdout\""
    exit 1
fi

exit 0
