# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=sha256
alg_create_key=hmac

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_loadexternal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_name=name.loadexternal_"$alg_primary_obj"_\
"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_ctx=ctx_loadexternal_out_"$alg_primary_obj"_\
"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_output=loadexternal_"$file_loadexternal_key_ctx"

tss_privkey=tss_pk
tss_prim=prim

Handle_parent=0x81010019

cleanup() {
  rm -f $file_primary_key_ctx $file_loadexternal_key_pub \
  $file_loadexternal_key_priv $file_loadexternal_key_name \
  $file_loadexternal_key_ctx $file_loadexternal_output private.pem public.pem \
  plain.txt plain.rsa.dec key.ctx public.ecc.pem private.ecc.pem \
  data.in.digest data.out.signed ticket.out name.bin stdout.yaml passfile \
  private.pem key.priv key.pub

  if [ $(ina "$@" "keep_handle") -ne 0 ]; then
    tpm2 evictcontrol -Q -Co -c $Handle_parent 2>/dev/null || true
  fi

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2 clear

run_tss_test() {

    tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
    -c $file_primary_key_ctx

    tpm2 create -Q -g $alg_create_obj -G $alg_create_key \
    -u $file_loadexternal_key_pub -r $file_loadexternal_key_priv \
    -C $file_primary_key_ctx

    tpm2 loadexternal -Q -C n -u $file_loadexternal_key_pub \
    -c $file_loadexternal_key_ctx

    tpm2 evictcontrol -Q -C o -c $file_primary_key_ctx $Handle_parent

    # Test with Handle
    cleanup "keep_handle" "no-shut-down"

    tpm2 create -Q -C $Handle_parent -g $alg_create_obj -G $alg_create_key \
    -u $file_loadexternal_key_pub  -r  $file_loadexternal_key_priv

    tpm2 loadexternal -Q -C n -u $file_loadexternal_key_pub \
    -c $file_loadexternal_key_ctx

    # Test with default hierarchy (and handle)
    cleanup "keep_handle" "no-shut-down"

    tpm2 create -Q -C $Handle_parent -g $alg_create_obj -G $alg_create_key \
    -u $file_loadexternal_key_pub -r $file_loadexternal_key_priv

    tpm2 loadexternal -Q -u $file_loadexternal_key_pub \
    -c $file_loadexternal_key_ctx

    cleanup "no-shut-down"
}

# Test loading an OSSL generated private key with a password
run_rsa_test() {

    openssl genrsa -out private.pem $1
    openssl rsa -in private.pem -out public.pem -outform PEM -pubout

    echo "hello world" > plain.txt
    openssl pkeyutl -encrypt -inkey public.pem -pubin -in plain.txt \
    -out plain.rsa.enc

    tpm2 loadexternal -G rsa -C n -p foo -r private.pem -c key.ctx

    tpm2 rsadecrypt -c key.ctx -p foo -o plain.rsa.dec plain.rsa.enc

    diff plain.txt plain.rsa.dec

    # try encrypting with the public key and decrypting with the private
    tpm2 loadexternal -G rsa -C n -p foo -u public.pem -c key.ctx

    tpm2 rsaencrypt -c key.ctx plain.txt -o plain.rsa.enc

    openssl pkeyutl -decrypt -inkey private.pem -in plain.rsa.enc \
    -out plain.rsa.dec

    diff plain.txt plain.rsa.dec

    cleanup "no-shut-down"
}

#
# Verify loading an external AES key.
#
# Paramter 1: The AES keysize to create in bytes.
#
# Notes: Also tests that name output and YAML output are valid.
#
run_aes_test() {

    dd if=/dev/urandom of=sym.key bs=1 count=$(($1 / 8)) 2>/dev/null

    tpm2 loadexternal -G aes -r sym.key -n name.bin -c key.ctx > stdout.yaml

    local name1=$(yaml_get_kv "stdout.yaml" "name")
    local name2="$(xxd -c 256 -p name.bin)"

    test "$name1" == "$name2"

    echo "plaintext" > "plain.txt"

    if is_cmd_supported "EncryptDecrypt"; then
        tpm2 encryptdecrypt -c key.ctx -o plain.enc plain.txt

        openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -c 256 -p sym.key` \
        -iv 0 -aes-$1-cfb

        diff plain.txt plain.dec.ssl
    else
        tpm2 readpublic -c key.ctx >out.pub
        alg=$(yaml_get_kv out.pub "sym-alg" "value")
        len=$(yaml_get_kv out.pub "sym-keybits")
        if [ "$alg$len" != "aes$1" ]; then
            echo "Algorithm parsed from tpm2 readpublic is '$alg$len' but \
                  should be 'aes$1'"
            exit 1
        fi
        rm out.pub
    fi

    cleanup "no-shut-down"
}

run_ecc_test() {
    #
    # Test loading an OSSL PEM format ECC key, and verifying a signature
    # external to the TPM
    #

    #
    # Generate a NIST P256 Private and Public ECC pem file
    #
    openssl ecparam -name $1 -genkey -noout -out private.ecc.pem
    openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

    # Generate a hash to sign
    echo "data to sign" > data.in.raw
    shasum -a 256 data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > \
    data.in.digest

    # Load the private key for signing
    tpm2 loadexternal -Q -G ecc -r private.ecc.pem -c key.ctx

    # Sign in the TPM and verify with OSSL
    tpm2 sign -Q -c key.ctx -g sha256 -d -f plain -o data.out.signed \
    data.in.digest
    openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature \
    data.out.signed data.in.raw

    # Sign with openssl and verify with TPM but only with the public portion of
    # an object loaded
    tpm2 loadexternal -Q -G ecc -u public.ecc.pem -c key.ctx
    openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw
    tpm2 verifysignature -Q -c key.ctx -g sha256 -m data.in.raw -f ecdsa \
    -s data.out.signed

    cleanup "no-shut-down"
}

run_rsa_passin_test() {

    openssl genrsa -aes128 -passout "pass:mypassword" -out "private.pem" 1024

    if [ "$2" != "stdin" ]; then
        cmd="tpm2 loadexternal -Q -G rsa -r $1 -c key.ctx --passin $2"
    else
        cmd="tpm2 loadexternal -Q -G rsa -r $1 -c key.ctx --passin $2 < $3"
    fi;

    eval $cmd

    cleanup "no-shut-down"
}

run_tss_test

for len in "1024 2048"; do
    if is_alg_supported "rsa$len"; then
        run_rsa_test $len
    fi
done

for len in "128 256"; do
    if is_alg_supported "aes$len"; then
        run_aes_test $len
    fi
done

if is_alg_supported "ecc256"; then
    run_ecc_test prime256v1
fi

#
# Test loadexternal passin option
#
run_rsa_passin_test "private.pem" "pass:mypassword"

export envvar="mypassword"
run_rsa_passin_test "private.pem" "env:envvar"

echo -n "mypassword" > "passfile"
run_rsa_passin_test "private.pem" "file:passfile"

echo -n "mypassword" > "passfile"
exec 42<> passfile
run_rsa_passin_test "private.pem" "fd:42"

echo -n "mypassword" > "passfile"
run_rsa_passin_test "private.pem" "stdin" "passfile"

#
# Test cpHash output
#
tpm2 createprimary -C o -c prim.ctx -Q
tpm2 create -C prim.ctx -u key.pub -r key.priv -Q
tpm2 loadexternal -C n -u key.pub -c key.ctx --cphash cp.hash
TPM2_CC_Loadexternal="00000167"
External_priv_dat="0000"
External_pub_dat=$(xxd -p key.pub | tr -d '\n')
Hierarchy="40000007"
echo -ne $TPM2_CC_Loadexternal$External_priv_dat$External_pub_dat$Hierarchy | \
    xxd -r -p | openssl dgst -sha256 -binary -out test.bin
cmp cp.hash test.bin 2
if [ $? != 0 ]; then
	echo "cpHash doesn't match calculated value"
    exit 1
fi

#
# TSS Privkey
#
tpm2 createprimary -G rsa -C o \
-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
-c $tss_prim.ctx

tpm2 create -C $tss_prim.ctx -u $tss_privkey.pub -r $tss_privkey.priv

tpm2 encodeobject -C $tss_prim.ctx -u $tss_privkey.pub -r $tss_privkey.priv -o $tss_privkey.pem

tpm2 loadexternal -r $tss_privkey.pem -c $tss_privkey.ctx

#
# Test Policy from A Hash Input
#
openssl genrsa -out "private.pem" 1024

expected_dgst="fdb1c1e5ba81e95f2db8db6ed7627e9b01658e80df7f33220bd3638f98ad2d5f"
tpm2 loadexternal -Q -G rsa -r private.pem -c key.ctx -L "$expected_digest"
got_digest="$(tpm2 readpublic -c key.ctx | grep "authorization policy" | cut -d ' ' -f3-)"
test "$expected_digest" == "$got_digest"
exit 0
