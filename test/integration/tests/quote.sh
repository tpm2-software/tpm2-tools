# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=0x000B
alg_create_key=hmac

alg_quote=0x0004
alg_quote1=0x000b

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_quote_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_quote_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_quote_key_name=name.load_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"
file_quote_key_ctx=ctx_load_out_"$alg_primary_obj"_"$alg_primary_key"-\
"$alg_create_obj"_"$alg_create_key"

Handle_ak_quote=0x81010016
Handle_ek_quote=0x81010017
Handle_ak_quote2=0x81010018
ak2_ctx=ak2.ctx

out=out.yaml
toss_out=junk.out

cleanup() {
    rm -f $file_primary_key_ctx $file_quote_key_pub $file_quote_key_priv \
    $file_quote_key_name $file_quote_key_ ak.pub2 ak.name_2 \
    $out $toss_out $ak2_ctx ek.ctx ak.ctx nonce.bin quote.bin quote.sig quote.pcr

    tpm2 evictcontrol -Q -Co -c $Handle_ek_quote 2>/dev/null || true
    tpm2 evictcontrol -Q -Co -c $Handle_ak_quote 2>/dev/null || true
    tpm2 evictcontrol -Q -Co -c $Handle_ak_quote2 2>/dev/null || true

    if [ "$1" != "no-shut-down" ]; then
       shut_down
    fi
}
trap cleanup EXIT

start_up

tpm2 getcap properties-fixed | tr -dc '[[:print:]]\r\n' > $out
maxdigest=$(yaml_get_kv $out "TPM2_PT_MAX_DIGEST" "raw")
if ! [[ "$maxdigest" =~ ^(0x)*[0-9]+$ ]] ; then
 echo "error: not a number, got: \"$maxdigest\"" >&2
 exit 1
fi

nonce=12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde12345abcde
nonce=${nonce:0:2*$maxdigest}

cleanup "no-shut-down"

tpm2 clear

tpm2 createprimary -Q -C e -g $alg_primary_obj -G $alg_primary_key \
-c $file_primary_key_ctx

tpm2 create -Q -g $alg_create_obj -G $alg_create_key -u $file_quote_key_pub \
-r $file_quote_key_priv -C $file_primary_key_ctx

tpm2 load -Q -C $file_primary_key_ctx -u $file_quote_key_pub \
-r $file_quote_key_priv -n $file_quote_key_name -c $file_quote_key_ctx

tpm2 quote -c $file_quote_key_ctx -l $alg_quote:16,17,18 -q $nonce \
-m $toss_out -s $toss_out -o $toss_out -g $alg_primary_obj > $out

yaml_verify $out

tpm2 quote -Q -c $file_quote_key_ctx \
-l $alg_quote:16,17,18+$alg_quote1:16,17,18 -q $nonce -m $toss_out \
-s $toss_out -o $toss_out -g $alg_primary_obj

#####handle testing
tpm2 evictcontrol -Q -C o -c $file_quote_key_ctx $Handle_ak_quote

tpm2 quote -Q -c $Handle_ak_quote -l $alg_quote:16,17,18 -q $nonce \
-m $toss_out -s $toss_out -o $toss_out -g $alg_primary_obj

tpm2 quote -Q -c $Handle_ak_quote -l $alg_quote:16,17,18+$alg_quote1:16,17,18 \
-q $nonce -m $toss_out -s $toss_out -o $toss_out -g $alg_primary_obj

#####AK
tpm2 createek -Q -c $Handle_ek_quote -G 0x01

tpm2 createak -Q -C $Handle_ek_quote -c $ak2_ctx -u ak.pub2 -n ak.name_2
tpm2 evictcontrol -Q -C o -c $ak2_ctx $Handle_ak_quote2

tpm2 quote -Q -c $Handle_ak_quote -l $alg_quote:16,17,18 -q $nonce \
-m $toss_out -s $toss_out -o $toss_out -g $alg_primary_obj

# ECC Test
tpm2 createek -G ecc -c ek.ctx
tpm2 createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa
tpm2 getrandom -o nonce.bin 20
tpm2 quote -c ak.ctx -l sha256:15,16,22 -q nonce.bin -m quote.bin -s quote.sig -o quote.pcr -g sha256

exit 0
