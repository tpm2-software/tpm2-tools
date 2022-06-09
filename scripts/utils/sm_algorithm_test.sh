# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
	rm -f prim.ctx key.ctx key.pub key.priv sig sig.plain input_data

    if [ "$1" != "no-shut-down" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "12345678" > input_data

tpm2 createprimary -Q -C e -g sm3_256 -G "ecc_sm2:null:sm4128cfb" -c prim.ctx

tpm2 create -Q -g sm3_256 -G "ecc_sm2:sm2-sm3_256:null" -u key.pub -r key.priv -C prim.ctx

tpm2 load -Q -C prim.ctx -u key.pub -r key.priv -c key.ctx

tpm2 sign -c key.ctx -g sm3_256 -o sig -s sm2 input_data
tpm2 verifysignature -c key.ctx -g sm3_256 -s sig -m input_data

tpm2 sign -c key.ctx -g sm3_256 -o sig.plain -s sm2 -f plain input_data
tpm2 verifysignature -c key.ctx -g sm3_256 -s sig.plain -m input_data --scheme sm2

