#!/bin/bash

commands=""

generate_bashcompletion() {

    k=`basename $1 .1.md`
    commands+="`echo $k |sed 's/tpm2_//g'` "

    shortop="$(grep -oP '(?<=\* \*\*\-)([a-zA-Z])' $1)"

    longoptwithshortop="$(grep -oP '(?<=\* \*\*\-[a-zA-Z]\*\*, \*\*\\--)([a-zA-Z\-]+)' $1)"

    longopwithoutshortop="$(grep -oP '(?<=\* \*\*\\\-\-)([a-zA-Z]{1,})' $1)"

    echo "# bash completion for $k                   -*- shell-script -*-"

    echo \
    "_$k()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \\
        sensitivedataorigin userwithauth adminwithpolicy noda \\
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \\
        policydelete writelocked writeall writedefine write_stclear \\
        globallock ppread ownerread authread policyread no_da orderly \\
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case \$prev in
            -h | --help)
                COMPREPLY=( \$(compgen -W \"man no-man\" -- \"\$cur\") )
                return;;
            -T | --tcti)
                COMPREPLY=( \$(compgen -W \"tabrmd mssim device none\" -- \"\$cur\") )
                return;;"
            shortop_ctr=0
            longoptwithshortop_ctr=0
            for shortop_index in $shortop;do
                for longoptwithshortop_index in $longoptwithshortop;do
                    if [ $shortop_ctr == $longoptwithshortop_ctr ];then
                        echo "            -$shortop_index | --$longoptwithshortop_index)"
                        if [[ "$longoptwithshortop_index" == *"auth"* ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${auth_methods[*]}\" -- \"\$cur\"))"
                        elif [[ "$shortop_index" == "g" ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${hash_methods[*]}\" -- \"\$cur\"))"
                        elif [[ "$shortop_index" == "G" ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${key_object[*]}\" -- \"\$cur\"))"
                        elif [[ "$longoptwithshortop_index" == *"attributes"* && "$k" != "tpm2_nvdefine" ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${key_attributes[*]}\" -- \"\$cur\"))"
                        elif [[ "$longoptwithshortop_index" == *"attributes"* && "$k" == "tpm2_nvdefine" ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${nv_attributes[*]}\" -- \"\$cur\"))"
                        elif [[ "$longoptwithshortop_index" == *"format"* && "$k" != "tpm2_verifysignature" ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${format_methods[*]}\" -- \"\$cur\"))"
                        elif [[ "$longoptwithshortop_index" == *"scheme"* ]];then
                            echo "                COMPREPLY=(\$(compgen -W \"\${signing_scheme[*]}\" -- \"\$cur\"))"
                        else
                            echo "                _filedir"
                        fi
                        echo "                return;;"
                    fi
                    longoptwithshortop_ctr=$((longoptwithshortop_ctr + 1))
                done
                shortop_ctr=$((shortop_ctr + 1))
                longoptwithshortop_ctr=0
            done
        echo -n "        esac

        COMPREPLY=(\$(compgen -W \"-h --help -v --version -V --verbose -Q --quiet \\
        -Z --enable-erata -T --tcti \\"
        echo ""
        echo -n "        "
        for j in $shortop; do echo -n "-$j "; done
        for j in $longoptwithshortop; do echo -n "--$j "; done
        for j in $longopwithoutshortop; do echo -n "--$j "; done
        echo "\" \\"
        echo -n "        "
        echo "-- \"\$cur\"))
    } &&
    complete -F _$k $k"
    echo "# ex: filetype=sh"
}

generate_bashcompletion_for_tpm2() {

    echo "_tpm2() {
            local cur prev words cword split
            _init_completion -s || return

            if ((cword == 1)); then
                COMPREPLY=(\$(compgen -W \"$commands\" -- \"\$cur\"))
            else
                tpmcommand=_tpm2_\$prev
                type \$tpmcommand &>/dev/null && \$tpmcommand
                if [ \$? == 1 ];then
                    COMPREPLY=(\$(compgen -W \${words[1]} -- \"\$cur\"))
                fi
            fi
            } &&
            complete -F _tpm2 tpm2"
}

current_dir="$(readlink -e "$(dirname "$0")")"
mandir="$(readlink -e "${current_dir}"/../../man)"
bashcompletiondir="$(readlink -e "${current_dir}"/../../dist/bash-completion/tpm2-tools)"

rm -f $bashcompletiondir/tpm2_completion.bash
for man_file in `ls $mandir/tpm2*.1.md`
do
    generate_bashcompletion $man_file >> $bashcompletiondir/tpm2_completion.bash
done

generate_bashcompletion_for_tpm2 >> $bashcompletiondir/tpm2_completion.bash
