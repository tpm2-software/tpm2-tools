#!/bin/sh
# bash completion for tmp2-tools                                 -*- shell-script -*-


_tpm2_tools()
{



    local cur prev words cword
    _init_completion || return
    local common_options=(-h --help -v --version -V --verbose -Q --quiet -Z --enable-errata -T --tcti=)
    local aux1=$( ${COMP_WORDS[0]} --help=no-man 2>/dev/null )
    local aux2=$( echo "${aux1}" | tr "[]|" " " | awk '{if(NR>2)print}' | tr " " "\n")
    suggestions=("${aux2[@]}" "${common_options[@]}") #generate all the opts for the tool
    local halg=(0x4 sha1 0xB sha256 0xC sha384 0xD sha512 0x12 sm3_256)
    local public_object_alg=(0x1 rsa 0x8 keyedhash 0x23 ecc 0x25 symcipher)
    local signing_alg=(0x5 hmac 0x14 rsassa 0x16 rsapss 0x18 ecdsa 0x1A ecdaa 0x1B sm2 0x1C ecschnorr)
    local signing_schemes=(0x5 hmac 0x14 rsassa 0x15 rsaes 0x16 rsapss 0x17 oeap)
    local tcti_opts=(device: mssim: abrmd:)


    case $prev in
      -g)
          if [[ "${COMP_WORDS[0]}" != "tpm2_createek" && "${COMP_WORDS[0]}" != "tpm2_getmanufec" && "${COMP_WORDS[0]}" != "tpm2_createak" ]]; then
            suggestions=( $( compgen -W "${halg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          else
            suggestions=( $( compgen -W "${public_object_alg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          fi
          return;;
      -G)
          if [[  "${COMP_WORDS[0]}" != "tpm2_import"  && "${COMP_WORDS[0]}" != "tpm2_quote" ]]; then
            suggestions=( $( compgen -W "${public_object_alg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          else
            suggestions=( $( compgen -W "${halg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          fi
          return;;
      -D)
          if [[  "${COMP_WORDS[0]}" == "tpm2_createak" ]]; then
            suggestions=( $( compgen -W "${halg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          else
            _filedir
          fi
          return;;

      -h | --help)
          suggestions=( $( compgen -W 'man no-man' -- "$cur" ) )
          COMPREPLY=("${suggestions[@]}")
          return;;
      -T)
          suggestions=( $( compgen -W "${tcti_opts[*]}" -- "$cur" ) )
          COMPREPLY=("${suggestions[@]}")
          [[ $COMPREPLY == *: ]] && compopt -o nospace
          return;;
      -f)
          if [[ "${COMP_WORDS[0]}" == "tpm2_activatecredential" || "${COMP_WORDS[0]}" == "print" ]]; then
            _filedir
          elif [[ "${COMP_WORDS[0]}" == "tpm2_quote" || "${COMP_WORDS[0]}" == "tpm2_sign" ]]; then
            suggestions=( $( compgen -W 'plain tss' -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          elif [[ "${COMP_WORDS[0]}" == "tpm2_verifysignature" ]]; then
            suggestions=( $( compgen -W "${signing_schemes[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          fi
          return;;
      -s)
          if [[ "${COMP_WORDS[0]}" == "tpm2_createak" ]]; then
            suggestions=( $( compgen -W "${signing_alg[*]}" -- "$cur" ) )
            COMPREPLY=("${suggestions[@]}")
          elif [["${COMP_WORDS[0]}" == "tpm2_verifysignature" ]];then
            _filedir
          fi
          return;;
      -u | -r)
          if [[ "${COMP_WORDS[0]}" == "tpm2_load" || "${COMP_WORDS[0]}" == "tpm2_loadexternal" ]]; then
            _filedir
          fi
          return;;
      -I)
          if [[ "${COMP_WORDS[0]}" != "tpm2_nvdefine" ]]; then
            _filedir
          fi
          return;;
      -k | -K)
          if [[ "${COMP_WORDS[0]}" == "tpm2_import" ]]; then
            _filedir
          fi
          return;;
      -i)
          if [[ "${COMP_WORDS[0]}" == "tpm2_send" ]]; then
            _filedir
          fi
          return;;
      -m)
          if [[ "${COMP_WORDS[0]}" != "tpm2_quote" ]]; then
            _filedir
          fi
          return;;
      -t)
          if [[ "${COMP_WORDS[0]}" == "tpm2_sign" ]]; then
            _filedir
          fi
          return;;
      -L)
          if [[ "${COMP_WORDS[0]}" == "tpm2_create" || "${COMP_WORDS[0]}" == "tpm2_createprimary" || "${COMP_WORDS[0]}" == "tpm2_nvdefine" ]]; then
            _filedir
          fi
          return;;
      -e)
          if [[ "${COMP_WORDS[0]}" == "tpm2_makecredential" ]]; then
            _filedir
          fi
          return;;

      -S | F | C)
         _filedir
         return;;

    esac

    if [[ "$cur" == -* ]]; then #start completion
        _exclude_completed_opts
        COMPREPLY=( $( compgen -W '$( echo ${suggestions[@]//<value>} )' -- "$cur" ) )
        [[ $COMPREPLY == *= ]] && compopt -o nospace
        return
    fi

} &&
  #to obtain the installation path of the tools, it is necessary to know just one of them, tpm2_import was choose ramdomly
  #and then assign the completion function to all the tools
  tools_for_completions=( $(find $( dirname $(which tpm2_import) ) -type f -printf '%f\n' | grep 'tpm2_') )
  for i in "${tools_for_completions[@]}"
  do
   complete -F _tpm2_tools $i
  done

#function used to exlude the already completed options from the suggested completions
_exclude_completed_opts() {
  local len=$(($COMP_CWORD - 1))
  local i
  for ((i=1 ; i<=len; i++)) ; do
      local aux="${COMP_WORDS[$i]}"
      if [[ $aux == -* ]] ; then
          (( i<len )) && [[ ${COMP_WORDS[$(( i + 1))]} == '=' ]] && aux="$aux="
          suggestions=( "${suggestions[@]/$aux}" )
      fi
  done
}
