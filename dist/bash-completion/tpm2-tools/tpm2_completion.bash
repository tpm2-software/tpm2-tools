# bash completion for tpm2_activatecredential                   -*- shell-script -*-
_tpm2_activatecredential()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --credentialedkey-context)
                _filedir
                return;;
            -C | --credentialkey-context)
                _filedir
                return;;
            -p | --credentialedkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -P | --credentialkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -i | --credential-blob)
                _filedir
                return;;
            -o | --certinfo-data)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -C -p -P -i -o --credentialedkey-context --credentialkey-context --credentialedkey-auth --credentialkey-auth --credential-blob --certinfo-data --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_activatecredential tpm2_activatecredential
# ex: filetype=sh
# bash completion for tpm2_certify                   -*- shell-script -*-
_tpm2_certify()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --certifiedkey-context)
                _filedir
                return;;
            -C | --signingkey-context)
                _filedir
                return;;
            -p | --certifiedkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -P | --signingkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -o | --attestation)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -C -p -g -P -o -s -f --certifiedkey-context --signingkey-context --certifiedkey-auth --hash-algorithm --signingkey-auth --attestation --signature --format --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_certify tpm2_certify
# ex: filetype=sh
# bash completion for tpm2_certifyX509certutil                   -*- shell-script -*-
_tpm2_certifyX509certutil()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --outcert)
                _filedir
                return;;
            -d | --days)
                _filedir
                return;;
            -i | --issuer)
                _filedir
                return;;
            -s | --subject)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -o -d -i -s --outcert --days --issuer --subject " \
        -- "$cur"))
    } &&
    complete -F _tpm2_certifyX509certutil tpm2_certifyX509certutil
# ex: filetype=sh
# bash completion for tpm2_certifycreation                   -*- shell-script -*-
_tpm2_certifycreation()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --signingkey-context)
                _filedir
                return;;
            -P | --signingkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --certifiedkey-context)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -d | --creation-hash)
                _filedir
                return;;
            -t | --ticket)
                _filedir
                return;;
            -o | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -q | --qualification)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -c -g -s -d -t -o -f -q --signingkey-context --signingkey-auth --certifiedkey-context --hash-algorithm --scheme --creation-hash --ticket --signature --format --qualification --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_certifycreation tpm2_certifycreation
# ex: filetype=sh
# bash completion for tpm2_changeauth                   -*- shell-script -*-
_tpm2_changeauth()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --object-context)
                _filedir
                return;;
            -p | --object-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -C | --parent-context)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -C -r --object-context --object-auth --parent-context --private --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_changeauth tpm2_changeauth
# ex: filetype=sh
# bash completion for tpm2_changeeps                   -*- shell-script -*-
_tpm2_changeeps()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -p --auth " \
        -- "$cur"))
    } &&
    complete -F _tpm2_changeeps tpm2_changeeps
# ex: filetype=sh
# bash completion for tpm2_changepps                   -*- shell-script -*-
_tpm2_changepps()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -p --auth " \
        -- "$cur"))
    } &&
    complete -F _tpm2_changepps tpm2_changepps
# ex: filetype=sh
# bash completion for tpm2_checkquote                   -*- shell-script -*-
_tpm2_checkquote()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -u | --public)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -m | --message)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -f | --pcr)
                _filedir
                return;;
            -l | --pcr-list)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
            -F | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -u -g -m -s -f -l -q -F --public --hash-algorithm --message --signature --pcr --pcr-list --qualification --format " \
        -- "$cur"))
    } &&
    complete -F _tpm2_checkquote tpm2_checkquote
# ex: filetype=sh
# bash completion for tpm2_clear                   -*- shell-script -*-
_tpm2_clear()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --auth-hierarchy)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c --auth-hierarchy --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_clear tpm2_clear
# ex: filetype=sh
# bash completion for tpm2_clearcontrol                   -*- shell-script -*-
_tpm2_clearcontrol()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P --hierarchy --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_clearcontrol tpm2_clearcontrol
# ex: filetype=sh
# bash completion for tpm2_clockrateadjust                   -*- shell-script -*-
_tpm2_clockrateadjust()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --hierarchy)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p --hierarchy --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_clockrateadjust tpm2_clockrateadjust
# ex: filetype=sh
# bash completion for tpm2_commit                   -*- shell-script -*-
_tpm2_commit()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -u | --public)
                _filedir
                return;;
            -t | --counter)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --context)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -u -t -p -c --public --counter --auth --context --basepoint --eccpoint --eccpoint --eccpoint " \
        -- "$cur"))
    } &&
    complete -F _tpm2_commit tpm2_commit
# ex: filetype=sh
# bash completion for tpm2_create                   -*- shell-script -*-
_tpm2_create()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --parent-context)
                _filedir
                return;;
            -P | --parent-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --key-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -a | --attributes)
                COMPREPLY=($(compgen -W "${key_attributes[*]}" -- "$cur"))
                return;;
            -i | --sealing-input)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
            -u | --public)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -c | --key-context)
                _filedir
                return;;
            -t | --creation-ticket)
                _filedir
                return;;
            -d | --creation-hash)
                _filedir
                return;;
            -q | --outside-info)
                _filedir
                return;;
            -l | --pcr-list)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -p -g -G -a -i -L -u -r -c -t -d -q -l --parent-context --parent-auth --key-auth --hash-algorithm --key-algorithm --attributes --sealing-input --policy --public --private --key-context --creation-ticket --creation-hash --outside-info --pcr-list --creation --template --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_create tpm2_create
# ex: filetype=sh
# bash completion for tpm2_createak                   -*- shell-script -*-
_tpm2_createak()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --eh-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --ak-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -C | --ek-context)
                _filedir
                return;;
            -c | --ak-context)
                _filedir
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --signing-algorithm)
                _filedir
                return;;
            -u | --public)
                _filedir
                return;;
            -n | --ak-name)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -q | --ak-qualified-name)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P -p -C -c -G -g -s -u -n -r -q --eh-auth --ak-auth --ek-context --ak-context --key-algorithm --hash-algorithm --signing-algorithm --public --ak-name --private --ak-qualified-name " \
        -- "$cur"))
    } &&
    complete -F _tpm2_createak tpm2_createak
# ex: filetype=sh
# bash completion for tpm2_createek                   -*- shell-script -*-
_tpm2_createek()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --eh-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -w | --owner-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --ek-context)
                _filedir
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -u | --public)
                _filedir
                return;;
            -t | --template)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P -w -c -G -u -t --eh-auth --owner-auth --ek-context --key-algorithm --public --template " \
        -- "$cur"))
    } &&
    complete -F _tpm2_createek tpm2_createek
# ex: filetype=sh
# bash completion for tpm2_createpolicy                   -*- shell-script -*-
_tpm2_createpolicy()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -g | --policy-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -l | --pcr-list)
                _filedir
                return;;
            -f | --pcr)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -g -l -f --policy --policy-algorithm --pcr-list --pcr --policy --policy " \
        -- "$cur"))
    } &&
    complete -F _tpm2_createpolicy tpm2_createpolicy
# ex: filetype=sh
# bash completion for tpm2_createprimary                   -*- shell-script -*-
_tpm2_createprimary()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --key-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
            -a | --attributes)
                COMPREPLY=($(compgen -W "${key_attributes[*]}" -- "$cur"))
                return;;
            -u | --unique-data)
                _filedir
                return;;
            -t | --creation-ticket)
                _filedir
                return;;
            -d | --creation-hash)
                _filedir
                return;;
            -q | --outside-info)
                _filedir
                return;;
            -l | --pcr-list)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -p -g -G -c -L -a -u -t -d -q -l --hierarchy --hierarchy-auth --key-auth --hash-algorithm --key-algorithm --key-context --policy --attributes --unique-data --creation-ticket --creation-hash --outside-info --pcr-list --creation --template --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_createprimary tpm2_createprimary
# ex: filetype=sh
# bash completion for tpm2_dictionarylockout                   -*- shell-script -*-
_tpm2_dictionarylockout()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -s | --setup-parameters)
                _filedir
                return;;
            -c | --clear-lockout)
                _filedir
                return;;
            -l | --lockout-recovery-time)
                _filedir
                return;;
            -t | --recovery-time)
                _filedir
                return;;
            -n | --max-tries)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -s -c -l -t -n -p --setup-parameters --clear-lockout --lockout-recovery-time --recovery-time --max-tries --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_dictionarylockout tpm2_dictionarylockout
# ex: filetype=sh
# bash completion for tpm2_duplicate                   -*- shell-script -*-
_tpm2_duplicate()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -G | --wrapper-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -i | --encryptionkey-in)
                _filedir
                return;;
            -o | --encryptionkey-out)
                _filedir
                return;;
            -C | --parent-context)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -s | --encrypted-seed)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -G -i -o -C -r -s -p -c --wrapper-algorithm --encryptionkey-in --encryptionkey-out --parent-context --private --encrypted-seed --auth --key-context --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_duplicate tpm2_duplicate
# ex: filetype=sh
# bash completion for tpm2_ecdhkeygen                   -*- shell-script -*-
_tpm2_ecdhkeygen()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --context)
                _filedir
                return;;
            -u | --public)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -u -o --context --public --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_ecdhkeygen tpm2_ecdhkeygen
# ex: filetype=sh
# bash completion for tpm2_ecdhzgen                   -*- shell-script -*-
_tpm2_ecdhzgen()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --key-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -u | --public)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -u -o --key-context --key-auth --public --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_ecdhzgen tpm2_ecdhzgen
# ex: filetype=sh
# bash completion for tpm2_ecephemeral                   -*- shell-script -*-
_tpm2_ecephemeral()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -u | --public)
                _filedir
                return;;
            -t | --counter)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -u -t --public --counter " \
        -- "$cur"))
    } &&
    complete -F _tpm2_ecephemeral tpm2_ecephemeral
# ex: filetype=sh
# bash completion for tpm2_encryptdecrypt                   -*- shell-script -*-
_tpm2_encryptdecrypt()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -d | --decrypt)
                _filedir
                return;;
            -e | --pad)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
            -G | --mode)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -t | --iv)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -d -e -o -G -t --key-context --auth --decrypt --pad --output --mode --iv --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_encryptdecrypt tpm2_encryptdecrypt
# ex: filetype=sh
# bash completion for tpm2_eventlog                   -*- shell-script -*-
_tpm2_eventlog()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_eventlog tpm2_eventlog
# ex: filetype=sh
# bash completion for tpm2_evictcontrol                   -*- shell-script -*-
_tpm2_evictcontrol()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -c | --object-context)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -c -P -o --hierarchy --object-context --auth --output --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_evictcontrol tpm2_evictcontrol
# ex: filetype=sh
# bash completion for tpm2_flushcontext                   -*- shell-script -*-
_tpm2_flushcontext()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -t | --transient-object)
                _filedir
                return;;
            -l | --loaded-session)
                _filedir
                return;;
            -s | --saved-session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -t -l -s --transient-object --loaded-session --saved-session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_flushcontext tpm2_flushcontext
# ex: filetype=sh
# bash completion for tpm2_getcap                   -*- shell-script -*-
_tpm2_getcap()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -l | --list)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -l --list " \
        -- "$cur"))
    } &&
    complete -F _tpm2_getcap tpm2_getcap
# ex: filetype=sh
# bash completion for tpm2_getcommandauditdigest                   -*- shell-script -*-
_tpm2_getcommandauditdigest()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -q | --qualification)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -m | --message)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P -c -p -q -s -m -f -g --hierarchy-auth --key-context --auth --qualification --signature --message --format --hash-algorithm " \
        -- "$cur"))
    } &&
    complete -F _tpm2_getcommandauditdigest tpm2_getcommandauditdigest
# ex: filetype=sh
# bash completion for tpm2_geteccparameters                   -*- shell-script -*-
_tpm2_geteccparameters()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -o --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_geteccparameters tpm2_geteccparameters
# ex: filetype=sh
# bash completion for tpm2_getekcertificate                   -*- shell-script -*-
_tpm2_getekcertificate()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --ek-certificate)
                _filedir
                return;;
            -X | --allow-unverified)
                _filedir
                return;;
            -u | --ek-public)
                _filedir
                return;;
            -x | --offline)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -o -X -u -x --ek-certificate --allow-unverified --ek-public --offline " \
        -- "$cur"))
    } &&
    complete -F _tpm2_getekcertificate tpm2_getekcertificate
# ex: filetype=sh
# bash completion for tpm2_getrandom                   -*- shell-script -*-
_tpm2_getrandom()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --output)
                _filedir
                return;;
            -f | --force)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -o -f -S --output --force --session --hex --cphash --rphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_getrandom tpm2_getrandom
# ex: filetype=sh
# bash completion for tpm2_getsessionauditdigest                   -*- shell-script -*-
_tpm2_getsessionauditdigest()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -q | --qualification)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -m | --message)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P -c -p -q -s -m -f -g -S --hierarchy-auth --key-context --auth --qualification --signature --message --format --hash-algorithm --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_getsessionauditdigest tpm2_getsessionauditdigest
# ex: filetype=sh
# bash completion for tpm2_gettestresult                   -*- shell-script -*-
_tpm2_gettestresult()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_gettestresult tpm2_gettestresult
# ex: filetype=sh
# bash completion for tpm2_gettime                   -*- shell-script -*-
_tpm2_gettime()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -P | --endorse-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -q | --qualification)
                _filedir
                return;;
            -o | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -P -g -s -q -o -f --key-context --auth --endorse-auth --hash-algorithm --scheme --qualification --signature --format --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_gettime tpm2_gettime
# ex: filetype=sh
# bash completion for tpm2_hash                   -*- shell-script -*-
_tpm2_hash()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -o | --output)
                _filedir
                return;;
            -t | --ticket)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -g -o -t --hierarchy --hash-algorithm --output --ticket --hex " \
        -- "$cur"))
    } &&
    complete -F _tpm2_hash tpm2_hash
# ex: filetype=sh
# bash completion for tpm2_hierarchycontrol                   -*- shell-script -*-
_tpm2_hierarchycontrol()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P --hierarchy --hierarchy-auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_hierarchycontrol tpm2_hierarchycontrol
# ex: filetype=sh
# bash completion for tpm2_hmac                   -*- shell-script -*-
_tpm2_hmac()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -o | --output)
                _filedir
                return;;
            -t | --ticket)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -g -o -t --key-context --auth --hash-algorithm --output --ticket --hex --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_hmac tpm2_hmac
# ex: filetype=sh
# bash completion for tpm2_import                   -*- shell-script -*-
_tpm2_import()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -i | --input)
                _filedir
                return;;
            -C | --parent-context)
                _filedir
                return;;
            -U | --parent-public)
                _filedir
                return;;
            -k | --encryption-key)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -u | --public)
                _filedir
                return;;
            -a | --attributes)
                COMPREPLY=($(compgen -W "${key_attributes[*]}" -- "$cur"))
                return;;
            -P | --parent-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --key-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -s | --seed)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -G -g -i -C -U -k -r -u -a -P -p -L -s --key-algorithm --hash-algorithm --input --parent-context --parent-public --encryption-key --private --public --attributes --parent-auth --key-auth --policy --seed --passin --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_import tpm2_import
# ex: filetype=sh
# bash completion for tpm2_incrementalselftest                   -*- shell-script -*-
_tpm2_incrementalselftest()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_incrementalselftest tpm2_incrementalselftest
# ex: filetype=sh
# bash completion for tpm2_load                   -*- shell-script -*-
_tpm2_load()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --parent-context)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -u | --public)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
            -c | --key-context)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -u -r -n -c --parent-context --auth --public --private --name --key-context --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_load tpm2_load
# ex: filetype=sh
# bash completion for tpm2_loadexternal                   -*- shell-script -*-
_tpm2_loadexternal()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -u | --public)
                _filedir
                return;;
            -r | --private)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -a | --attributes)
                COMPREPLY=($(compgen -W "${key_attributes[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -G -u -r -p -L -g -a -c -n --hierarchy --key-algorithm --public --private --auth --policy --hash-algorithm --attributes --key-context --name --passin " \
        -- "$cur"))
    } &&
    complete -F _tpm2_loadexternal tpm2_loadexternal
# ex: filetype=sh
# bash completion for tpm2_makecredential                   -*- shell-script -*-
_tpm2_makecredential()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -e | --encryption-key)
                _filedir
                return;;
            -u | --public)
                _filedir
                return;;
            -G | --key-algorithm)
                COMPREPLY=($(compgen -W "${key_object[*]}" -- "$cur"))
                return;;
            -s | --secret)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
            -o | --credential-blob)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -e -u -G -s -n -o --encryption-key --public --key-algorithm --secret --name --credential-blob " \
        -- "$cur"))
    } &&
    complete -F _tpm2_makecredential tpm2_makecredential
# ex: filetype=sh
# bash completion for tpm2_nvcertify                   -*- shell-script -*-
_tpm2_nvcertify()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --signingkey-context)
                _filedir
                return;;
            -P | --signingkey-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --nvauthobj-context)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --nvauthobj-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -o | --signature)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -c -p -g -s -f -o -q --signingkey-context --signingkey-auth --nvauthobj-context --nvauthobj-auth --hash-algorithm --scheme --format --signature --qualification --size --offset --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvcertify tpm2_nvcertify
# ex: filetype=sh
# bash completion for tpm2_nvdefine                   -*- shell-script -*-
_tpm2_nvdefine()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -s | --size)
                _filedir
                return;;
            -a | --attributes)
                COMPREPLY=($(compgen -W "${nv_attributes[*]}" -- "$cur"))
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -p | --index-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -s -a -P -p -L --hierarchy --size --attributes --hierarchy-auth --index-auth --policy --hash-algorithm --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvdefine tpm2_nvdefine
# ex: filetype=sh
# bash completion for tpm2_nvextend                   -*- shell-script -*-
_tpm2_nvextend()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -i | --input)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -i --hierarchy --auth --input --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvextend tpm2_nvextend
# ex: filetype=sh
# bash completion for tpm2_nvincrement                   -*- shell-script -*-
_tpm2_nvincrement()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P --hierarchy --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvincrement tpm2_nvincrement
# ex: filetype=sh
# bash completion for tpm2_nvread                   -*- shell-script -*-
_tpm2_nvread()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -s | --size)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -o -P -s --hierarchy --output --auth --size --offset --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvread tpm2_nvread
# ex: filetype=sh
# bash completion for tpm2_nvreadlock                   -*- shell-script -*-
_tpm2_nvreadlock()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P --hierarchy --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvreadlock tpm2_nvreadlock
# ex: filetype=sh
# bash completion for tpm2_nvreadpublic                   -*- shell-script -*-
_tpm2_nvreadpublic()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvreadpublic tpm2_nvreadpublic
# ex: filetype=sh
# bash completion for tpm2_nvsetbits                   -*- shell-script -*-
_tpm2_nvsetbits()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -i | --bits)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -i --hierarchy --auth --bits --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvsetbits tpm2_nvsetbits
# ex: filetype=sh
# bash completion for tpm2_nvundefine                   -*- shell-script -*-
_tpm2_nvundefine()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -S --hierarchy --auth --session --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvundefine tpm2_nvundefine
# ex: filetype=sh
# bash completion for tpm2_nvwrite                   -*- shell-script -*-
_tpm2_nvwrite()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -i | --input)
                _filedir
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -i -C -P --input --hierarchy --auth --offset --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvwrite tpm2_nvwrite
# ex: filetype=sh
# bash completion for tpm2_nvwritelock                   -*- shell-script -*-
_tpm2_nvwritelock()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P --hierarchy --auth --global --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_nvwritelock tpm2_nvwritelock
# ex: filetype=sh
# bash completion for tpm2_pcrallocate                   -*- shell-script -*-
_tpm2_pcrallocate()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P --auth " \
        -- "$cur"))
    } &&
    complete -F _tpm2_pcrallocate tpm2_pcrallocate
# ex: filetype=sh
# bash completion for tpm2_pcrevent                   -*- shell-script -*-
_tpm2_pcrevent()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -P --auth " \
        -- "$cur"))
    } &&
    complete -F _tpm2_pcrevent tpm2_pcrevent
# ex: filetype=sh
# bash completion for tpm2_pcrextend                   -*- shell-script -*-
_tpm2_pcrextend()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_pcrextend tpm2_pcrextend
# ex: filetype=sh
# bash completion for tpm2_pcrread                   -*- shell-script -*-
_tpm2_pcrread()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local pcr_format_methods=(values serialized)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --output)
                _filedir
                return;;
            -F | --pcrs_format)
                COMPREPLY=($(compgen -W "${pcr_format_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -F --pcrs_format \
        -o --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_pcrread tpm2_pcrread
# ex: filetype=sh
# bash completion for tpm2_pcrreset                   -*- shell-script -*-
_tpm2_pcrreset()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_pcrreset tpm2_pcrreset
# ex: filetype=sh
# bash completion for tpm2_policyauthorize                   -*- shell-script -*-
_tpm2_policyauthorize()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -i | --input)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
            -t | --ticket)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S -i -q -n -t --policy --session --input --qualification --name --ticket " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyauthorize tpm2_policyauthorize
# ex: filetype=sh
# bash completion for tpm2_policyauthorizenv                   -*- shell-script -*-
_tpm2_policyauthorizenv()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -L -S --hierarchy --auth --policy --session --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyauthorizenv tpm2_policyauthorizenv
# ex: filetype=sh
# bash completion for tpm2_policyauthvalue                   -*- shell-script -*-
_tpm2_policyauthvalue()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S --policy --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyauthvalue tpm2_policyauthvalue
# ex: filetype=sh
# bash completion for tpm2_policycommandcode                   -*- shell-script -*-
_tpm2_policycommandcode()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -S | --session)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -S -L --session --policy " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policycommandcode tpm2_policycommandcode
# ex: filetype=sh
# bash completion for tpm2_policycountertimer                   -*- shell-script -*-
_tpm2_policycountertimer()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S --policy --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policycountertimer tpm2_policycountertimer
# ex: filetype=sh
# bash completion for tpm2_policycphash                   -*- shell-script -*-
_tpm2_policycphash()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S --policy --session --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policycphash tpm2_policycphash
# ex: filetype=sh
# bash completion for tpm2_policyduplicationselect                   -*- shell-script -*-
_tpm2_policyduplicationselect()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -S | --session)
                _filedir
                return;;
            -n | --object-name)
                _filedir
                return;;
            -N | --parent-name)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -S -n -N -L --session --object-name --parent-name --policy --include " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyduplicationselect tpm2_policyduplicationselect
# ex: filetype=sh
# bash completion for tpm2_policylocality                   -*- shell-script -*-
_tpm2_policylocality()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -S | --session)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -S -L --session --policy " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policylocality tpm2_policylocality
# ex: filetype=sh
# bash completion for tpm2_policynamehash                   -*- shell-script -*-
_tpm2_policynamehash()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S -n --policy --session --name " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policynamehash tpm2_policynamehash
# ex: filetype=sh
# bash completion for tpm2_policynv                   -*- shell-script -*-
_tpm2_policynv()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -i | --input)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -L -S -i --hierarchy --auth --policy --session --input --offset --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policynv tpm2_policynv
# ex: filetype=sh
# bash completion for tpm2_policynvwritten                   -*- shell-script -*-
_tpm2_policynvwritten()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -S | --session)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -S -L --session --policy " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policynvwritten tpm2_policynvwritten
# ex: filetype=sh
# bash completion for tpm2_policyor                   -*- shell-script -*-
_tpm2_policyor()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -l | --policy-list)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S -l --policy --session --policy-list " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyor tpm2_policyor
# ex: filetype=sh
# bash completion for tpm2_policypassword                   -*- shell-script -*-
_tpm2_policypassword()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S --policy --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policypassword tpm2_policypassword
# ex: filetype=sh
# bash completion for tpm2_policypcr                   -*- shell-script -*-
_tpm2_policypcr()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -f | --pcr)
                _filedir
                return;;
            -l | --pcr-list)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -f -l -S --policy --pcr --pcr-list --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policypcr tpm2_policypcr
# ex: filetype=sh
# bash completion for tpm2_policyrestart                   -*- shell-script -*-
_tpm2_policyrestart()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -S --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyrestart tpm2_policyrestart
# ex: filetype=sh
# bash completion for tpm2_policysecret                   -*- shell-script -*-
_tpm2_policysecret()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --object-context)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -L | --policy)
                _filedir
                return;;
            -t | --expiration)
                _filedir
                return;;
            -x | --nonce-tpm)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -S -L -t -x -q --object-context --session --policy --expiration --nonce-tpm --qualification --ticket --timeout --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policysecret tpm2_policysecret
# ex: filetype=sh
# bash completion for tpm2_policysigned                   -*- shell-script -*-
_tpm2_policysigned()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -c | --key-context)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -t | --expiration)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
            -x | --nonce-tpm)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S -c -g -s -f -t -q -x --policy --session --key-context --hash-algorithm --signature --format --expiration --qualification --nonce-tpm --ticket --timeout " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policysigned tpm2_policysigned
# ex: filetype=sh
# bash completion for tpm2_policytemplate                   -*- shell-script -*-
_tpm2_policytemplate()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S --policy --session " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policytemplate tpm2_policytemplate
# ex: filetype=sh
# bash completion for tpm2_policyticket                   -*- shell-script -*-
_tpm2_policyticket()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -L | --policy)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -L -S -n -q --policy --session --name --qualification --ticket --timeout " \
        -- "$cur"))
    } &&
    complete -F _tpm2_policyticket tpm2_policyticket
# ex: filetype=sh
# bash completion for tpm2_print                   -*- shell-script -*-
_tpm2_print()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -t | --type)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -t --type " \
        -- "$cur"))
    } &&
    complete -F _tpm2_print tpm2_print
# ex: filetype=sh
# bash completion for tpm2_quote                   -*- shell-script -*-
_tpm2_quote()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local pcr_format_methods=(values serialized)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -l | --pcr-list)
                _filedir
                return;;
            -F | --pcrs_format)
                COMPREPLY=($(compgen -W "${pcr_format_methods[*]}" -- "$cur"))
                return;;
            -m | --message)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
            -o | --pcr)
                _filedir
                return;;
            -q | --qualification)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti -F --pcrs_format \
        -c -p -l -m -s -f -o -q -g --key-context --auth --pcr-list --message --signature --format --pcr --qualification --hash-algorithm --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_quote tpm2_quote
# ex: filetype=sh
# bash completion for tpm2_rc_decode                   -*- shell-script -*-
_tpm2_rc_decode()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_rc_decode tpm2_rc_decode
# ex: filetype=sh
# bash completion for tpm2_readclock                   -*- shell-script -*-
_tpm2_readclock()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_readclock tpm2_readclock
# ex: filetype=sh
# bash completion for tpm2_readpublic                   -*- shell-script -*-
_tpm2_readpublic()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --object-context)
                _filedir
                return;;
            -n | --name)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
            -t | --serialized-handle)
                _filedir
                return;;
            -q | --qualified-name)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -n -o -t -q --object-context --name --output --serialized-handle --qualified-name " \
        -- "$cur"))
    } &&
    complete -F _tpm2_readpublic tpm2_readpublic
# ex: filetype=sh
# bash completion for tpm2_rsadecrypt                   -*- shell-script -*-
_tpm2_rsadecrypt()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -o | --output)
                _filedir
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -l | --label)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -o -s -l --key-context --auth --output --scheme --label --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_rsadecrypt tpm2_rsadecrypt
# ex: filetype=sh
# bash completion for tpm2_rsaencrypt                   -*- shell-script -*-
_tpm2_rsaencrypt()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -o | --output)
                _filedir
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -l | --label)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -o -s -l --key-context --output --scheme --label " \
        -- "$cur"))
    } &&
    complete -F _tpm2_rsaencrypt tpm2_rsaencrypt
# ex: filetype=sh
# bash completion for tpm2_selftest                   -*- shell-script -*-
_tpm2_selftest()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -f | --fulltest)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -f --fulltest " \
        -- "$cur"))
    } &&
    complete -F _tpm2_selftest tpm2_selftest
# ex: filetype=sh
# bash completion for tpm2_send                   -*- shell-script -*-
_tpm2_send()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -o --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_send tpm2_send
# ex: filetype=sh
# bash completion for tpm2_setclock                   -*- shell-script -*-
_tpm2_setclock()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --hierarchy)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p --hierarchy --auth --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_setclock tpm2_setclock
# ex: filetype=sh
# bash completion for tpm2_setcommandauditstatus                   -*- shell-script -*-
_tpm2_setcommandauditstatus()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --hierarchy-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -c | --clear-list)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -c -g --hierarchy --hierarchy-auth --clear-list --hash-algorithm " \
        -- "$cur"))
    } &&
    complete -F _tpm2_setcommandauditstatus tpm2_setcommandauditstatus
# ex: filetype=sh
# bash completion for tpm2_setprimarypolicy                   -*- shell-script -*-
_tpm2_setprimarypolicy()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -C | --hierarchy)
                _filedir
                return;;
            -P | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -L | --policy)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -C -P -L -g --hierarchy --auth --policy --hash-algorithm --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_setprimarypolicy tpm2_setprimarypolicy
# ex: filetype=sh
# bash completion for tpm2_shutdown                   -*- shell-script -*-
_tpm2_shutdown()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --clear)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c --clear " \
        -- "$cur"))
    } &&
    complete -F _tpm2_shutdown tpm2_shutdown
# ex: filetype=sh
# bash completion for tpm2_sign                   -*- shell-script -*-
_tpm2_sign()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -d | --digest)
                _filedir
                return;;
            -t | --ticket)
                _filedir
                return;;
            -o | --signature)
                _filedir
                return;;
            -f | --format)
                COMPREPLY=($(compgen -W "${format_methods[*]}" -- "$cur"))
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -g -s -d -t -o -f --key-context --auth --hash-algorithm --scheme --digest --ticket --signature --format --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_sign tpm2_sign
# ex: filetype=sh
# bash completion for tpm2_startauthsession                   -*- shell-script -*-
_tpm2_startauthsession()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -c | --key-context)
                _filedir
                return;;
            -S | --session)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -g -c -S --hash-algorithm --key-context --session --policy --audit " \
        -- "$cur"))
    } &&
    complete -F _tpm2_startauthsession tpm2_startauthsession
# ex: filetype=sh
# bash completion for tpm2_startup                   -*- shell-script -*-
_tpm2_startup()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --clear)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c --clear " \
        -- "$cur"))
    } &&
    complete -F _tpm2_startup tpm2_startup
# ex: filetype=sh
# bash completion for tpm2_stirrandom                   -*- shell-script -*-
_tpm2_stirrandom()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_stirrandom tpm2_stirrandom
# ex: filetype=sh
# bash completion for tpm2_testparms                   -*- shell-script -*-
_tpm2_testparms()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        " \
        -- "$cur"))
    } &&
    complete -F _tpm2_testparms tpm2_testparms
# ex: filetype=sh
# bash completion for tpm2_unseal                   -*- shell-script -*-
_tpm2_unseal()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --object-context)
                _filedir
                return;;
            -p | --auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -o | --output)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -o --object-context --auth --output --cphash " \
        -- "$cur"))
    } &&
    complete -F _tpm2_unseal tpm2_unseal
# ex: filetype=sh
# bash completion for tpm2_verifysignature                   -*- shell-script -*-
_tpm2_verifysignature()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -g | --hash-algorithm)
                COMPREPLY=($(compgen -W "${hash_methods[*]}" -- "$cur"))
                return;;
            -m | --message)
                _filedir
                return;;
            -d | --digest)
                _filedir
                return;;
            -s | --signature)
                _filedir
                return;;
            -f | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -t | --ticket)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -g -m -d -s -f -t --key-context --hash-algorithm --message --digest --signature --scheme --ticket --format " \
        -- "$cur"))
    } &&
    complete -F _tpm2_verifysignature tpm2_verifysignature
# ex: filetype=sh
# bash completion for tpm2_zgen2phase                   -*- shell-script -*-
_tpm2_zgen2phase()
    {
        local auth_methods=(str: hex: file: file:- session: pcr:)

        local hash_methods=(sha1 sha256 sha384 sha512)

        local format_methods=(tss plain)

        local signing_scheme=(rsassa rsapss ecdsa ecdaa sm2 ecshnorr hmac)

        local key_object=(rsa ecc aes camellia hmac xor keyedhash)

        local key_attributes=(\| fixedtpm stclear fixedparent \
        sensitivedataorigin userwithauth adminwithpolicy noda \
        encrypteddupplication restricted decrypt sign)

        local nv_attributes=(\| ppwrite ownerwrite authwrite policywrite \
        policydelete writelocked writeall writedefine write_stclear \
        globallock ppread ownerread authread policyread no_da orderly \
        clear_stclear readlocked written platformcreate read_stclear)

        local cur prev words cword split
        _init_completion -s || return
        case $prev in
            -h | --help)
                COMPREPLY=( $(compgen -W "man no-man" -- "$cur") )
                return;;
            -T | --tcti)
                COMPREPLY=( $(compgen -W "tabrmd mssim device none" -- "$cur") )
                return;;
            -c | --key-context)
                _filedir
                return;;
            -p | --key-auth)
                COMPREPLY=($(compgen -W "${auth_methods[*]}" -- "$cur"))
                return;;
            -s | --scheme)
                COMPREPLY=($(compgen -W "${signing_scheme[*]}" -- "$cur"))
                return;;
            -t | --counter)
                _filedir
                return;;
        esac

        COMPREPLY=($(compgen -W "-h --help -v --version -V --verbose -Q --quiet \
        -Z --enable-erata -T --tcti \
        -c -p -s -t --key-context --key-auth --scheme --counter --static --ephemeral --output --output " \
        -- "$cur"))
    } &&
    complete -F _tpm2_zgen2phase tpm2_zgen2phase
# ex: filetype=sh
_tpm2() {
            local cur prev words cword split
            _init_completion -s || return

            if ((cword == 1)); then
                COMPREPLY=($(compgen -W "activatecredential certify certifyX509certutil certifycreation changeauth changeeps changepps checkquote clear clearcontrol clockrateadjust commit create createak createek createpolicy createprimary dictionarylockout duplicate ecdhkeygen ecdhzgen ecephemeral encryptdecrypt eventlog evictcontrol flushcontext getcap getcommandauditdigest geteccparameters getekcertificate getrandom getsessionauditdigest gettestresult gettime hash hierarchycontrol hmac import incrementalselftest load loadexternal makecredential nvcertify nvdefine nvextend nvincrement nvread nvreadlock nvreadpublic nvsetbits nvundefine nvwrite nvwritelock pcrallocate pcrevent pcrextend pcrread pcrreset policyauthorize policyauthorizenv policyauthvalue policycommandcode policycountertimer policycphash policyduplicationselect policylocality policynamehash policynv policynvwritten policyor policypassword policypcr policyrestart policysecret policysigned policytemplate policyticket print quote rc_decode readclock readpublic rsadecrypt rsaencrypt selftest send setclock setcommandauditstatus setprimarypolicy shutdown sign startauthsession startup stirrandom testparms unseal verifysignature zgen2phase " -- "$cur"))
            else
                tpmcommand=_tpm2_$prev
                type $tpmcommand &>/dev/null && $tpmcommand
                if [ $? == 1 ];then
                    COMPREPLY=($(compgen -W ${words[1]} -- "$cur"))
                fi
            fi
            } &&
            complete -F _tpm2 tpm2
