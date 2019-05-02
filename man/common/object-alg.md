# Supported Public Object Algorithms

Supported public object algorithms are:

## Symmetric
###  AES
The AES cipher has a bitsize and a mode. When the mode is not specified, ie a
"NULL" mode, the TPM will allow any mode usages on subsequent key uses. If the
mode is specified during object creation, only that mode is allowed in
subsequent use cases.

  * **aes** - Default AES selection. The default AES Selection is AES 128 with
    a NULL mode.

  * **aes[128|192|256]** - AES with a key size of 128, 192 and 256 respectively
    with a NULL mode.

  * **aes[128|192|256][cbc|ocb|cfb|ecb]** - AES with a key size of 128, 192 and
    256 and a mode of cbc, ocb, cfb and ecb respectively.

#### Examples

  * aes256cbc - AES with a key bitsize of 256 and a mode of cbc.

  * aes192cfb - AES with a bitsize of 192 and mode of cfb.

  * aes128 - AES with a bitsize of 128 and NULL mode.

## Asymmetric

### RSA

The RSA cipher has a bitsize, and the TPM (optionally) supports associating a symmetric
key along with the RSA algorithm. The AES key will be used for encryption modes that rely
on an RSA scheme, like RSAES_OAEP.

  * **rsa** -
    Default RSA algorithm. The default bitsize is 2048. Depending on if the object
    is a restricted object (aka a parent object), the algorithms encryption options will default to:

    * restricted object - scheme of null and a NULL symmetric algorithm.

    * non-restricted object - scheme of null and an aes128cfb symmetric algorithm.

  * **rsa[1024|2048|4096]** -
    Similar to **rsa** option, but provides control over the key
    size to either 1024, 2048 or 4096 respectively.

  * **rsa[1024|2048|4096]:[oaep|rsaes]** -
    Similar to **rsa[1024|2048|4096]** option, but provides the ability
    to control the scheme. The algorithms encryption options will default to:
    aes128cfb.

  * **rsa[1024|2048|4096]:[oaep|rsaes]:[aes]**
    Similar to **rsa[1024|2048]:[oaep|rsaes]** option, but provides
    full control over the aes key options. See the section **AES**
    for details of these AES strings.

#### Examples

  * rsa1024 - Creates an RSA 1024 key with a scheme and symmetric algorithm dependent on the restricted attribute.

  * rsa:oeap:aes - Creates an RSA 2048 key with an AES-OEAP scheme and an AES default key based on attributes.

  * rsa1024:null:aes128cbc - Creates an RSA 1024 key with a NULL encryption scheme and an AES key of 128 for use ONLY with CBC.

### ECC

The ECC cipher has a size, and the TPM (optionally) supports associating a symmetric
key along with the ECC algorithm. The AES key will be used for encryption modes that rely
on an asymmetric encryption scheme, like RSAES_OAEP.

  * **ecc** -
    Default ECC algorithm. The default curve size is 256. Depending on if the object
    is a restricted object (aka a parent object), the algorithms encryption options will default to:

    * restricted object - scheme of null and a NULL symmetric algorithm.

    * non-restricted object - scheme of null and an aes128cfb symmetric algorithm.

  * **ecc[224|256|384|521]** -
    Similar to **ecc** option, but provides control over the curve
    size to either 224,256,384 or 521 respectively.

  * **ecc[224|256|384|521]:[oaep|rsaes]** -
    Similar to **ecc[224|256|384|521]** option, but provides the ability
    to control the scheme. The algorithms encryption options will default to:
    aes128cfb.

  * **ecc[224|256|384|521]:[oaep|rsaes]:[aes]**
    Similar to **ecc[224|256|384|521]:[oaep|rsaes]** option, but provides
    full control over the aes key options. See the section **AES**
    for details of these AES strings.

#### Examples

  * ecc224 - Creates an ECC 224 key with a scheme and symmetric algorithm dependent on the restricted attribute.

  * ecc:oeap:aes - Creates an ECC 256 key with an AES-OEAP scheme and an AES default key based on attributes.

  * ecc384:null:aes128cbc - Creates an ECC 384 key with a NULL encryption scheme and an AES key of 128 for use ONLY with CBC.

## KeyedHash

 The keyedhash algorithms are hmac and xor.

### HMAC

The HMAC algorithm needs a hashing algorithm and nothing more. It defaults to
sha256 if not specified.

  * **hmac:[sha256|sha384|sha512]** -
    Generate an HMAC key valid for the associated hash algorithm, defaults to
    sha256 if not specified.


### XOR

The XOR algorithm needs a hashing algorithm and nothing more. It defaults to
sha256 if not specified. The XOR scheme should be used where confidentiality
of the objects is desired, but secrecy is not mandatory. The algorithm is
lightweight and quick.

  * **xor:[sha256|sha384|sha512]** -
    Generate an XOR key valid for the associated hash algorithm, defaults to
    sha256 if not specified.

**NOTE**: Your TPM may not support all algorithms.
