# Algorithm Specifiers

Options that take algorithms support "nice-names".

There are two major algorithm specification string classes, simple and complex.
Only certain algorithms will be accepted by the TPM, based on usage and conditions.

## Simple specifiers
These are strings with no additional specification data. When creating objects,
non-specified portions of an object are assumed to defaults. You can find the
list of known "Simple Specifiers" below.

### Asymmetric
  * rsa
  * ecc

### Symmetric
  * aes
  * camellia
  * sm4

### Hashing Algorithms
  * sha1
  * sha256
  * sha384
  * sha512
  * sm3_256
  * sha3_256
  * sha3_384
  * sha3_512

### Keyed Hash
  * hmac
  * xor

### Signing Schemes
  * rsassa
  * rsapss
  * ecdsa
  * ecdaa
  * ecschnorr
  * sm2

### Asymmetric Encryption Schemes
  * oaep
  * rsaes
  * ecdh

### Modes
  * ctr
  * ofb
  * cbc
  * cfb
  * ecb

### Misc
  * null

## Complex Specifiers
Objects, when specified for creation by the TPM, have numerous algorithms to populate in the
public data. Things like type, scheme and asymmetric details, key size, etc. Below is the
general format for specifying this data:
`<type>:<scheme>:<symmetric-details>`

### Type Specifiers

   This portion of the complex algorithm specifier is required. The remaining scheme and symmetric details
   will default based on the type specified and the type of the object being created.

  * aes - Default AES: aes128
  * aes128`<mode>` - 128 bit AES with optional mode (*ctr*|*ofb*|*cbc*|*cfb*|*ecb*). If mode is not
      specified, defaults to *null*.
  * aes192`<mode>` - Same as aes128`<mode>`, except for a 192 bit key size.
  * aes256`<mode>` - Same as aes128`<mode>`, except for a 256 bit key size.
  * sm4 - Default SM4: sm4128
  * sm4128 or sm4_128 `<mode>` - 128 bit SM4 with optional mode (*ctr*|*ofb*|*cbc*|*cfb*|*ecb*). If mode is not
      specified, defaults to *null*.
  * ecc - Elliptical Curve, defaults to ecc256.
  * ecc192 or ecc_nist_p192 - 192 bit ECC NIST curve
  * ecc224 or ecc_nist_p224 - 224 bit ECC NIST curve
  * ecc256 or ecc_nist_p256 - 256 bit ECC NIST curve
  * ecc384 or ecc_nist_p384 - 384 bit ECC NIST curve
  * ecc521 or ecc_nist_p521 - 521 bit ECC NIST curve
  * ecc_sm2 or ecc_sm2_p256 - 256 bit SM2 curve
  * rsa - Default RSA: rsa2048
  * rsa1024 - RSA with 1024 bit keysize.
  * rsa2048 - RSA with 2048 bit keysize.
  * rsa3072 - RSA with 3072 bit keysize.
  * rsa4096 - RSA with 4096 bit keysize.

### Scheme Specifiers
Next, is an optional field, it can be skipped.

Schemes are usually **Signing Schemes** or **Asymmetric Encryption Schemes**.
Most signing schemes take a hash algorithm directly following the signing scheme. If the hash
algorithm is missing, it defaults to *sha256*. Some take no arguments, and some take multiple
arguments.

#### Hash Optional Scheme Specifiers
These scheme specifiers are followed by a dash and a valid hash algorithm, For example: `oaep-sha256`.

  * oaep
  * ecdh
  * rsassa
  * rsapss
  * ecdsa
  * ecschnorr
  * sm2

#### Multiple Option Scheme Specifiers
This scheme specifier is followed by a count (max size UINT16) then followed by a dash(-) and a valid hash algorithm.
  * ecdaa
For example, ecdaa4-sha256. If no count is specified, it defaults to 4.

#### No Option Scheme Specifiers
This scheme specifier takes NO arguments.
  * rsaes

### Symmetric Details Specifiers
This field is optional, and defaults based on the *type* of object being created and it's attributes.
Generally, any valid **Symmetric** specifier from the **Type Specifiers** list should work. If not
specified, an asymmetric objects symmetric details defaults to *aes128cfb*.

## Examples

### Create an rsa2048 key with an rsaes asymmetric encryption scheme
`tpm2_create -C parent.ctx -G rsa2048:rsaes -u key.pub -r key.priv`

### Create an ecc256 key with an ecdaa signing scheme with a count of 4 and sha384 hash
`/tpm2_create -C parent.ctx -G ecc256:ecdaa4-sha384 -u key.pub -r key.priv`
