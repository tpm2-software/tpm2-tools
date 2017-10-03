# Supported Signing Algorithms

Supported algorithms are:

  * **0x5** or **hmac** for **TPM_ALG_HMAC** **(default)**
  * **0x14** or **rsassa** for **TPM_ALG_RSASSA**
  * **0x16** or **rsapss** for **TPM_ALG_RSAPSS**
  * **0x18** or **ecdsa** for **TPM_ALG_ECDSA**
  * **0x1A** or **ecdaa** for **TPM_ALG_ECDAA**
  * **0x1B** or **sm2** for **TPM_ALG_SM2**
  * **0x1C** or **ecschnorr** for **TPM_ALG_ECSCHNORR**

**NOTE**: Your TPM may not support all algorithms.
