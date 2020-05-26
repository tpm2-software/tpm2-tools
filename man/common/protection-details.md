# Protection Details

Objects that can move outside of TPM need to be protected (confidentiality and integrity).
For instance, transient objects require that TPM protected data (key or seal material) be
stored outside of the TPM. This is seen in tools like tpm2\_create(1), where the **-r** option
outputs this protected data. This blob contains the sensitive portions of the object. The sensitive
portions of the object are protected by the parent object, using the parent's symmetric encryption
details to encrypt the sensitive data and HMAC it.

In-depth details can be found in sections 23 of:

  - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf

Notably Figure 20, is relevant, even though it's specifically referring to duplication blobs, the process
is identical.

If the output is from tpm2\_duplicate(1), the output will be slightly different, as described fully in
section 23.
