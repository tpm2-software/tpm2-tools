  * **-f**, **\--format**:

    Format selection for the public key output file. 'tss' (the default) will
    output a binary blob according to the TPM 2.0 Specification. 'pem' will
    output an OpenSSL compatible PEM encoded public key. 'der' will output an
    OpenSSL compatible DER encoded public key. 'tpmt' will output a binary blob
    of the TPMT_PUBLIC struct referenced by TPM 2.0 specs.
