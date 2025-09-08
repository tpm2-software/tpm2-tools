  * **-F**, **\--pcrs_format**=_FORMAT_:

    Format selection for the binary blob in the PCR output file. 'values' will output a binary blob of the PCR values. 'serialized' will write or read a binary blob of the PCR values in the form of serialized data structure in little endian format.
    'marshaled' will will read or write a binary blob in the binary format used by the TSS2 marshaling and unmarshaling functions. If marshaled is used the data is serialized in the following order: TPML_PCR_SELECTION, 
    UINT32 (the number of following TPML_DIGEST elements) TPML_DIGEST [number of TPML_DIGEST elements].
    Optional.
