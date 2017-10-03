# Algorithm Specfiers

Options that take algorithms support "nice-names". Nice names, like sha1 can be
used in place of the raw hex for sha1: 0x4. The nice names are converted by
stripping the leading **TPM_ALG_** from the Algorithm Name field and converting
it to lower case. For instance **TPM_ALG_SHA3_256** becomes **sha3_256**.

The algorithms can be found at:
<https://trustedcomputinggroup.org/wp-content/uploads/TCG_Algorithm_Registry_Rev_1.24.pdf>
