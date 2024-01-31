% tpm2_pcrread(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrread**(1) - List PCR values.

# SYNOPSIS

**tpm2_pcrread** [*OPTIONS*] _PCR\_LIST\_OR\_ALG_

# DESCRIPTION

**tpm2_pcrread**(1) - Displays PCR values. Without any arguments, **tpm2_pcrread**(1)
outputs all PCRs and their hash banks. One can use specify the hash algorithm or
a pcr list as an argument to filter the output.

To only output PCR banks with a given algorithm, specify the hashing algorithm
as the argument. Algorithms should follow the "formatting standards", see section
"Algorithm Specifiers". Also, see section "Supported Hash Algorithms" for a list
of supported hash algorithms.

To output a list of PCR banks (sha1, sha256, etc) and ids (0, 1, 2 etc) specify
a PCR selection list as the argument as specified via section "PCR Bank
Specifiers".

Also read **NOTES** section below.

Output is written in a YAML format to stdout, with each algorithm followed by
a PCR index and its value. As a simple example assume just sha1 and sha256
support and only 1 PCR. The output would be:
```
$ tpm2_pcrread sha1:0+sha256:0
sha1 :
  0  : 0000000000000000000000000000000000000003
sha256 :
  0  : 0000000000000000000000000000000000000000000000000000000000000003
```

# OPTIONS

  * **-o**, **\--output**=_FILE_:

    The output file to write the PCR values in binary format, optional.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

[PCR output file format specifiers](common/pcrs_format.md)
    Default is 'values'.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[PCR bank specifiers](common/pcr.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

## Display all PCR values
```bash
tpm2_pcrread
```

## Display the PCR values with a specified bank
```bash
tpm2_pcrread sha1
```

## Display the PCR values with specified banks and store in a file
```bash
tpm2_pcrread -o pcrs sha1:16,17,18+sha256:16,17,18
```

## Display the supported PCR bank algorithms and exit
```bash
tpm2_pcrread
```

# NOTES

The maximum number of PCR that can be dumped at once is associated
with the maximum length of a bank.

On most TPMs, it means that this tool can dump up to 24 PCRs
at once.

[returns](common/returns.md)

[footer](common/footer.md)
