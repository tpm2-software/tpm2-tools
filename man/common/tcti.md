# TCTI ENVIRONMENT

This collection of environment variables that may be used to configure the
various TCTI modules available.

The values passed through these variables can be overridden on a per-command
basis using the available command line options, see the _TCTI_OPTIONS_ section.

The variables respected depend on how the software was configured.

  * _TPM2TOOLS\_TCTI\_NAME_:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the Resource Manager called tabrms,
	but it could be a TPM simulator or TPM device itself.

  The current known TCTIs are:

	* tabrmd - The new resource manager, called
	           [tabrmd](https://github.com/01org/tpm2-abrmd).
	* socket - Typically used with the old resource manager, or talking directly to
	           a simulator.
	* device - Used when talking directly to a TPM device file.

One can pass TCTI specific options to a TCTI via the _TPM2TOOLS\_TCTI\_NAME_ environment
variable by appending the options after the name with a : (colon) seperator. These TCTI
option config strings are TCTI specific. Specifying **-h** on the tool command line will
show help output for the TCTIs. The section **TCTI OPTIONS** has examples for known TCTIs.

Formally, the format is:
```<tcti-name>:<tcti-options>```

# TCTI OPTIONS

This collection of options are used to configure the varous TCTI modules
available. They override any environment variables.

  * **-T**, **--tcti**=_TCTI\_NAME_**[**:_TCTI\_OPTIONS_**]**:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the resource manager:
	[tabrmd](https://github.com/01org/tpm2-abrmd)
	Optionally, tcti specific options can appended to _TCTI\_NAME_ by appending
	a **:** to _TCTI\_NAME_.

    * For the device TCTI, the TPM device file for use by the device TCTI can be specified.
      The default is /dev/tpm0.
      Example: **-T device:/dev/tpm0** or **export _TPM2TOOLS\_TCTI\_NAME_="device:/dev/tpm0"**

    * For the socket TCTI, the domain name or IP address and port number used by the socket
      can be specified. The default are 127.0.0.1 and 2321.
      Example: **-T socket:tcp://127.0.0.1:2321** or **export _TPM2TOOLS\_TCTI\_NAME_="socket:tcp://127.0.0.1:2321"**

    * For the abrmd TCTI, it takes no options. Example: **-T abrmd** or **export _TPM2TOOLS\_TCTI\_NAME_="abrmd"**
