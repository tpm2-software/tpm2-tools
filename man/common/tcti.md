# TCTI ENVIRONMENT

This collection of environment variables that may be used to configure the
various TCTI modules available.

The values passed through these variables can be overridden on a per-command
basis using the available command line options, see the _TCTI_OPTIONS_ section.

The variables respected depend on how the software was configured.

  * _TPM2TOOLS\_TCTI\_NAME_:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the TPM but it could be a simulator
	or proxy. The current known TCTIs are:

	* tabrmd - The new resource manager, called
	           [tabrmd](https://github.com/01org/tpm2-abrmd).
	* socket - Typically used with the old resource manager, or talking directly to
	           a simulator.
	* device - Used when talking directly to a TPM device file.
	* none   - Do not initialize a connection with the TPM. Some tools allow for off-tpm
               options and thus support not using a TCTI. Tools that do not support it
               will error when attempted to be used without a TCTI connection. Does not
               support *ANY* options and *MUST BE* presented as the exact text of "none".

  * _TPM2TOOLS\_DEVICE\_FILE_:
	When using the device TCTI, specify the TPM device file. The default is
	"/dev/tpm0".

	Note: Using the tpm directly requires the users to ensure that concurrent
	access does not occur and that they manage the tpm resources. These tasks are
	usually managed by a resource manager. Linux 4.12 and greater supports an in
	kernel resource manager at "/dev/tpmrm**<num>**",	typically "/dev/tpmrm0".

  * _TPM2TOOLS\_SOCKET\_ADDRESS_:
    When using the socket TCTI, specify the domain name or IP address used. The
    default is 127.0.0.1.

  * _TPM2TOOLS\_SOCKET\_PORT_:
	When using the socket TCTI, specify the port number used. The default is 2321.

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
      Example: **-T device:/dev/tpm0**

    * For the socket TCTI, the domain name or IP address and port number used by the socket
      can be specified. The default are 127.0.0.1 and 2321.
      Example: **-T socket:127.0.0.1:2321**

    * For the abrmd TCTI, it takes no options. Example: **-T abrmd**
