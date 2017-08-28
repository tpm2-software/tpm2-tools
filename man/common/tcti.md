TCTI ENVIRONMENT
----------------

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

  * _TPM2TOOLS\_DEVICE\_FILE_:
	When using the device TCTI, specify the TPM device file. The default is
	"/dev/tpm0".

	Note: Using the tpm directly requires the users to ensure that concurrent
	access does not occur and that they manage the tpm resources. These tasks are
	usually managed by a resource manager. Linux 4.12 and greater supports an in
	kernel resource manager at "/dev/tpmrm`<num>`",	typically "/dev/tpmrm0".

  * _TPM2TOOLS\_SOCKET\_ADDRESS_:
    When using the socket TCTI, specify the domain name or IP address used. The
    default is 127.0.0.1.

  * _TPM2TOOLS\_SOCKET\_PORT_:
	When using the socket TCTI, specify the port number used. The default is 2321.

TCTI OPTIONS
------------

This collection of options are used to configure the varous TCTI modules
available. They override any environment variables.

  * `-T`, `--tcti`=_TCTI_NAME_:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the resource manager:
	[tabrmd](https://github.com/01org/tpm2-abrmd)

  * `-d`, `--device-file`=_DEVICE_FILE_:
	Specify the TPM device file for use by the device TCTI. The default is
	/dev/tpm0.

  * `-R`, `--socket-address`=_SOCKET_ADDRESS_:
	Specify the domain name or IP address used by the socket TCTI. The default
	is 127.0.0.1.

  * `-p`, `--socket-port`=_SOCKET_PORT_:
	Specify the port number used by the socket TCTI. The default is 2321.
