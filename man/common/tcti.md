# TCTI ENVIRONMENT

This collection of environment variables that may be used to configure the
various TCTI modules available.

The values passed through these variables can be overridden on a per-command
basis using the available command line options, see the _TCTI_OPTIONS_ section.

The variables respected depend on how the software was configured.

  * _TPM2TOOLS\_TCTI\_NAME_:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the Resource Manager called tabrmd,
	but it could be a TPM simulator or TPM device itself.

  The current known TCTIs are:

	* tabrmd - The new resource manager, called
	           [tabrmd](https://github.com/01org/tpm2-abrmd).
	           Note that tabrmd and abrmd as a tcti name are synonymous.
	* socket - Typically used with the old resource manager, or for communicating to
	           the TPM software simulator.
	* device - Used when talking directly to a TPM device file.

One can pass TCTI specific options to a TCTI via the _TPM2TOOLS\_TCTI\_NAME_ environment
variable by appending the option string after the name with a : (colon) separator. These TCTI
option config strings are TCTI specific. Specifying **-h** on the tool command line will
show help output for the TCTIs. The section **TCTI OPTIONS** has examples for known TCTIs.

Formally, the format is:
```<tcti-name>:<tcti-option-config>```

Specifying an empty string for either the ```<tcti-name>``` or ```<tcti-option-config>```
results in the default being used for that portion respectively.

# TCTI OPTIONS

This collection of options are used to configure the various TCTI modules
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

    * For the abrmd TCTI, the configuration string format is a series of simple key value pairs
      separated by a ',' character. Each key and value string are separated by a '=' character.

      * TCTI abrmd supports two keys:
      1. 'bus_name' : The name of the tabrmd service on the bus (a string).
      2. 'bus_type' : The type of the dbus instance (a string) limited to
         'session' and 'system'.

## TCTI Option Examples:
Specify the tabrmd tcti name and a config string of ```bus_name=com.example.FooBar```:
```
--tcti=tabrmd:bus_name=com.example.FooBar
```

Specify the default (abrmd) tcti and a config string of ```bus_type=session```:
```
--tcti:bus_type=session
```

Specify the device tcti and use the default config:
```
--tcti=device
```
or
```
--tcti=device:
```
