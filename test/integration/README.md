# Testing Framework

The command **make check** can be used to run the test scripts.

The configure option `--enable-unit` must be specified and the
`tpm2-abrmd` and `tpm_server` must be found on `$PATH`. If they are installed
in custom locations, specify or export `$PATH` during configure.

For example:
```sh
./configure --enable-unit PATH=$PATH:/path/to/tpm2-abrmd:/path/to/tpm/sim/ibmtpm974/src
```

## Adding a new integration test
To add a new test, do:

1. add a script to the `test/integration/tests` directory.
2. `source helpers.sh` in the new script.
3. issue the command `start_up`.
4. Do whatever test you need to do.
5. If you set the `EXIT` handler, call `tpm2 shutdown` in that handler.
6. `make distclean`, re-run `bootstrap` and configure to pick up the new script.
7. Run `make check` again.
