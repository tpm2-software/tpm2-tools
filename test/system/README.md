# Testing Framework

The command **test.sh** can be used to run the test scripts. Invoking
**test.sh** will run the full test suite. For example:

```
./test.sh
```

One can also run individual test scripts by invoking **test.sh** with an
argument of the test file name(s) to run, for example:

```
./test.sh test_tpm2_hmac.sh test_tpm2_hash.sh
```

**NOTE: That the tools must be avialble on *PATH* **

**NOTE: That the test script should be run against the tpm simulator with a resource manager**