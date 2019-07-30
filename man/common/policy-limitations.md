# Limitations

It expects a session to be already established via **tpm2_startauthsession**(1) and
requires one of the following:

  - direct device access
  - extended session support with **tpm2-abrmd**.

Without it, most resource managers **will not** save session state between command
invocations.
