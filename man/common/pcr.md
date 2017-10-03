# PCR Bank Specfiers

PCR Bank Selection lists follow the below specification:

```
<BANK>:<PCR>[,<PCR>]
```

multiple banks may be separated by '+'.

For example:

```
sha:3,4+sha256:5,6
```
will select PCRs 3 and 4 from the SHA bank and PCRs 5 and 6
from the SHA256 bank.