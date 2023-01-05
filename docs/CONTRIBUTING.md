## Guidelines for submitting bugs:

All non security bugs can be filed on the Issues tracker:

<https://github.com/tpm2-software/tpm2-tools/issues>

Security sensitive bugs should be handled per the instructions in the
[docs/SECURITY.md](docs/SECURITY.md) file.

## Guidelines for submitting changes:

All changes should be introduced via github pull requests. This allows anyone to
comment and provide feedback in lieu of having a mailing list. For pull requests
opened by non-maintainers, any maintainer may review and merge that pull request.
For maintainers, they either must have their pull request reviewed by another
maintainer if possible, or leave the PR open for at least 24 hours, we consider
this the window for comments.

All tests must pass on Github Actions CI for the merge to occur.
All changes must not introduce superfluous whitespace changes or whitespace errors.
All changes should adhere to the coding standard documented under misc.

### Guideline for merging changes:
Changes should be merged with the "rebase" option on github to avoid merge commits.
This provides for a clear linear history.
