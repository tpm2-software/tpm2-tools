## Release Instructions

The general release process will be to fork a branch at each major release followed by a ".X".
For example, the major version 2 branches will be 2.X. Release candidates (rc), will be tagged
using a -rc suffix (starting with rc0), signed, pushed to github, and marked under releases as
"pre-release". The release notes on github will contain the CHANGELOG contents for the running
rc series. Releases shall be pushed to branch coverity_scan, to inititiate a scan.

An example can be found here:

<https://github.com/01org/tpm2-tools/releases/tag/2.1.0-rc0>

Release candidates will also be announced on the
[mailing list](https://lists.01.org/mailman/listinfo/tpm2). When a rc has gone 1
week without new changes, a release will be conducted.

When a release is cut, the process is the same as an rc, with the exception that it is
not marked as "pre-release" on github. The release notes should include everything from
the last release to the latest release.

### Version Information

Releases shall be tagged following semantic version guidelines found at:
http://semver.org/

Versions after v1.1.0 will no longer have the "v" prefix. Autoconf now sets
the VERSION #define based on the output of git describe. See commit 2e8a07bc
for the details.

Version tags after v1.1.0 shall be signed. Valid known public keys can be reached by
referencing the annotated tags listed below:

william-roberts-pub

### Verifying tags

Import the key into your keyring:
```
$ git show [annotated-tag-name] | gpg --import
```

**Example**:
```
$ git show william-roberts-pub | gpg --import
```

Verify the release tag:
```
$ git tag --verify [signed-tag-name]
```

### Signing Release Tags

Ensure you have a key set up:
```
$ gpg --list-keys
```

If you don't generate one:
```
$ gpg --gen-key
```

Add that key to the gitconfig:
```
$ git config user.signingkey [gpg-key-id]
```

Make sure that key is reachable as an object in the repository:
```
$ gpg -a --export [gpg-key-id] | git hash-object -w --stdin [object SHA]
$ git tag -a [your-name-here]-pub [object SHA]
```

Make sure you push that tag:
```
$ git push origin [your-name-here]-pub
```
**NOTE**: this assumes origin is the tpm2-tools official repo.

After that, you can sign tags:
```
$ git tag --sign [signed-tag-name]
```

Push the tag to the repo:
```
$ git push origin [signed-tag-name]
```
**NOTE**: this assumes origin is the tpm2-tools official repo.

### Making a GitHub release.

1. Create a release using the signed release tag.
2. Add to the binary file section:

    1. A release tarball from `make dist`.
    2. A detached signature for the tarball made via:
      `gpg --armor --detach-sign <tarball>`

A lot of this git/gpg information was edited from:
<https://blog.thesoftwarecraft.com/2013/03/signing-git-tags.html>
