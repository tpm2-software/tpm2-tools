## Release Instructions

The general release process will be to fork a branch at each major release followed by a ".X".
For example, the major version 2 branches will be 2.X. Release candidates (rc), will be tagged
using a -rc suffix (starting with rc0), signed, pushed to github, and marked under releases as
"pre-release". The release notes on github will contain the CHANGELOG contents for the running
rc series. Releases shall be pushed to branch coverity_scan, to initiate a scan.

An example can be found here:

<https://github.com/tpm2-software/tpm2-tools/releases/tag/2.1.0-rc0>

Release candidates will also be announced on the
[mailing list](https://lists.01.org/mailman/listinfo/tpm2). When a rc has gone 1
week without new changes, a release will be conducted.

When a release is cut, the process is the same as an rc, with the exception that it is
not marked as "pre-release" on github. The release notes should include everything from
the last release to the latest release.

### Updating the CHANGELOG for release candidates and final releases

When a first release candidate is cut, a new entry will be added to the CHANGELOG file. This
entry will have the release candiate version and the date on which the release candidate was
released. The entry will list all the changes that happened between the latest final release
and the first release candidate.

The commit that made the change will be tagged with a release version and a -rc0 suffix as an
indication that is not a final release but a first release candidate. If after a week the -rc
has no changes, then a final release can be made as explained above. But if changes are made,
then a new releases candidate will be released and the -rc suffix will be incremented.

For each release candidate, the changes that happened between the previous release candidate
will be appended to the CHANGELOG entry, and both the release candidate version and the date
of the release will be updated to reflect the latest release candidate.

The commit that updated the CHANGELOG entry will be tagged as the latest release candidate.

When a final version will be released, there will not be changes to append to the CHANGELOG
entry since otherwise a new release candidate should be cut. So only the release version and
date should be updated in the CHANGELOG.

The commit that updated the CHANGELOG entry will be tagged as the final release.

For a final release, change the version to the final release version (i.e: 3.0.5-rc3 -> 3.0.5)
and update the date. The commit for this change will be tagged as $version.

The format for the release entry in the CHANGELOG shall be the version date header, and a list of
change items, like so:

```
<VERSION> - <DATE>
  * item 1
  * item 2
  * ...
```

### Version Information

Releases shall be tagged following semantic version guidelines found at:
http://semver.org/

Versions after v1.1.0 will no longer have the "v" prefix. Autoconf now sets
the VERSION #define based on the output of git describe. See commit 2e8a07bc
for the details.

Version tags after v1.1.0 shall be signed. Valid known public keys can be reached by
referencing the annotated tags listed below:

- william-roberts-pub
- javier-martinez-pub
- joshua-lock-pub

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

## Testing
The tools code **MUST** pass the travis CI testing and have a clean
coverity scan result performed on every release. The CI testing not
only tests for valid outputs, but also runs tests uses clang's asan
feature to detect memory corruption issues.

### Making a GitHub release.

1. Create a release using the signed release tag.
2. Add to the binary file section:

    1. A release tarball from `make dist`.
    2. A detached signature for the tarball made via:
      `gpg --armor --detach-sign <tarball>`

A lot of this git/gpg information was edited from:
<https://blog.thesoftwarecraft.com/2013/03/signing-git-tags.html>
