# Release Process
This document describes the overall release process of the tpm2-tools project.

# Milestones
All releases should have a milestone used to track the release. If the release version is not known, as covered in [Version Numbers](#Version Numbers),
then an "x" may be used for the unknown number, or the generic term "next" may be used. The description field of the milestone will be used to record
the CHANGELOG for that release. See [CHANGELOG Update](#CHANGELOG Update) for details.

# Release Lifecycle

All tpm2-tools project releases before 4.0 is considered legacy and is or will
be reaching end of life. Releases greater than 4.0 will always
**will be backwards compatible**.

Release will be conducted off the master branch and feature/bugfix only releas branches
can be created off of *master* and maintained as needed.
The majority of development will occur on *master* with tagged release numbers
following semver.org recommendations. This page explicitly does not formalize an
LTS support timeline, and that is intentional. The release schedules and
required features are driven by community involvement and needs. However,
milestones will be created to outline the goals, bugs, issues and timelines of
the next release.

## End Of Life versions
- [1.X](https://github.com/tpm2-software/tpm2-tools/tree/1.X)
- [2.X](https://github.com/tpm2-software/tpm2-tools/tree/2.X)
- [3.X](https://github.com/tpm2-software/tpm2-tools/tree/3.X)

# Release Information

Releases shall be tagged following semantic version guidelines found at:
  - http://semver.org/

The general release process will be one of two models:

- Tag releases off of branch master.
- Tag releases off of a release specific branch.
  - Release specific branch names can be for long-running major versions, IE 3.1, 3.2, 3.3, etc.
    and *SHALL* be named `<major-version>.X`.
  - Release specific branch names can be for long-running minor versions, IE 3.1.1, 3.1.2, etc.
    and *SHALL* be named `<major-version>.<minor-version>.X`.

Release candidates will be announced on the
[mailing list](https://lists.linuxfoundation.org/mailman/listinfo/tpm2). When a RC has gone 1
week without new substantive changes, a release will be conducted. Substantive
changes are generally not editorial in nature and they do not contain changes to
the CI system. Substantive changes are changes to the man-pages, code or tests.

When a release is cut, the process is the same as a Release Candidate (RC), with the exception that
it is not marked as "pre-release" on GitHub. The release notes should include everything from the
last release to the latest release.

# CHANGELOG Update
Before tagging the repository with the release version, the maintainer MUST update the CHANGELOG file with the contents from the description field
from the corresponding release milestone and update any missing version string details in the CHANGELOG and milestone entry.

The commit that updated the CHANGELOG entry will be tagged as the final release.

For a final release, change the version to the final release version (i.e: 3.0.5-rc3 -> 3.0.5) and
update the date. The commit for this change will be tagged as the release version.

## Testing
The tools code **MUST** pass the Github Actions CI testing and have a clean
Coverity scan result performed on every release. The CI testing not
only tests for valid outputs, but also runs tests uses clang's ASAN
feature to detect memory corruption issues.
  - BUG: Reconfigure Coverity: https://github.com/tpm2-software/tpm2-tools/issues/1727

## Release Checklist

The steps, in order, required to make a release.

- Ensure current HEAD is pointing to the last commit in the release branch.

- Ensure [Github Actions CI](https://github.com/tpm2-software/tpm2-tools/actions) has conducted a passing build of
  HEAD.

- Update version and date information in [CHANGELOG.md](CHANGELOG.md) **and** commit per the
  [CHANGELOG Update](#CHANGELOG Update) instructions.

- Create a signed tag for the release. Use the version number as the title line in the tag commit
  message and use the [CHANGELOG.md](CHANGELOG.md) contents for that release as the body.
  ```bash
  git tag -s <tag-name>
  ```

- Build a tarball for the release and check the dist tarball. **Note**: The file name of the tarball
  should include a match for the git tag name.
  ```bash
  make distcheck
  ```

- Generate a detached signature for the tarball.
  ```bash
  gpg --armor --detach-sign <tarball>
  ```

- Push **both** the current git HEAD (should be the CHANGELOG edit) and tag to the release branch.
  ```bash
  git push origin HEAD:<release-branch>
  git push origin <tag-name>
  ```

- Verify that the Github Actions CI build passes. **Note**: Github Actions CI will have two builds, one for the
  push to master and one for the tag push. Both should succeed.

- Create a release on [Github](https://github.com/tpm2-software/tpm2-tools/releases),
  using the `<release-tag>` uploaded. If it is a release candidate, ensure you check the "pre-release"
  box on the GitHub UI. Use the [CHANGELOG.md](CHANGELOG.md) contents for
  that release as the message for the GitHub release. **Add the dist tarball and signature file
  to the release**.

- Update the [dependency-matrix](https://tpm2-software.github.io/versions/)
  ensuring that the CI is building against a released version of:
  - [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd)
  - [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

  Configuration can be modified via [docker-prelude.sh](.ci/docker-prelude.sh).

- After the release (not a release candidate) add a commit to master updating the News section of
  the [README](README.md) to point to the latest release.

- Send announcement on [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/tpm2).


## Historical Version Information

Versions after v1.1.0 will no longer have the "v" prefix. Autoconf now sets
the VERSION #define based on the output of git describe. See commit 2e8a07bc
for the details.

Version tags after v1.1.0 shall be signed.

## Verifying git signature

Valid known public keys can be reached by
referencing the annotated tags listed below:

| Tag | Fingerprint |
| ------------- | ------------- |
| idesai-pub  | [6313e6dc41aafc315a8760a414986f6944b1f72b](https://keys.openpgp.org/vks/v1/by-fingerprint/6313E6DC41AAFC315A8760A414986F6944B1F72B) |
| william-roberts-pub | [5b482b8e3e19da7c978e1d016de2e9078e1f50c1](https://keys.openpgp.org/vks/v1/by-fingerprint/5B482B8E3E19DA7C978E1D016DE2E9078E1F50C1)|
| javier-martinez-pub | [D75ED7AA24E50CD645C6F457C751E590D63F3D69](https://keys.openpgp.org/vks/v1/by-fingerprint/D75ED7AA24E50CD645C6F457C751E590D63F3D69)|
| joshua-lock-pub | [5BEC526CE3A61CAF07E7A7DA49BCAE5443FFFC34](https://keys.openpgp.org/vks/v1/by-fingerprint/5BEC526CE3A61CAF07E7A7DA49BCAE5443FFFC34)|
| ajay-kish-pub |[6f72a30eea41b9b548570ad20d0db2b265493e29](http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x6f72a30eea41b9b548570ad20d0db2b265493e29)|
| juergen-repp-pub |[7A8F470DA9C8B2CACED1DBAAF1B152D9441A2563](https://keys.openpgp.org/vks/v1/by-fingerprint/7A8F470DA9C8B2CACED1DBAAF1B152D9441A2563)|
| andreas-fuchs-pub |[D533275B0123D0A679F51FF48F4F9A45D7FFEE74](https://keys.openpgp.org/vks/v1/by-fingerprint/D533275B0123D0A679F51FF48F4F9A45D7FFEE74)|

or via a PGP public keyring server like:
  - http://keyserver.pgp.com/vkd/GetWelcomeScreen.event

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

# Local Release Configuration

Below you will find information how to configure your machine locally to conduct releases.

## Signing Key Setup

Signing keys should have these four properties going forward:
  - belong to a project maintainer.
  - be discoverable using a public GPG key server.
  - be [associated](https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/)
    with the maintainers GitHub account.
  - be discoverable via an annotated tag within the repository itself.

Ensure you have a key set up:
```
$ gpg --list-keys
```

If you don't generate one:
```
$ gpg --gen-key
```

Add that key to the gitconfig:
```bash
git config user.signingkey [gpg-key-id]
```

Make sure that key is reachable as an object in the repository:
```bash
gpg -a --export [gpg-key-id] | git hash-object -w --stdin [object SHA]
git tag -a [your-name-here]-pub [object SHA]
```

Make sure you push the tag referencing your public key:
```bash
git push origin [your-name-here]-pub
```

Make sure you publish your key by doing:
  - http://keyserver.pgp.com/vkd/GetWelcomeScreen.event
    - Select "Publish your key".
    - Select "Key block"
    - Copy and paste the output of `gpg --armor --export <key-id>`
    - Validate your email account.

After that, you can sign tags:
```bash
git tag --sign [signed-tag-name]
```
