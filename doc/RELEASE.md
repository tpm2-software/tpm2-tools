# Release Lifecycle

All tpm2-tools project releases before 4.0 is considered legacy and is or will
be reaching end of life. Releases greater than 4.0 will always
**will be backwards compatible**. Thus, based on the semver.org rules outlined,
pretty much dictates we will never be off of a 4.X version number. Because of
this, master will always be the *next* release, and bugfix only releases can be
branched off of *master* as needed. These patch level branches will be supported
on an as needed bases, since we don't have dedicated stable maintainers. The
majority of development will occur on *master* with tagged release numbers
following semver.org recommendations. This page explicitly does not formalize an
LTS support timeline, and that is intentional. The release schedules and
required features are driven by community involvement and needs. However,
milestones will be created to outline the goals, bugs, issues and timelines of
the next release.

## End Of Life versions
- [1.X](https://github.com/tpm2-software/tpm2-tools/tree/1.X)
- [2.X](https://github.com/tpm2-software/tpm2-tools/tree/2.X)
- [3.0.X](https://github.com/tpm2-software/tpm2-tools/tree/3.0.X)

## Near End of Life
- [3.0.X](https://github.com/tpm2-software/tpm2-tools/tree/3.0.X): EOL after
3.2.1 release.

## OpenSSL

tpm2-tools relies heavily on OpenSSL. OpenSSL will be EOL'ing 1.0.2 at the end
of 2019, see: https://www.openssl.org/blog/blog/2018/05/18/new-lts/. When this
occurs, we will remove OSSL 1.0.2 support from the tpm2-tools repository as
supporting an EOL crypto library is not a good idea.

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
[mailing list](https://lists.01.org/mailman/listinfo/tpm2). When a RC has gone 1
week without new substantive changes, a release will be conducted. Substantive
changes are generally not editorial in nature and they do not contain changes to
the CI system. Substantive changes are changes to the man-pages, code or tests.

When a release is cut, the process is the same as a Release Candidate (RC), with the exception that
it is not marked as "pre-release" on GitHub. The release notes should include everything from the
last release to the latest release.

## Updating the CHANGELOG for release candidates and final releases

When a first release candidate is cut, a new entry will be added to the CHANGELOG file. This
entry will have the release candidate version and the date on which the release candidate was
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

For a final release, change the version to the final release version (i.e: 3.0.5-rc3 -> 3.0.5) and
update the date. The commit for this change will be tagged as $version.

## Testing
The tools code **MUST** pass the Travis CI testing and have a clean
Coverity scan result performed on every release. The CI testing not
only tests for valid outputs, but also runs tests uses clang's ASAN
feature to detect memory corruption issues.
  - BUG: Reconfigure Coverity: https://github.com/tpm2-software/tpm2-tools/issues/1727

## Release Checklist

The steps, in order, required to make a release.

- Ensure current HEAD is pointing to the last commit in the release branch.

- Ensure [Travis](https://travis-ci.org/tpm2-software/tpm2-tools) has conducted a passing build of
  HEAD.

- Update version and date information in [CHANGELOG.md](CHANGELOG.md) **and** commit.

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

- Verify that the Travis CI build passes. **Note**: Travis will have two builds, one for the
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

- Send announcement on [mailing list](https://lists.01.org/mailman/listinfo/tpm2).


## Historical Version Information

Versions after v1.1.0 will no longer have the "v" prefix. Autoconf now sets
the VERSION #define based on the output of git describe. See commit 2e8a07bc
for the details.

Version tags after v1.1.0 shall be signed.

## Verifying git signature

Valid known public keys can be reached by
referencing the annotated tags listed below:

- william-roberts-pub
- javier-martinez-pub
- joshua-lock-pub
- idesai-pub

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
  - be [associated]((https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/))
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
