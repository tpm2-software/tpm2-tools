# Security Policy

## Supported Versions

Currently supported versions:

| Version | Supported          |
| ------  | ------------------ |
| < 5.0   | :x:                |
| >= 5.0  | :white_check_mark: |

## Reporting a Vulnerability

### Reporting

Security vulnerabilities can be disclosed in one of two ways:
- GitHub: *preferred* By following [these](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) instructions.
- Email: A descirption *should be emailed* to **all** members of the [MAINTAINERS](MAINTAINERS) file to coordinate the
disclosure of the vulnerability.

### Tracking

When a maintainer is notified of a security vulnerability, they *must* create a GitHub security advisory
per the instructions at:

  - <https://docs.github.com/en/code-security/repository-security-advisories/about-github-security-advisories-for-repositories>

Maintainers *should* use the optional feature through GitHub to request a CVE be issued, alternatively RedHat has provided CVE's
in the past and *may* be used, but preference is on GitHub as the issuing CNA.

### Publishing

Once ready, maintainers should publish the security vulnerability as outlined in:

  - <https://docs.github.com/en/code-security/repository-security-advisories/publishing-a-repository-security-advisory>

As well as ensuring the publishing of the CVE, maintainers *shal*l have new release versions ready to publish at the same time as
the CVE. Maintainers *should* should strive to adhere to a sub 60 say turn around from report to release.
