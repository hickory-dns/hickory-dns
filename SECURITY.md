# Security Policy

## Supported Versions

The Hickory DNS team fully supports the most recent minor release train and will consider patches to
prior versions depending on prevalence of the affected version(s) and severity of the reported
issue.  For example, if the most recent release is 0.24.1, we would provide a fix in a 0.24.x
release, but we might not backport the fix to 0.23.x.

## Reporting a Vulnerability

Please do not report vulnerabilities via public issue reports or pull requests. Instead, report
vulnerabilities via Github's private [report a vulnerability](https://github.com/hickory-dns/hickory-dns/security/advisories/new)
link. The Hickory DNS team will make every effort to respond to vulnerability disclosures within 5
working days. After initial triage, we will work with the reporting researcher on a disclosure
time-frame and mutually agreeable embargo date, taking into account the work needed to:

  * Identify affected versions
  * Prepare a fix and regression test
  * Coordinate response with other DNS vendors (if necessary)

After testing a fix and upon the end of the embargo date we will:

* Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db)
* Publish fixed releases on crates.io and deprecate prior releases as appropriate

**Please note that at this time, the Hickory DNS project is not able to offer a bug bounty.**
