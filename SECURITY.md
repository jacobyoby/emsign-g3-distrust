# Security policy

## Scope
This repository holds **defensive** tooling and **public** indicators for the eight
compromised eMudhra/emSign G3 intermediate CAs (Mozilla Bug 2083449). It contains
**no private keys** and no material that enables forging certificates — by design.

## The underlying incident
The CA key compromise and related issues are tracked by the root programs, not here:
- Key compromise: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- CRL/OCSP availability (User-Agent filtering): https://bugzilla.mozilla.org/show_bug.cgi?id=2085612

Report new facts about the incident to those bugs / the relevant root program.

## Reporting an issue with this tooling
Open a GitHub issue for bugs, or for anything sensitive email the maintainer. Please do
**not** post recovered private keys, forged certificates, or other offensive material in
issues or pull requests — they will be removed.

## Responsible use
These tools help operators detect and distrust the compromised intermediates. Use them
only against systems you are authorized to inspect or administer.
