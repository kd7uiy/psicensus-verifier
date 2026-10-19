# Security policy

## Reporting a vulnerability

Please report a suspected vulnerability privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting for this repository: open the repository's **Security** tab, choose
**Report a vulnerability**, and describe what you found. Include the version or commit, the steps to reproduce it,
and what you expect the impact to be.

Reports are read by the maintainers, who will reply there and agree a way to publish a fix and credit you if you wish.

## What is in scope

- A way to make the verifier accept data or a receipt that does not satisfy the format in `SPEC.md`, or reject data
  that does.
- A way to make the verifier misreport a result, crash on untrusted input, or read or write files outside the
  folders it is pointed at.

Questions about the study itself, or about how to use the verifier, are not security reports; use a normal issue.
