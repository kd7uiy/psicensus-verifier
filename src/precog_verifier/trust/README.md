# Trust directory

Self-signed root certificates (DER) of the pinned RFC 3161 timestamp authorities, one file per root, named
`<sha256 of the DER>.der`. The `rfc3161` plugin only ever opens a file whose name is a `root_sha256` pinned by
a release manifest or a receipt, and re-checks that the file's hash equals its name.

| File (hash prefix) | Certificate | Where it came from |
|---|---|---|
| `552f7bdc...` | DigiCert Trusted Root G4 | `cacerts.digicert.com` (also in the Mozilla bundle) |
| `2bcbbfd6...` | GlobalSign Timestamping Root R45 | the CA Issuers URL inside GlobalSign's tokens (`secure.globalsign.com/cacert/timestamprootr45.crt`); not in the Mozilla bundle, compare the fingerprint with GlobalSign's repository page |
| `b676f2ed...` | Certum Trusted Network CA 2 | `repository.certum.pl` (also in the Mozilla bundle) |

These are public certificates. Nothing private belongs in this directory. Adding a root is adding a new
authority (new `id`) to a release manifest.
