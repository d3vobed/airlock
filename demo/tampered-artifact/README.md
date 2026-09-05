# Tampered artifact

This directory contains `package.tgz`: an exact copy of
`demo/legitimate-package/package.tgz` (`@naijapay/payment-sdk@2.1.0`) with
**one byte flipped**.

Compare the SHA-256 digests:

    sha256sum demo/legitimate-package/package.tgz
    sha256sum demo/tampered-artifact/package.tgz

AIRLOCK rejects the tampered artifact: its digest no longer matches the
identity/passport recorded for the original artifact.

Regenerate with: `python -m demo.build_demos`