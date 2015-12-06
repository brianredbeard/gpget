## GPGet / Gurl

### About

The purpose of this utility is to securely retrieve URLs for use in computing
environments.  A design pattern has become to use the utility `curl` to
retreive a remote endpoint and directly pipe this into a shell interpreter.
While this provides for a distinct ease of use and the ability to change
runtime image based server deployments, it is of dubious security.

## Mechanism

Through a series of well formed URIs we attempt a series of HTTP GET requests
to retrieve both a desired endpoint as well as a series of extensions used for
the attestation of that file.  The two standard extensions for these files are
`.sig` and `.asc`.  `.sig` files are binary based GPG/PGP signatures while
`.asc` files are Base64 encoded armored signatures.  In both cases the
signature files are "detached" and created in compliance with RFC XXXX.

