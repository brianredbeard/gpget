## GPGet 

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
`.asc` files are Base64 encoded armored signatures.  *GPGget expects to
retrieve the armored `.asc` extention.*  The signature files are "detached" 
and created in compliance with RFC 4880.

This utility will download those files and operate largely as one would expect
`curl` to, only with the addition of GPG validation.  First, if the files fail
to pass GPG validation, the utility will exit on a non-zero error code.  This
is to ensure that a user can correctly operate using normal POSIX error
handling.  Next, as the files have passed validation, we achieve the next choice
in the program.  If the user has supplied no additional arguments, the utility
will output the data stream to STDOUT.   If the user has supplied to argument
`-O`, then the file will be written down to disk, and exit with a zero error 
code.  If the file cannot be written to disk, the utility will exit non-zero. 

In short, if there is any behavior which deviates from the basic pattern of 
"request a URI, validate it cryptographically, and pass the data to the users
desired location" the program will exit non-zero.

## Trust

The GPG trust model is patterened after the APPC container specification.
Originally GPG utilized the standard keychain mechanism generally used by
most PGP/GPG based utilities.  The reality was that the actual use pattern
follows much more closely to that of the CA trust model of openssl.  The
result is the ability to trust a series of signatures solely through the
use of file operations and without execution of any GPG/GPG2 binary directly.
