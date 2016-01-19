## GPGet 

### About

The purpose of this utility is to securely retrieve URLs for use in computing
environments.  A design pattern has become to use the utility `curl` to
retreive a remote endpoint and directly pipe this into a shell interpreter.
While this provides for a distinct ease of use and the ability to change
runtime image based server deployments, it is of dubious security.

### Why?

Increasingly users are implementing services on untrustworthy networks. Let's
take the case of public utility computing as prophesized by John McCarthy (aka
Amazon AWS, GCE, etc).  One of the core services provided by these services
is that of "object storage", the ability to host a file an provide access to
it via a services interface (generally `HTTP`).  While wonderful for building
highly scalable network services, it is problematic in that there is no
attestation around access or modification to the files.  Surely one could hash
every file uploaded and verify the hashes, but when Alice is trying to talk to
Bob they can't rule out that Mallory is a state actor.  In this case, they need
a strong mechanism of attesting that their files have not been modified on
storage or in transit.  TLS can only protect against the _transport_ security
not the on disk case.  This it is desireable to take this to the lowest common
denominator.  Why not build a system even usable on _hostile_ networks?  This
is the goal of *GPGet*.

#### Mechanism

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

#### Trust

The GPG trust model is patterened after the APPC container specification.
Originally GPG utilized the standard keychain mechanism generally used by
most PGP/GPG based utilities.  The reality was that the actual use pattern
follows much more closely to that of the CA trust model of openssl.  The
result is the ability to trust a series of signatures solely through the
use of file operations and without execution of any GPG/GPG2 binary directly.

### Examples

#### Authorized Keys
Given a situation where users want to provide access to a host without the full
feature set of a centralized AAA (authentication, authorization, and 
accounting) system a streamlined mechanism for securely providing this access
can be achieved with GPGet.

First, one would generate an ssh keypair with which to access a host:

```
$ ssh-keygen   -b 8192 -t ed25519 -C "Deployment key for host foo.example.com" -f  foo 
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in foo.
Your public key has been saved in foo.pub.
The key fingerprint is:
SHA256:agsS0ZY7Uh579d2NjXO1NSeUlzEU/8qFF5jQigzrhs8 Deployment key for host foo.example.com
The key's randomart image is:
+--[ED25519 256]--+
|           .. o*+|
|   . . .    .o+.+|
|  . *   = . .o.+=|
|   = + o + o . BO|
|  o = + S . . *.B|
|   o + +     . * |
|  . . *       o  |
|   . o E         |
|      .          |
+----[SHA256]-----+
```

Next, the public key will be signed by the build system (or the security team
to truely do it "right") with a detached signature.  Both armored ASCII and
binary signatures are supported, though armored is the default:

```
$ gpg -b -u jenkins@example.com -a  foo.pub 
$ cat foo.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM07Yybpo5KPALuqpTffHTyAvUiJclIiBFU6jAY4xGAO Deployment key for host foo.example.com
$ cat foo.pub.asc 
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQIcBAABAgAGBQJWnodYAAoJELlooAvCoMRn29QP+wbvQddEoXSfONow4zk/HgBM
8PcxTRhAVsGgo77evjKE1TUWQvr4gxS5kX73mrnMlhnIseCCj2IOs7Pf8bqoXAlB
q3v6aRGXCsvc2tN0TQtxi0qddcuc38ZCXkdUOJ+1bvOsdkyQ1pPfx3Ra9K/kadAO
5EMvMjnZjbzDAkfr4SeGXZXbMZiNLSACoe5wB45hg+5XpwtEc0dJwyyl2JZmfrND
P0AzxRLdZbXKmn0xjahBwp0UhojrXDYVsiZJDIBo6tW0NVDsuNFsKm81teLSh4Lj
uItlVg45eVE3TbJeAQsm9/aIOCRBvMkP/XFV5wxcd1Bge4rnyyneHkozLyoAm9Pe
l+bAmiJerCUjoeY4sNmj01gLN7QHAdEftaM0p8iyad8Eum8LZo2extYlfw1+nAbN
RxToPmzdrO9Azfe/Q4OgwEOP3SHbKTRzI9vA2SaOpMF1IIUt0ziLc4l7hyJJ7Tk7
k96/BmObDcGmj/bbuj9UsCcgIsOToO7NUjs3bnkPFUCJi7YXT+ZGu3L4NHebzAhl
sXozQYuarUzn3JSF7Xn7NLiLXWH5hcoeyBLkGoZK+vv9w01L9e/9EN5kA/OROEf9
h306yzg1fTRa59Ia9iysjmqr6hRF0glzbqNiG3QBf9ibspyxCs2MeVabsw8MM0p3
hk9TcKBRhDDCrF23eLFV
=8ouN
-----END PGP SIGNATURE-----
$ gpg --verify foo.pub.asc 
gpg: assuming signed data in `foo.pub'
gpg: Signature made Tue 19 Jan 2016 10:58:32 AM PST using RSA key ID C2A0C467
gpg: Good signature from "Jenkins Build System (Example, Inc) <jenkins@example.com>"
```

At this point, the private key can be placed in escrow and the public key and 
signature published to a generic web hosting service.  This could be anything
from Amazon S3, Google GCS, GitHub, etc.

From there the remote host could be deployed with a job that includes no public
keys for it's build user but instead a cron job which will run periodically,
retrieve those keys from the untrusted storage, and yet cycle keys as needed.

Imagine the following processes happening on provisioning:

```
$ gpg --import C2A0C467
gpg: key C2A0C467: public key "Jenkins Build System (Example, Inc) <jenkins@example.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
```

and a cron job calling the following command every five minutes

```
$ /usr/local/bin/gpget -k C2A0C467 -o /home/nobody/.ssh/authorized_keys --url http://s3.aws.amazon.com/examplebucket/foo.pub
```

This will continuously pull down that public key file, verify the GPG based
provinence of the file and only write it to the filesystem in the event that
it can successfully both download AND verify the signature.
