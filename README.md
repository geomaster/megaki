# Megaki Reference Implementation

**Megaki** is a toy cryptographically secure protocol and reference
implementation developed by me in order to brush up on my systems programming and
cryptography knowledge. Megaki was envisioned as a replacement of TLS/SSL in some
narrow use-cases, namely, when the server certificate can be hard-coded into the
client, when the underlying data fits a request-response pattern, etc. It is
significantly less flexible and very likely insecure by design, due to my
experience and not being reviewed by any credible third-party.

It uses RSA-OAEP for initial symmetric key exchange and identity verification,
switching to AES-CBC with HMAC-SHA256 for actual data afterwards.

**Please don't use this in production! Neither the protocol or the implementation
have been audited, and they have been developed as a learning exercise.**

## Contents

The code in this repository contains the following components:

    * **MKD**. This is the daemon listening for incoming connections. Its role is
      to accept a connection, handle the wrapping/unwrapping of the Megaki
      protocol, and run a PHP script which should, given a plaintext request,
      return the plaintext response for a given packet.

    * **libsazukari**. This is the client library that communicates with MKD
      using the Megaki protocol. In `tests/playground.c`, there is an example of
      its usage. Also includes a JNI binding buildable using the Android NDK
      (Native Development Kit), for usage in Android apps.

    * **PHP userspace**. A simple "Hello, world" PHP script that acts as the
      "application layer" server with which communication is being done.

### MKD

MKD is, by far, the most complex component of the three. It's organized in
layers, and layers have cryptic names, so here are their names and descriptions:

    * **Yugi**. Bottom layer of the daemon which manages the connections via
      libuv and runs the main event loop (like node.js). It also handles closed
      connections, timeouts, graceful failure on errors on all operations, etc.
      The actual data read and written to and from the sockets is delegated to
      Yami.

    * **Yami**. Threadpool-based crypto powerhouse, which handles the actual
      handshake via the Megaki protocol, runs integrity checks, provides session
      resumption ability, and encryption/decryption of the application-layer data
      after a session is established. Yami operates on streams of data and does
      not assume a networking environment, ensuring full separation. The
      plaintext of the requests and responses is delegated to Pegasus.

    * **Pegasus**. Keeps a pool of worker processes running the PHP binary, to
      which plaintext requests are sent and plaintext responses retrieved.
      Handles restarting failed workers and communication between them.

    * **Arcangelo**. PHP shell running an event loop inside a worker PHP process,
      that can accept requests in plaintext, run a user-provided PHP script and
      return the response in plaintext.

## Building/running

Unfortunately, this is a fairly old project of mine that I've uploaded to GitHub
due to its historic significance :) There should be no problems running `make` to
build, but some system adjustments perhaps need to be done (installing `libuv`,
for example).

If you have a problem building or getting the code to run, contact me and I'll
try and help you with what I can remember.




