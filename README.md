# Anonymous credential schemes based on emmy crypto library  [![Build Status](https://circleci.com/gh/emmyzkp/emmy.svg?style=svg)](https://circleci.com/gh/emmyzkp/emmy)

This repository contains implementations of several cryptographic schemes for 
**anonymous credentials**. 

It relies heavily on the [core emmy crypto library](https://github.com/emmyzkp/crypto)
 for building  protocols/applications based on 
zero-knowledge proofs (ZKPs). If you are interested in cryptographic 
primitives, commitments, groups and zero-knowledge protocols supporting 
anonymous credentials schemes implemented here, please refer to the core 
library. 

For a short introduction to anonymous credentials, please refer to our 
[Wiki pages](https://github.com/emmyzkp/emmy/wiki/Anonymous-credentials).

## Notice
_This project is a work in progress. It can be used to allow 
applications to provide anonymous credentials as a proof of concept and for 
research purposes. As such, it **should never be used in production**._ 

> The APIs of anonymous authentication schemes are **not stable** yet - they 
are expected to undergo major changes, and may be changed at any point.

## Contents
<!-- toc -->
- [Supported cryptographic schemes](#supported-cryptograhpic-schemes)
- [Core aspects](#core-aspects)
  * [Communication](#communication)
- [Installation](#installation)
- [Emmy CLI tool](#using-the-emmy-cli-tool)
  * [Emmy server](#emmy-server)
  * [Emmy clients](#emmy-clients)
  * [TLS support](#tls-support)
- [Mobile clients](#mobile-clients)
- [Roadmap](#roadmap)
- [References](#references)
<!-- tocstop -->

## Supported cryptographic schemes  
* Pseudonym system [1] offered in &#8484;<sub>p</sub> and EC groups
* Camenisch-Lysyanskaya anonymous credentials [2][3] - work in progress

## Core aspects
In all implemented schemes, we use the notion of _clients_ (provers) that 
request issuance of anonymous credentials, or authentication with 
anonymous credentials, to  the _server_ (verifier). The server is typically 
an organization supporting anonymous authentication to their existing 
services, while clients are users of these services.

### Communication
All anonymous credentials schemes in this repository are complete with 
communication layer supporting execution of the schemes over the network. 

Communication between clients and the server is based on 
[Protobuffers](https://developers.google.com/protocol-buffers/)
and [gRPC](http://www.grpc.io/). 

# Installation
## Prerequisites
* go 1.11+

To install emmy anonymous authentication schemes, run 

```
$ go get -u github.com/emmyzkp/emmy
```

This should give you the `emmy` executable in your `$GOBIN`.
You can run the unit tests to see if everything is working properly by 
navigating to root of the project and running

```
$ go test ./...
```

# Using the emmy CLI tool

Below we provide some isntructions for using the `emmy` CLI tool. You can type `emmy` in the terminal to get a list of available commands and subcommands, and to get additional help.

Emmy CLI offers the following commands:
* `emmy server` (with subcommand `cl`, _TODO_: subcommands `psys` and `ecpsys`)
* `emmy generate` (with subcommand `cl`)
* `emmy client` (_TODO_)

## Emmy server

Emmy server waits for requests from clients (provers) and starts verifying them.
It is capable of serving (verifying) thousands of clients (provers) 
concurrently.

 Note that Emmy server connects to a redis database in order to verify the 
 registration keys, provided in the nym generation process.
 Redis is expected to run at localhost:6379.

```bash
$ emmy server              # prints available subcommands
$ emmy server cl --help    # prints subcommand flags, their meaning and default values
```

To start emmy server with the default options, run 

```bash
$ emmy server cl        # starts emmy server with default settings
```

Alternatively, you can control emmy server's behavior with the following options (specified as command line flags):
1. **Port**: flag *--port* (shorthand *-p*), defaults to 7007.

    Emmy server will listen for client connections on this port. Example: 
    ```bash
    $ emmy server start --port 2323   # starts emmy server that listens on port 2323
    $ emmy server start -p 2323       # equivalently
    ```
2. **Logging level**: flag *--loglevel* (shorthand *-l*), which must be one of `debug|info|notice|error|critical`. Defaults to `ìnfo`.

    For development or debugging purposes, we might prefer more fine-grained logs, in which case we would run:
    ```bash
    $ emmy server start --loglevel debug # or shorthand '-l debug'
    ```
3. **Log file**: flag *--logfile*, whose value is a path to the file where emmy server will output logs in addition to standard output. If the file does not exist, one is created. If it exists, logs will be appended to the file. It defaults to empty string, meaning that the server will not write output to any file.

    Example:
    ```bash
    $ emmy server start --loglevel debug --logfile ~/emmy-server.log
    ```

4. **Certificate and private key**: flags *--cert* and *--key*, whose value is a path to a valid certificate and private key in PEM format. These will be used to secure communication channel with clients. Please refer to [explanation of TLS support in Emmy](#tls-support) for explanation.

5. **Address of the redis database**: flag *--db* of the form *redisHost:redisPort*, which points
 to a running instance of redis database that holds [registration keys](#registration-keys). 
 Defaults to *localhost:6379*.

Starting the server should produce an output similar to the one below:

```
(1) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Instantiating new protocol server
(2) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Successfully read certificate [test/testdata/server.pem] and key [test/testdata/server.key]
(3) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ NOTI  gRPC Services registered
(4) [server][Mon 25.Sep 2017,14:11:041] EnableTracing ▶ NOTI  Enabled gRPC tracing
(5) [server][Mon 25.Sep 2017,14:11:041] Start ▶ NOTI  Emmy server listening for connections on port 7007
```

Line 1 indicates that the emmy server is being instantiated. Line 2 informs us about the server's certificate and private key paths to be used for secure communication with clients. Line 3 indicates that gRPC service for execution of crypto protocols is ready, and Line 4 tells us that gRPC tracing (used to oversee RPC calls) has been enabled. Finaly, line 5 indicates that emmy server is ready to serve clients.

When a client establishes a connection to emmy server and starts communicating with it, the server will log additional information. How much gets logged depends on the desired log level. 

You can stop emmy server by hitting `Ctrl+C` in the same terminal window.

#### Registration keys

Emmy server verifies registration keys provided by clients when initiating the nym generation procedure. A separate server is expected to provide registration keys to clients via another channel (e.g. QR codes on physical person identification) and save the generated keys to a registration database, read by the Emmy server.

## TLS support
Communication channel between emmy clients and emmy server is secure, as it enforces the usage of TLS. TLS is used to encrypt communication and to ensure emmy server's authenticity.

By default, the server will attempt to use the private key and certificate in `test/testdata` directory. The provided certificate is self-signed, and therefore the clients can use it as the CA certificate (e.g. certificate of the entity that issued server's certificate) which they have to provide in order to authenticate the server.
 >**Important note:** You should never use the private key and certificate that comes with this repository when running emmy in production. These are meant *for testing and development purposes only*.

In a real world setting, the client needs to keep a copy of the CA certificate which issued server's certificate. When the server presents its certificate to the client, the client uses CA's certificate to check the validity of server's certifiacate.

To control keys and certificates used for TLS, emmy CLI programs use several flags. In addition to those already presented in this document, `emmy server` supports the following flags:

* `--cert` which expects the path to server's certificate in PEM format, 
* `--key` which expects the path to server's private key file.

On the other hand, we can provide `emmy client` with the following flags:
* `--cacert`, which expects the path to certificate of the CA that issued emmy server's certificate 
(in PEM format). Again, if this flag is omitted, the certificate in `test/testdata` directory is used.
* `--servername`, which instructs the client to skip validation of the server's hostname. In the 
absence of this flag, client will always check whether the server's hostname matches 
the common name (CN) specified in the server's certificate as a part of certificate validation. For 
development purposes, hostname and server's CN will likely not match, and thus it is convenient to 
provide a `--servername` flag with the value matching the CN specified in the server's certificate.
* `--syscertpool`, which tells the client to look for the CA certificate in the host system's 
certificate pool. If this flag is provided, the presence of `--cacert` or `--servername` flags 
will be ignored. In addition, the CA certificate needs to be put in the system's default 
certificate store location beforehand.
  
  To give you an example, let's try to run an emmy client against an instance of emmy server that uses the self-signed certificate shipped with this repository. The hostname in the certificate is *localhost*, but the server is deployed on a host other than localhost (for instance, *10.12.13.45*). When we try to contact the server withour the *--insecure* flag, here's what happens:

  ```bash
  $ emmy client --server 10.12.13.45:7007 schnorr

  2017/09/13 12:48:47 [client] 12:48:47.232 GetConnection ▶ INFO 001 Getting the connection
  Cannot connect to gRPC server: Could not connect to server 10.12.13.45:7007 (x509: cannot validate certificate for 10.12.13.45 because it doesnt contain any IP SANs)
  ```

  Now let's include the *--insecure* flag, and the (insecure) connection to the server is now successfully established.

  ```bash
  $ emmy client --server 10.10.43.45:7007 --insecure schnorr

  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ INFO 001 Getting the connection
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 002 ######## You requested an **insecure** channel! ########
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 003 As a consequence, server's identity will *NOT* be validated!
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 004 Please consider using a secure connection instead
  2017/09/14 09:02:01 [client] 09:02:01.162 GetConnection ▶ NOTI 005 Established connection to gRPC server
  ```

# Mobile clients
This repository comes with a compatibility layer (see `anauth/compat` package) 
providing wrapper types that can be used for generating language bindings for 
anonymous credentials clients on Android or iOS mobile platforms. 

# Documentation
* [Developing Emmy (draft)](./docs/develop.md) 

# Roadmap

 * Improve the database layer supporting persistence of cryptographic material (credentials, pseudonyms, ...)
 * Refactor Camenisch-Lysyanskaya scheme (database records, challenge generation ... )
 * Additional proofs for Camenisch-Lysyanskaya scheme (range proof for attributes ... )
 * Revocation for Camenisch-Lysyanskaya scheme
 * Attribute types in Camenisch-Lysyanskaya scheme (string, int, date, enum)
 * Performance optimization (find bottlenecks and fix them)
 * Efficient attributes for anonymous credentials [2]
 * Camenisch-Lysyanskaya scheme based on pairings [3]

# References

[1] A. Lysyanskaya, R. Rivest, A. Sahai, and S. Wolf. Pseudonym systems. In 
Selected Areas in Cryptography, vol. 1758 of LNCS. Springer Verlag, 1999.

[2] Camenisch, Jan, and Anna Lysyanskaya. "Signature schemes and anonymous 
credentials from bilinear maps." Annual International Cryptology Conference. 
Springer, Berlin, Heidelberg, 2004.

[3] Camenisch, Jan, and Thomas Groß. "Efficient attributes for anonymous 
credentials." Proceedings of the 15th ACM conference on Computer and communications security. ACM, 2008.
