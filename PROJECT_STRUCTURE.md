# Overview

This is a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) server built using [hyper](https://hyper.rs/guides/server/hello-world/) that uses [rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) as a persistent embedded data store. This removes a lot of the complexity we'd otherwise have if we were to use an external database and it makes the attack surface a lot smaller.

At a high level, when a JSON-RPC 2.0 request from some user `U` to sign some transaction `T` comes in, the following happens:

1. Hyper receives and parses the HTTP request
2. Some middleware will check authentication headers and deny access if they are invalid.
3. A new handler function is instantiated by hyper to handle that request
4. Inside the handler function instance:
   1. The JSON-RPC params are parsed
   2. The relavant RPC is executed by the handler, including any involved  database access, encryption, and/or audit tracing/logging
   3. The result is serialized and returned as an HTTP response from the handler
5. Once the handler returns, Hyper does the rest

## Architecture

The wallet has a few components:
* HTTP API - basically a bunch of HTTP handlers that may or may not make requests of its own to the NEAR blockchain
* JSON-RPC - one HTTP endpoint, `/rpc`, serves a `JSON-RPC` interface including all methdos used for signing transactions, approving transactions, and managing the ACL of public keys in the user's account, which on NEAR is a smart contract
* RocksDB - RocksDB manages its own thread pool separately from tokio, so [it's instantiated outside the tokio runtime](https://github.com/bafnetwork/baf-wallet/blob/89cd9c4a6635db786e2fb59a8c7b578b9ff8d3a3/src/main.rs#L143). A handle wrapped in an `Arc` is then passed into the request handler tasks spawned by hyper on the tokio runtime, which those tasks can use to access the database.


Another thing to note is the usage of blocking tasks - [blocking tasks must be used for blocking work](https://docs.rs/tokio/1.2.0/tokio/task/index.html#blocking-and-yielding) because asynchronous tasks in the tokio runtime should not block due to tokio relying on cooperative scheduling. Thus it's important to use blocking tasks for all of the following
* RocksDB goes to disk and does not expose an asynchronous API, so all DB access is blocking
* Cryptography, especially public-key cryptography, is computationally expensive, and so it can in some sense be seen as 'blocking'


A rough diagram of the architecture is shown below (TODO: this is kind of out of date and needs to be updated)


![diagram](diagram.png)


## Code Organization

TODO:
