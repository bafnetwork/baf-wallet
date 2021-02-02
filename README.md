# BAF Wallet

whitelabel optionally-custodial hosted wallet for the NEAR blockchain as described by [this article](https://medium.com/nearprotocol/on-usability-of-blockchain-applications-398963798ab3)

rn this is just the [hyper-rs hello world example](https://hyper.rs/guides/server/hello-world/). Eventually we'll scope out how to make it an API.

## Goals

1. Minimalism - this thing should three things and only those three things - authenticate users, sign transactions, and store keys. There will likely only be that many endpoints, and as a result we don't need a full-blown web framework. We also are only storing keys and authentication-related information (email / hashed and salted password, etc), so we are going to use a key-value database.
2. Simplicity - should require the minimum amount of infrastructure to manage.

## Overview

This is a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) server built using [hyper](https://hyper.rs/guides/server/hello-world/) that uses [rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) as a persistent embedded data store. This removes a lot of the complexity we'd otherwise have if we were to use an external database and it makes the attack surface a lot smaller.

At a high level, when a JSON-RPC 2.0 request from some user `U` to sign some transaction `T` comes in, the following happens:

1. Hyper receives and parses the HTTP request
2. Some middleware will check authentication headers and deny access if they are invalid.
3. A new handler function is instantiated by hyper to handle that request
4. Inside the handler function instance:
   1. The JSOHN-RPC params are parsed
   2. The relavant RPC is executed by the handler, including any involved  database access, encryption, and/or audit tracing/logging
   3. The result is serialized and returned as an HTTP response from the handler
5. Once the handler returns, Hyper does the rest

![diagram](diagram.png)
