# BAF Wallet

Whitelabel optionally-custodial hosted wallet for the NEAR blockchain as described by [this article](https://medium.com/nearprotocol/on-usability-of-blockchain-applications-398963798ab3)


## Overview

At a high level, the BAF Wallet is a REST API with an `/rpc/` endpoint that exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) interface. It's built using [hyper](https://hyper.rs/guides/server/hello-world/) that uses [rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) as a persistent embedded data store. This removes a lot of the complexity we'd otherwise have if we were to use an external database and it makes the attack surface a lot smaller. For a more detailed description of the API, see [API.md](./API.md).

## Goals

1. Simplicity - should require the minimum amount of infrastructure to manage and be as predictable as possible when it comes to cost of ownership. In short, it should be as simple and easy as possible to use.
2. Minimalism - should do only three things and do them really well - store keys, authenticate users, and sign transactions. Anything else should be built atop this in a separate layer.
3. Security - It should go without saying that this is a custodial wallet, so it should be as secure as possible.

## Notes

* `sodiumoxide` depends on `libsodium`, which is written in C, so you might run into compilation trouble. If you do, I reccomend installing `pkg-config` and `libsodium` separately using using your prefered package manager (e.g. `sudo apt install pkg-config libsodium` on WSL/Ubuntu, `brew install pkg-config libsodium` on MacOS). Then set the env variable `SODIUM_USE_PKG_CONFIG=1` as documented [here](https://github.com/sodiumoxide/sodiumoxide#extended-usage) to make `sodiumoxide` use the libsodium installed in the previous step.
 do `source use_pkg_config.sh` to set this env variable automatically.

## Tasks

- Phase 0
    - [ ]  ORY Kratos + Oathkeeper automation
    - [ ]  Build, test, upstream Kratos rust client via openapi-codegen
    - [ ]  Keystore: Encryption
    - [ ]  Keystore: get + set keys
    - [ ]  Create Accounts
    - [ ]  Recv, Sign, respond transaction hashes
    - [ ]  Use Kratos sessions to extract user ID from signature requests
    - [ ]  CLI: sign into Kratos
    - [ ]  CLI: build + request signature for simple “send money” transactions
    - [ ]  CLI: send signed transaction to NEAR blockchain
- Phase 1
    - [ ]  Wallet JSON-RPC Spec
    - [ ]  Implement Wallet JSON-RPC
    - [ ]  Unit tests for JSON-RPC
    - [ ]  Integration Tests for JSON-RPC
    - [ ]  JS client library
    - [ ]  Setup React Client Library + Skelton React Hooks
    - [ ]  Add email + password form and connect with JSON-RPC
    - [ ]  Create a dashboard to view balances and access keys
    - [ ]  Styling
    - [ ]  Handling user sessions and local storage
    - [ ]  Accept Cookies popup 
- Phase 2
    - [ ]  Sign in with OAuth Providers (Google, Facebook, Etc)
    - [ ]  Integrate user testing feedback from phase 1
    - [ ]  React SDK
    - [ ]  More User Testing
- Phase 3
    - [ ] Hardening
    - [ ] Audit
    - [ ] Integrate user testing feedback from phase 2
- Phase 4
    - [ ] get 25 BAF members to use it and provide feedback
    - [ ] Iterate on BAF member feedback
    - [ ] get a real application to integrate it in their stack
