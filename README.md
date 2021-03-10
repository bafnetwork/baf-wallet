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

## Timeline
- {{[[table]]}}
    - **Phase** 
        - **Task**
            - **Hours Planned**
                - **Assignee**
                    - **Hours Taken**
    - Phase 0
        - All Tasks
            - 100 hr, total compensation: $7,000 
        - {{[[TODO]]}} [[ORY Kratos + Oathkeeper automation]]
            - 20 
        - {{[[TODO]]}} Build, test, upstream Kratos rust client via openapi-codegen
            - 20
        - {{[[TODO]]}} Keystore: Encryption
            - 8
        - {{[[TODO]]}} Keystore: get + set keys
            - 8
        - {{[[TODO]]}} Create Accounts
            - 6
        - {{[[TODO]]}} Recv, Sign, respond transaction hashes
            - 6
        - {{[[TODO]]}} Use Kratos sessions to extract user ID from signature requests
            - 4
        - {{[[TODO]]}} CLI: sign into Kratos
            - 6
        - {{[[TODO]]}} CLI: build + request signature for simple “send money” transactions
            - 4
        - {{[[TODO]]}} CLI: send signed transaction to NEAR blockchain
            - 2
        - Slack
            - 16
    - Phase 1
        - All Tasks
            - 121 hr, total compensation: $8,470
        - {{[[TODO]]}} Wallet JSON-RPC Spec
            - 20
        - {{[[TODO]]}} Implement Wallet JSON-RPC
            - 30
        - {{[[TODO]]}} Unit tests for JSON-RPC
            - 21
        - {{[[TODO]]}} Integration Tests for JSON-RPC
            - 11
        - {{[[TODO]]}} JS client library
            - 20
        - {{[[TODO]]}} Setup React Client Library + Skelton React Hooks
            - 2
        - {{[[TODO]]}} Add email + password form and connect with JSON-RPC
            - 4
        - {{[[TODO]]}} Create a dashboard to view balances and access keys
            - 9
        - {{[[TODO]]}} Styling
            - 4
        - {{[[TODO]]}} Handling user sessions and local storage
            - 4
        - {{[[TODO]]}} Accept Cookies popup 
            - 2
    - Phase 2
        - All Tasks
            - 84-104 hr, total compensation: $5,880 - $7,280 
        - {{[[TODO]]}} Sign in with OAuth Providers (Google, Facebook, Etc)
            - 4
        - {{[[TODO]]}} Integrate user testing feedback from phase 1
            - 50
        - {{[[TODO]]}} React SDK
            - 20
        - {{[[TODO]]}} More User Testing
            - 30
    - Phase 3
        - Hardening
            - Unknown
        - Audit
            - Unknown
        - Integrate user testing feedback from phase 2
            - 30-50
    - Phase 4
        - get 25 BAF members to use it and provide feedback
            - 20-40
        - Iterate on BAF member feedback
            - 15-30
        - get a real application to integrate it in their stack
            - Unknown
