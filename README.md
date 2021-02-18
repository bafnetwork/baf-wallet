# BAF Wallet

Whitelabel optionally-custodial hosted wallet for the NEAR blockchain as described by [this article](https://medium.com/nearprotocol/on-usability-of-blockchain-applications-398963798ab3)


## Overview

At a high level, the BAF Wallet is a REST API with an `/rpc/` endpoint that exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) interface. It's built using [hyper](https://hyper.rs/guides/server/hello-world/) that uses [rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) as a persistent embedded data store. This removes a lot of the complexity we'd otherwise have if we were to use an external database and it makes the attack surface a lot smaller. For a more detailed description of the API, see [API.md](./API.md).

## Goals

1. Simplicity - should require the minimum amount of infrastructure to manage and be as predictable as possible when it comes to cost of ownership. In short, it should be as simple and easy as possible to use.
2. Minimalism - should do only three things and do them really well - store keys, authenticate users, and sign transactions. Anything else should be built atop this in a separate layer.
3. Security - It should go without saying that this is a custodial wallet, so it should be as secure as possible.

## Roadmap

Our roadmap takes the form of something we call a "Minimum Awesome Product map", or "MAP map" for short. It roughly follows the "MVP map" paradigm, but with an emphasis on making an awesome product, not just a viable one.

- Bronze 🥉
    - [ ] signup
    - [ ] login
        - [x] implement
        - [ ] [set JWT headers properly](https://github.com/bafnetwork/baf-wallet/issues/18)
    - [ ] [verifyEmail](https://github.com/bafnetwork/baf-wallet/issues/17)
    - [ ] create near accounts
	- [ ] implement near account creation via wallet's root account
        - [x] add owner's NEAR account via environment variables
        - [ ] [add endpoint that allows owner to authorize user to create their account exactly once](https://github.com/bafnetwork/baf-wallet/issues/7)
        - [ ] [add endpoint that allows user to create their account once authorized](https://github.com/bafnetwork/baf-wallet/issues/23)
    - [ ] signTx for transactions that don't contain data
        - [ ] figure out what needs to happen for this and add this functionality to a `signTx` RPC method
    - [ ] [use access keys proprely](https://github.com/bafnetwork/baf-wallet/issues/19)
        - [ ] create new ones for contract methods that haven't been used yet
        - [ ] use the access key with minimum permissions for a particular contract methods when signing transactions
    - [ ] [signTx for arbitrary transaction as byte string](https://github.com/bafnetwork/baf-wallet/issues/2)
    - [ ] implement another wallet account in near-api-js
	- https://github.com/near/near-api-js/blob/master/src/wallet-account.ts generates a new keypair literally every time the user signs in 
	- this doesn't fit with our JWT-oriented flow, so we'll want to implement a `HostedWalletConnection` that overrides the undesired behavior of `WalletConnection` and try to get it pushed upstream into `near-api-js`
    - [ ] addRootKey RPC for adding a public key to a contract account's ACL
    - [ ] removeRootKey RPC for removing a public key from a contract account's ACL
    - [ ] testing
        - [x] write basic integration tests for every HTTP endpoint
	- [ ] write basic integration tests for every `/rpc` method
	- [ ] [implement a harness for unit-testing HTTP handlers in `test_util.rs`](https://github.com/bafnetwork/baf-wallet/issues/20)
	- [ ] [implement a harness for unit-testing `/rpc` handlers in `test_util.rs`](https://github.com/bafnetwork/baf-wallet/issues/21)
	- [ ] write correctness unit tests for all handlers, both `/rpc` and HTTP
	- [ ] make sure that `/rpc` actually adheres to `JSON-RPC` spec
- Silver 🥈
    - [ ] add logging / tracing for all DB access
        - [ ] wrap DB access in async "getter" and "setter" fns that also log stuff
    - Better transaction signing
        - add all NEAR transaction types to transaction structs in util.rs
        - add EIP-721
	    - implement a new `serde` crate - `serde_eip721`
	    - Wrap Transaction type in a `TransactionToSign` enum that looks something like this:
	    ```rust
		enum TransactionToSign {
		  Eip712(Transaction),
		  Bytestring(Vec<u8>)
		}```
    - [ ] Sign in with OAuth Providers
    - [ ] React UI for BAF Wallet:
        - [ ] UI for signing in
        - [ ] Dashboard that shows:
            - [ ] all registered apps
            - [ ] allowed root public keys with an indicator saying if corresponding private key is custodial or non-custodial
            - [ ] all access public keys, with an indicator saying if corresponding private key is custodial or non-custodial
	    - [ ] UI for changing permissions of all registered apps, access keys, and root keys
    - [ ] example React app using BAF Wallet via near-api-js and a NEAR contract
- Gold 🥇
    - [ ] onboard.js integration
    - [ ] load testing
    - [ ] fuzz testing
    - [ ] some really nice API documentation
    - [ ] adversarial / penetration testing
    - [ ] security audit
    - [ ] performance optimization
- Beyond 🌟
    - [ ] social recovery
    - [ ] sharding, load balancing, key migration
    - [ ] make blockchain-agnostic + add support for other chains
    - [ ] metamask snapp

## Notes

* `sodiumoxide` depends on `libsodium`, which is written in C, so you might run into compilation trouble. If you do, I reccomend installing `pkg-config` and `libsodium` separately using using your prefered package manager (e.g. `sudo apt install pkg-config libsodium` on WSL/Ubuntu, `brew install pkg-config libsodium` on MacOS). Then set the env variable `SODIUM_USE_PKG_CONFIG=1` as documented [here](https://github.com/sodiumoxide/sodiumoxide#extended-usage) to make `sodiumoxide` use the libsodium installed in the previous step.
 do `source use_pkg_config.sh` to set this env variable automatically.
