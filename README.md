# BAF Progressive Wallet

whitelabel optionally-custodial hosted wallet for the NEAR blockchain as described by [this article](https://medium.com/nearprotocol/on-usability-of-blockchain-applications-398963798ab3)

rn this is just the [hyper-rs hello world example](https://hyper.rs/guides/server/hello-world/). Eventually we'll scope out how to make it an API.

## Design Priorities

1. Minimalism - this thing should three things and only those three things - authenticate users, sign transactions, and store keys. There will likely only be that many endpoints, and as a result we don't need a full-blown web framework. We also are only storing keys and authentication-related information (email / hashed and salted password, etc), so we are going to use a key-value database.