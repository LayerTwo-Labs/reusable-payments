# Reusable Payments

BIP47 reusable payment codes (v1 and v3) and BIP352 silent payments:
parsing/serialization, notification blinding, send/receive address
derivation, silent-payment address handling, and transaction scanning.

Wallet-agnostic — depends only on `bitcoin`.

## Build

* Install dependencies (rustup)
* Build with `cargo build`
* Test with `cargo test`
