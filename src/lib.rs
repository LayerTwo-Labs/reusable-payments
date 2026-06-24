//! Reusable payments: BIP47 payment codes (v1/v3) and BIP352 silent payments.
//!
//! Wallet-agnostic primitives — payment-code parsing, notification blinding,
//! send/receive address derivation, silent-payment address handling, and
//! transaction scanning — operating purely on `bitcoin` types.

pub mod bip47;
