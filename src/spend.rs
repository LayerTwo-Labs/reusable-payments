//! Signing reusable-payments inputs of an already-built PSBT.
//!
//! The caller (a wallet) builds the transaction and supplies the recovered key
//! for each reusable input; this module finalizes those inputs. Silent-payment
//! outputs are taproot key-path spends whose output key *is* the recovered key
//! (BIP352), so they are signed with the key directly — **no BIP341 tweak**.

use bitcoin::{
    OutPoint, Script, TxOut, Weight, ecdsa,
    hashes::Hash as _,
    key::Keypair,
    psbt::Psbt,
    script::{Builder, PushBytesBuf},
    secp256k1::{Message, Secp256k1, SecretKey, Signing},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
    taproot,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpendError {
    #[error("input {input_index} has no prevout (missing witness_utxo / non_witness_utxo)")]
    MissingPrevout { input_index: usize },
    #[error("outpoint {outpoint} to sign is not present in the transaction")]
    OutpointNotInTx { outpoint: OutPoint },
    #[error("sighash computation failed: {0}")]
    Sighash(String),
    #[error("signature too large to encode in a scriptSig push")]
    SignaturePush,
}

/// Estimated satisfaction weight for a reusable input, for fee estimation when
/// adding it as a foreign UTXO to a transaction builder.
pub fn satisfaction_weight(spk: &Script) -> Weight {
    if spk.is_p2tr() {
        Weight::from_wu(66)
    } else if spk.is_p2wpkh() {
        Weight::from_wu(108)
    } else {
        Weight::from_wu(108 * 4)
    }
}

/// Finalize each input in `keys_by_outpoint` by signing it with its recovered
/// key, dispatching on the prevout script type. Inputs not listed are left for
/// the wallet's own signer.
pub fn sign_psbt_inputs<C: Signing>(
    psbt: &mut Psbt,
    keys_by_outpoint: &[(OutPoint, SecretKey)],
    secp: &Secp256k1<C>,
) -> Result<(), SpendError> {
    if keys_by_outpoint.is_empty() {
        return Ok(());
    }

    let prevouts = collect_prevouts(psbt)?;

    let targets = keys_by_outpoint
        .iter()
        .map(|(outpoint, key)| {
            psbt.unsigned_tx
                .input
                .iter()
                .position(|txin| txin.previous_output == *outpoint)
                .map(|input_index| (input_index, key))
                .ok_or(SpendError::OutpointNotInTx {
                    outpoint: *outpoint,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);

    for (input_index, key) in targets {
        let spk = prevouts[input_index].script_pubkey.clone();
        if spk.is_p2tr() {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(|err| SpendError::Sighash(err.to_string()))?;
            let message = Message::from_digest(sighash.to_byte_array());
            let keypair = Keypair::from_secret_key(secp, key);
            let signature = taproot::Signature {
                signature: secp.sign_schnorr_no_aux_rand(&message, &keypair),
                sighash_type: TapSighashType::Default,
            };
            psbt.inputs[input_index].final_script_witness =
                Some(bitcoin::Witness::p2tr_key_spend(&signature));
        } else if spk.is_p2wpkh() {
            let sighash = cache
                .p2wpkh_signature_hash(
                    input_index,
                    &spk,
                    prevouts[input_index].value,
                    EcdsaSighashType::All,
                )
                .map_err(|err| SpendError::Sighash(err.to_string()))?;
            let message = Message::from_digest(sighash.to_byte_array());
            let signature = ecdsa::Signature {
                signature: secp.sign_ecdsa(&message, key),
                sighash_type: EcdsaSighashType::All,
            };
            let mut witness = bitcoin::Witness::new();
            witness.push(signature.to_vec());
            witness.push(key.public_key(secp).serialize());
            psbt.inputs[input_index].final_script_witness = Some(witness);
        } else {
            let sighash = cache
                .legacy_signature_hash(input_index, &spk, EcdsaSighashType::All.to_u32())
                .map_err(|err| SpendError::Sighash(err.to_string()))?;
            let message = Message::from_digest(sighash.to_byte_array());
            let signature = ecdsa::Signature {
                signature: secp.sign_ecdsa(&message, key),
                sighash_type: EcdsaSighashType::All,
            };
            let sig_push = PushBytesBuf::try_from(signature.to_vec())
                .map_err(|_| SpendError::SignaturePush)?;
            let mut builder = Builder::new().push_slice(&sig_push);
            if spk.is_p2pkh() {
                builder = builder.push_slice(key.public_key(secp).serialize());
            }
            psbt.inputs[input_index].final_script_sig = Some(builder.into_script());
        }
    }

    Ok(())
}

fn collect_prevouts(psbt: &Psbt) -> Result<Vec<TxOut>, SpendError> {
    psbt.inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            input
                .witness_utxo
                .clone()
                .or_else(|| {
                    let vout = psbt.unsigned_tx.input[input_index].previous_output.vout as usize;
                    input
                        .non_witness_utxo
                        .as_ref()
                        .and_then(|tx| tx.output.get(vout).cloned())
                })
                .ok_or(SpendError::MissingPrevout { input_index })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime,
        hashes::Hash as _,
        key::TweakedPublicKey,
        psbt::Psbt,
        secp256k1::{Message, Secp256k1, SecretKey, rand::rngs::OsRng},
        sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
        transaction::Version,
    };

    use super::*;

    fn dummy_outpoint(seed: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([seed; 32]), 0)
    }

    fn psbt_spending(prevout: TxOut, outpoint: OutPoint) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: bitcoin::ScriptBuf::new_op_return([]),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");
        psbt.inputs[0].witness_utxo = Some(prevout);
        psbt
    }

    #[test]
    fn signs_silent_payment_taproot_keypath_without_tweak() {
        let secp = Secp256k1::new();
        let key = SecretKey::new(&mut OsRng);
        let xonly = key.x_only_public_key(&secp).0;
        let spk =
            bitcoin::ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly));
        let outpoint = dummy_outpoint(1);
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk,
        };
        let mut psbt = psbt_spending(prevout.clone(), outpoint);

        sign_psbt_inputs(&mut psbt, &[(outpoint, key)], &secp).expect("sign");

        let witness = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("witness set");
        let sig = taproot::Signature::from_slice(&witness[0]).expect("schnorr sig");
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                TapSighashType::Default,
            )
            .expect("sighash");
        secp.verify_schnorr(
            &sig.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &xonly,
        )
        .expect("valid against the untweaked output key");
    }

    #[test]
    fn signs_p2wpkh_input() {
        let secp = Secp256k1::new();
        let key = SecretKey::new(&mut OsRng);
        let pubkey = bitcoin::CompressedPublicKey(key.public_key(&secp));
        let spk = bitcoin::ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash());
        let outpoint = dummy_outpoint(2);
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        };
        let mut psbt = psbt_spending(prevout, outpoint);

        sign_psbt_inputs(&mut psbt, &[(outpoint, key)], &secp).expect("sign");

        let witness = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("witness set");
        let sig = ecdsa::Signature::from_slice(&witness[0]).expect("ecdsa sig");
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(0, &spk, Amount::from_sat(10_000), EcdsaSighashType::All)
            .expect("sighash");
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig.signature,
            &key.public_key(&secp),
        )
        .expect("valid");
    }

    #[test]
    fn signs_p2pkh_input() {
        let secp = Secp256k1::new();
        let key = SecretKey::new(&mut OsRng);
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let spk = bitcoin::ScriptBuf::new_p2pkh(&pubkey.pubkey_hash());
        let outpoint = dummy_outpoint(3);
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        };
        let mut psbt = psbt_spending(prevout, outpoint);

        sign_psbt_inputs(&mut psbt, &[(outpoint, key)], &secp).expect("sign");

        let script_sig = psbt.inputs[0]
            .final_script_sig
            .as_ref()
            .expect("scriptSig set");
        let sig_push = match script_sig.instructions().next() {
            Some(Ok(bitcoin::script::Instruction::PushBytes(bytes))) => bytes,
            other => panic!("expected signature push, got {other:?}"),
        };
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .legacy_signature_hash(0, &spk, EcdsaSighashType::All.to_u32())
            .expect("sighash");
        let sig = ecdsa::Signature::from_slice(sig_push.as_bytes()).expect("ecdsa sig");
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig.signature,
            &key.public_key(&secp),
        )
        .expect("valid");
    }
}
