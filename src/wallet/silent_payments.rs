//! Silent payments (BIP352) functionality, experimental and limited to regtest.
//!
//! This module defines the wallet methods to send RGB assets to a silent payment recipient. The
//! proof is expected to reach the recipient by means of the application, which can encrypt it with
//! keys derived from the shared secret.
//!
//! Outputs are derived by `bitcoin-silent-payments` (libsecp256k1), which doesn't expose the shared
//! secret: that is computed here, refusing it if it doesn't yield the same output.

use bdk_wallet::bitcoin::{
    CompressedPublicKey,
    hashes::{Hash, HashEngine, sha256},
    key::{Keypair, Parity, TapTweak, TweakedPublicKey},
    secp256k1::{PublicKey, Scalar, SecretKey, XOnlyPublicKey, ecdh::shared_secret_point},
};
use bitcoin_silent_payments::{LexMin, send::SpGroup};

use super::*;

/// The public keys of a silent payment recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentPubkeys {
    /// Scan public key
    pub scan: PublicKey,
    /// Spend public key
    pub spend: PublicKey,
}

/// The payment of an RGB asset to a silent payment recipient.
#[derive(Debug, Clone)]
pub struct SilentPaymentRecipient {
    /// Public keys of the recipient
    pub pubkeys: SilentPaymentPubkeys,
    /// Amount of the asset
    pub amount: u64,
    /// Bitcoin amount of the output, in sats
    pub amount_sat: u64,
    /// Blinding of the seal, which the recipient needs to know, random if not set
    pub blinding: Option<u64>,
}

/// The result of beginning a send to a silent payment recipient.
#[derive(Debug, Clone)]
pub struct SilentPaymentSendBeginResult {
    /// Result of the underlying send begin
    pub send_begin: SendBeginResult,
    /// Vout of the output paying the recipient
    pub vout: u32,
    /// BIP352 shared secret, known only to the parties: who has it can recognize the payment
    pub shared_secret: PublicKey,
}

/// A BIP352 output (the one at counter zero, without label).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpOutput {
    shared_secret: PublicKey,
    tweak: SecretKey,
    script: ScriptBuf,
}

/// An input of a silent payment, with the secret key of its previous output (for a taproot one,
/// the already tweaked one).
struct SpInput {
    outpoint: BdkOutPoint,
    secret_key: SecretKey,
    taproot: bool,
}

fn sp_error(details: impl ToString) -> Error {
    Error::InvalidRecipientData {
        details: format!("silent payment: {}", details.to_string()),
    }
}

/// The BIP340 tagged hash of the given data, as a scalar.
fn tagged_scalar(tag: &str, data: &[&[u8]]) -> Result<SecretKey, Error> {
    let tag = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    data.iter().for_each(|d| engine.input(d));
    let hash = sha256::Hash::from_engine(engine);
    SecretKey::from_slice(hash.as_byte_array()).map_err(sp_error)
}

/// The point obtained by multiplying the given one by a secret, in constant time.
fn ecdh_point(point: &PublicKey, secret: &SecretKey) -> Result<PublicKey, Error> {
    let mut bytes = [0x04; 65];
    bytes[1..].copy_from_slice(&shared_secret_point(point, secret));
    PublicKey::from_slice(&bytes).map_err(sp_error)
}

fn lex_min<'a>(outpoints: impl Iterator<Item = &'a BdkOutPoint>) -> Result<[u8; 36], Error> {
    let mut lex_min = LexMin::default();
    outpoints.for_each(|o| lex_min.update_v32(o));
    lex_min.bytes().map_err(|_| sp_error("no inputs"))
}

fn input_hash(lex_min: &[u8; 36], pubkey_sum: &PublicKey) -> Result<Scalar, Error> {
    Ok(tagged_scalar("BIP0352/Inputs", &[lex_min, &pubkey_sum.serialize()])?.into())
}

fn xonly_output_key(script: &ScriptBuf) -> Result<XOnlyPublicKey, Error> {
    XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).map_err(sp_error)
}

/// The output at counter zero, from the shared secret.
fn derive_output(shared_secret: PublicKey, spend: &PublicKey) -> Result<SpOutput, Error> {
    let tweak = tagged_scalar(
        "BIP0352/SharedSecret",
        &[&shared_secret.serialize(), &0u32.to_be_bytes()],
    )?;
    let (key, _) = spend
        .add_exp_tweak(&Secp256k1::new(), &tweak.into())
        .map_err(sp_error)?
        .x_only_public_key();
    Ok(SpOutput {
        shared_secret,
        tweak,
        script: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key)),
    })
}

/// Derive the output paying a recipient from all the inputs of the TX.
fn sender_derive(inputs: &[SpInput], pubkeys: &SilentPaymentPubkeys) -> Result<SpOutput, Error> {
    let secp = Secp256k1::new();
    let lex_min = lex_min(inputs.iter().map(|i| &i.outpoint))?;

    let mut taproot_keys = vec![];
    let mut plain_keys = vec![];
    let mut key_sum: Option<SecretKey> = None;
    for input in inputs {
        let mut key = input.secret_key;
        if input.taproot {
            taproot_keys.push(Keypair::from_secret_key(&secp, &key));
            if key.x_only_public_key(&secp).1 == Parity::Odd {
                key = key.negate();
            }
        } else {
            plain_keys.push(key);
        }
        key_sum = Some(match key_sum {
            Some(sum) => sum.add_tweak(&key.into()).map_err(sp_error)?,
            None => key,
        });
    }
    let key_sum = key_sum.ok_or_else(|| sp_error("no inputs"))?;
    let tweaked_sum = key_sum
        .mul_tweak(&input_hash(&lex_min, &key_sum.public_key(&secp))?)
        .map_err(sp_error)?;
    let output = derive_output(ecdh_point(&pubkeys.scan, &tweaked_sum)?, &pubkeys.spend)?;

    let mut group = SpGroup::new();
    group
        .add_v32(pubkeys.scan, pubkeys.spend)
        .map_err(|e| sp_error(format!("{e:?}")))?;
    let derived: Vec<XOnlyPublicKey> = group
        .create_outputs_v32(&lex_min, &taproot_keys, &plain_keys)
        .map_err(|e| sp_error(format!("{e:?}")))?
        .outputs()
        .collect();
    if derived != [xonly_output_key(&output.script)?] {
        return Err(sp_error("derived output mismatch"));
    }
    Ok(output)
}

/// The inputs of a PSBT, all of which need to be P2WPKH or P2TR (key path) ones of this wallet.
fn psbt_inputs(psbt: &Psbt, master_xprv: &Xpriv) -> Result<Vec<SpInput>, Error> {
    let secp = Secp256k1::new();
    let fingerprint = master_xprv.fingerprint(&secp);
    let derive = |source: &KeySource| -> Result<SecretKey, Error> {
        if source.0 != fingerprint {
            return Err(sp_error("input not from this wallet"));
        }
        Ok(master_xprv.derive_priv(&secp, &source.1)?.private_key)
    };
    let mut inputs = vec![];
    for (txin, input) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs) {
        let script = &input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| sp_error("missing witness UTXO"))?
            .script_pubkey;
        let (secret_key, expected_script) = if script.is_p2tr() {
            if input.tap_merkle_root.is_some() {
                return Err(sp_error("input with a script tree"));
            }
            let (_, source) = input
                .tap_internal_key
                .and_then(|k| input.tap_key_origins.get(&k))
                .ok_or_else(|| sp_error("missing input key origin"))?;
            let keypair = Keypair::from_secret_key(&secp, &derive(source)?)
                .tap_tweak(&secp, None)
                .to_keypair();
            let (key, _) = keypair.x_only_public_key();
            (
                keypair.secret_key(),
                ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key)),
            )
        } else if script.is_p2wpkh() {
            let source = input
                .bip32_derivation
                .values()
                .next()
                .ok_or_else(|| sp_error("missing input key origin"))?;
            let key = derive(source)?;
            let pubkey = CompressedPublicKey(key.public_key(&secp));
            (key, ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash()))
        } else {
            return Err(sp_error("unsupported input type"));
        };
        if expected_script != *script {
            return Err(sp_error("input key mismatch"));
        }
        inputs.push(SpInput {
            outpoint: txin.previous_output,
            secret_key,
            taproot: script.is_p2tr(),
        });
    }
    Ok(inputs)
}

impl Wallet {
    fn check_silent_payments(&self) -> Result<(), Error> {
        self.check_xprv()?;
        let network = self.bitcoin_network();
        if network != BitcoinNetwork::Regtest {
            return Err(Error::InvalidBitcoinNetwork {
                network: network.to_string(),
            });
        }
        Ok(())
    }

    fn master_xprv(&self) -> Result<Xpriv, Error> {
        let keys = self.get_keys();
        let mnemonic = keys.mnemonic.as_deref().ok_or(Error::WatchOnly)?;
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
        Ok(Xpriv::new_master(self.bitcoin_network(), &mnemonic.to_seed("")).expect("valid seed"))
    }

    /// Prepare the PSBT to send an RGB asset to a silent payment recipient, which is always a
    /// donation.
    ///
    /// The recipient needs the proof to find out about the transfer: once the PSBT has been signed
    /// with [`sign_psbt`](Wallet::sign_psbt) and its consignments have been created with
    /// [`create_consignments`](Wallet::create_consignments), make them available to the recipient
    /// and only then broadcast the TX with [`send_end`](Wallet::send_end).
    ///
    /// The output depends on the inputs, so the TX must not be replaced.
    ///
    /// A wallet with private keys is required.
    ///
    /// <div class="warning">This method is experimental and only works on regtest</div>
    pub fn send_begin_silent_payment(
        &mut self,
        online: Online,
        asset_id: String,
        recipient: SilentPaymentRecipient,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: u64,
    ) -> Result<SilentPaymentSendBeginResult, Error> {
        info!(self.logger(), "Sending (begin) to silent payment...");
        self.check_silent_payments()?;
        self.check_online(online)?;
        let master_xprv = self.master_xprv()?;
        let pubkeys = recipient.pubkeys;
        let derive = |psbt: &Psbt| sender_derive(&psbt_inputs(psbt, &master_xprv)?, &pubkeys);

        // replaced once the inputs are final
        let placeholder: [u8; 32] = rand::random();
        let (placeholder, _) = SecretKey::from_slice(&placeholder)
            .map_err(sp_error)?
            .x_only_public_key(&Secp256k1::new());
        let placeholder =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(placeholder));
        let recipient_map = HashMap::from([(
            asset_id,
            vec![Recipient {
                recipient_id: crate::no_wallet::recipient_id_from_script_buf(
                    placeholder,
                    self.bitcoin_network(),
                ),
                witness_data: Some(WitnessData {
                    amount_sat: recipient.amount_sat,
                    blinding: recipient.blinding,
                }),
                assignment: Assignment::Fungible(recipient.amount),
                transport_endpoints: vec![],
                public_key: None,
                expiration_timestamp: None,
                encryption: Encryption::Optional,
            }],
        )]);
        let txn = self.database().begin_transaction()?;
        let begin_op_data = self.send_begin_derived_impl(
            &txn,
            recipient_map,
            true,
            fee_rate,
            min_confirmations,
            Some(expiration_timestamp as i64),
            None,
            false,
            Some(&|psbt| Ok(derive(psbt)?.script)),
        )?;
        // the inputs are the final ones, so this is the output paid
        let output = derive(&begin_op_data.psbt)?;
        let vout = begin_op_data
            .psbt
            .unsigned_tx
            .output
            .iter()
            .position(|o| o.script_pubkey == output.script)
            .ok_or_else(|| sp_error("the TX doesn't pay the recipient"))?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        info!(self.logger(), "Send (begin) to silent payment completed");
        Ok(SilentPaymentSendBeginResult {
            send_begin: SendBeginResult {
                psbt: begin_op_data.psbt.to_string(),
                batch_transfer_idx: begin_op_data.batch_transfer_idx,
                details: SendDetails {
                    fascia_path: begin_op_data
                        .transfer_dir
                        .join(FASCIA_FILE)
                        .to_string_lossy()
                        .to_string(),
                    min_confirmations,
                    entropy: begin_op_data.info_batch_transfer.entropy,
                    is_donation: true,
                },
            },
            vout: vout as u32,
            shared_secret: output.shared_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct VectorInput {
        txid: String,
        vout: u32,
        key: String,
        taproot: bool,
    }

    #[derive(Deserialize)]
    struct Vector {
        comment: String,
        inputs: Vec<VectorInput>,
        scan: String,
        spend: String,
        shared_secret: String,
        output: String,
    }

    // the BIP352 test vectors with a single unlabeled recipient and standard inputs
    #[test]
    fn bip352_vectors() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../tests/fixtures/bip352.json")).unwrap();
        assert!(!vectors.is_empty());
        for vector in vectors {
            let inputs: Vec<SpInput> = vector
                .inputs
                .iter()
                .map(|i| SpInput {
                    outpoint: BdkOutPoint::from_str(&format!("{}:{}", i.txid, i.vout)).unwrap(),
                    secret_key: SecretKey::from_str(&i.key).unwrap(),
                    taproot: i.taproot,
                })
                .collect();
            let pubkeys = SilentPaymentPubkeys {
                scan: PublicKey::from_str(&vector.scan).unwrap(),
                spend: PublicKey::from_str(&vector.spend).unwrap(),
            };
            let output = sender_derive(&inputs, &pubkeys).unwrap();
            assert_eq!(
                output.shared_secret.to_string(),
                vector.shared_secret,
                "{}",
                vector.comment
            );
            assert_eq!(
                output.script.to_hex_string(),
                format!("5120{}", vector.output),
                "{}",
                vector.comment
            );
        }
    }
}
