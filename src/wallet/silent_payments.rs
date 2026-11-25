//! Silent payments (BIP352) functionality, experimental and limited to regtest.
//!
//! This module defines the wallet methods to send RGB assets to a silent payment recipient and to
//! receive them. The received outputs cannot be spent yet. The
//! proof is expected to reach the recipient by means of the application, which can encrypt it with
//! keys derived from the shared secret.
//!
//! Outputs are derived by `bitcoin-silent-payments` (libsecp256k1), which doesn't expose the shared
//! secret: that is computed here, refusing it if it doesn't yield the same output.

use bdk_wallet::bitcoin::{
    CompressedPublicKey, EcdsaSighashType,
    hashes::{Hash, HashEngine, sha256},
    key::{Keypair, Parity, TapTweak, TweakedPublicKey},
    secp256k1::{PublicKey, Scalar, SecretKey, XOnlyPublicKey, ecdh::shared_secret_point},
};
use bitcoin_silent_payments::{
    LexMin, compat_v32::create_prevouts_summary_32, receive::SpRx, send::SpGroup,
};

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

/// A silent payment found in a TX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPayment {
    /// Outpoint of the output paying this wallet
    pub outpoint: Outpoint,
    /// Bitcoin amount of the output, in sats
    pub amount_sat: u64,
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

/// The public keys of the inputs of a signed TX, taproot and plain, `None` unless all of them are
/// P2WPKH (`SIGHASH_ALL`) or P2TR key path (`SIGHASH_DEFAULT`) ones.
fn input_pubkeys(
    tx: &BdkTransaction,
    prevouts: &[TxOut],
) -> Option<(Vec<XOnlyPublicKey>, Vec<PublicKey>)> {
    if tx.is_coinbase() || tx.input.len() != prevouts.len() {
        return None;
    }
    let (mut taproot, mut plain) = (vec![], vec![]);
    for (txin, prevout) in tx.input.iter().zip(prevouts) {
        if !txin.script_sig.is_empty() {
            return None;
        }
        let script = &prevout.script_pubkey;
        let witness = txin.witness.to_vec();
        match witness.as_slice() {
            [signature] if script.is_p2tr() && signature.len() == 64 => {
                taproot.push(xonly_output_key(script).ok()?);
            }
            [signature, pubkey]
                if script.is_p2wpkh()
                    && signature.last() == Some(&(EcdsaSighashType::All as u8)) =>
            {
                let pubkey = CompressedPublicKey::from_slice(pubkey).ok()?;
                if ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash()) != *script {
                    return None;
                }
                plain.push(pubkey.0);
            }
            _ => return None,
        }
    }
    Some((taproot, plain))
}

/// Find the output of a TX paying the given keys, `None` if there isn't exactly one.
fn receiver_scan(
    tx: &BdkTransaction,
    prevouts: &[TxOut],
    scan_key: &SecretKey,
    spend: &PublicKey,
) -> Result<Option<(u32, SpOutput)>, Error> {
    let candidates: Vec<XOnlyPublicKey> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .filter_map(|o| xonly_output_key(&o.script_pubkey).ok())
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    let Some((taproot, plain)) = input_pubkeys(tx, prevouts) else {
        return Ok(None);
    };
    let lex_min = lex_min(tx.input.iter().map(|i| &i.previous_output))?;
    // the keys may sum up to infinity, in which case this is not a silent payment
    let Ok(summary) = create_prevouts_summary_32(&lex_min, &taproot, &plain) else {
        return Ok(None);
    };
    let Ok(found) = SpRx::new_v32(*scan_key, *spend).scan_v32(&summary, &candidates) else {
        return Ok(None);
    };
    if found.is_empty() {
        return Ok(None);
    }

    let pubkeys: Vec<PublicKey> = taproot
        .iter()
        .map(|k| k.public_key(Parity::Even))
        .chain(plain)
        .collect();
    let pubkey_sum =
        PublicKey::combine_keys(&pubkeys.iter().collect::<Vec<_>>()).map_err(sp_error)?;
    let tweaked_sum = pubkey_sum
        .mul_tweak(&Secp256k1::new(), &input_hash(&lex_min, &pubkey_sum)?)
        .map_err(sp_error)?;
    let output = derive_output(ecdh_point(&tweaked_sum, scan_key)?, spend)?;
    let key = xonly_output_key(&output.script)?;
    if !found
        .iter()
        .any(|(k, meta)| *k == key && meta.tweak.to_be_bytes() == output.tweak.secret_bytes())
    {
        return Err(sp_error("found output mismatch"));
    }
    let vouts: Vec<usize> = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == output.script)
        .map(|(vout, _)| vout)
        .collect();
    // an error would let any payer stop the recipient from scanning
    Ok(match vouts.as_slice() {
        [vout] => Some((*vout as u32, output)),
        _ => None,
    })
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

    /// The scan and spend secret keys, derived with the purpose of BIP352 but the coin type of RGB:
    /// a bitcoin-only wallet with the same mnemonic must not find (and spend) the outputs, as that
    /// would destroy their assets.
    fn silent_payment_keys(&self) -> Result<(SecretKey, SecretKey), Error> {
        let secp = Secp256k1::new();
        let account = [
            ChildNumber::from_hardened_idx(352).expect("valid index"),
            ChildNumber::from_hardened_idx(get_coin_type(&self.bitcoin_network(), true))
                .expect("valid index"),
            ChildNumber::from_hardened_idx(0).expect("valid index"),
        ];
        let account = self.master_xprv()?.derive_priv(&secp, &account)?;
        let derive = |child: u32| -> Result<SecretKey, Error> {
            let path = [
                ChildNumber::from_hardened_idx(child).expect("valid index"),
                ChildNumber::from_normal_idx(0).expect("valid index"),
            ];
            Ok(account.derive_priv(&secp, &path)?.private_key)
        };
        Ok((derive(1)?, derive(0)?))
    }

    /// Return the public keys others can send RGB assets to with
    /// [`send_begin_silent_payment`](Wallet::send_begin_silent_payment).
    ///
    /// A wallet with private keys is required.
    ///
    /// <div class="warning">This method is experimental and only works on regtest</div>
    pub fn get_silent_payment_pubkeys(&self) -> Result<SilentPaymentPubkeys, Error> {
        self.check_silent_payments()?;
        let secp = Secp256k1::new();
        let (scan_key, spend_key) = self.silent_payment_keys()?;
        Ok(SilentPaymentPubkeys {
            scan: scan_key.public_key(&secp),
            spend: spend_key.public_key(&secp),
        })
    }

    /// Find the silent payment to this wallet in the given signed TX, if any, given the outputs its
    /// inputs spend (in the same order).
    ///
    /// The data is not checked to be on-chain. A TX with several payments to this wallet, or with
    /// inputs other than P2WPKH and P2TR key path ones, is ignored.
    ///
    /// A wallet with private keys is required.
    ///
    /// <div class="warning">This method is experimental and only works on regtest</div>
    pub fn scan_silent_payment(
        &self,
        tx: &BdkTransaction,
        prevouts: &[TxOut],
    ) -> Result<Option<SilentPayment>, Error> {
        self.check_silent_payments()?;
        Ok(self
            .scan_silent_payment_impl(tx, prevouts)?
            .map(|(payment, _)| payment))
    }

    fn scan_silent_payment_impl(
        &self,
        tx: &BdkTransaction,
        prevouts: &[TxOut],
    ) -> Result<Option<(SilentPayment, SpOutput)>, Error> {
        let (scan_key, spend_key) = self.silent_payment_keys()?;
        let spend = spend_key.public_key(&Secp256k1::new());
        let Some((vout, output)) = receiver_scan(tx, prevouts, &scan_key, &spend)? else {
            return Ok(None);
        };
        let payment = SilentPayment {
            outpoint: Outpoint {
                txid: tx.compute_txid().to_string(),
                vout,
            },
            amount_sat: tx.output[vout as usize].value.to_sat(),
            shared_secret: output.shared_secret,
        };
        Ok(Some((payment, output)))
    }

    /// Receive the RGB assets of a silent payment, found with
    /// [`scan_silent_payment`](Wallet::scan_silent_payment), given its proof.
    ///
    /// The TX needs to be confirmed. The consignment is validated as any received one is and needs
    /// to pay exactly `amount` of the asset to the output, otherwise nothing is saved. The transfer
    /// is then settled by [`refresh`](Wallet::refresh).
    ///
    /// The received assets can't be spent yet. Seed and chain are enough to find the output again
    /// but not the assets, which are in the backup of the wallet.
    ///
    /// Receiving the same output again has no effect.
    ///
    /// Return the index of the batch transfer.
    ///
    /// A wallet with private keys is required.
    ///
    /// <div class="warning">This method is experimental and only works on regtest</div>
    #[allow(clippy::too_many_arguments)]
    pub fn receive_silent_payment(
        &mut self,
        online: Online,
        tx: &BdkTransaction,
        prevouts: &[TxOut],
        consignment_path: String,
        asset_id: String,
        amount: u64,
        min_confirmations: u8,
    ) -> Result<i32, Error> {
        info!(self.logger(), "Receiving silent payment...");
        self.check_silent_payments()?;
        self.check_online(online)?;
        let (payment, output) = self
            .scan_silent_payment_impl(tx, prevouts)?
            .ok_or_else(|| sp_error("the TX doesn't pay this wallet"))?;
        let outpoint = payment.outpoint;

        let txn = self.database().begin_transaction()?;
        if let Some(batch_transfer_idx) = txn.get_silent_payment_batch_transfer(&outpoint)? {
            return Ok(batch_transfer_idx);
        }
        if self
            .indexer()
            .get_tx_confirmations(&outpoint.txid)?
            .is_none_or(|confirmations| confirmations == 0)
        {
            return Err(sp_error("the TX is not confirmed"));
        }
        let consignment =
            RgbTransfer::load_file(&consignment_path).map_err(|_| Error::InvalidFilePath {
                file_path: consignment_path.clone(),
            })?;
        if consignment.contract_id().to_string() != asset_id {
            return Err(Error::InvalidConsignment);
        }
        // the consignment must commit to this very TX, not to another one paying the same script
        if !consignment
            .bundles
            .iter()
            .any(|b| b.witness_id().to_string() == outpoint.txid)
        {
            return Err(Error::InvalidConsignment);
        }

        // save the receive as an out-of-band witness one, which the consignment is for
        let recipient_id =
            crate::no_wallet::recipient_id_from_script_buf(output.script, self.bitcoin_network());
        let beneficiary = XChainNet::<Beneficiary>::from_str(&recipient_id)
            .map_err(|_| Error::InvalidRecipientID)?;
        let operation_sk = gen_ed25519();
        let created_at = now().unix_timestamp();
        let receive_data = ReceiveDataInternal {
            asset_id: None,
            detected_assignment: Assignment::Fungible(amount),
            invoice_string: RgbInvoiceBuilder::new(beneficiary).finish().to_string(),
            recipient_id,
            endpoints: vec![],
            created_at,
            expiration_timestamp: created_at + i64::from(MAX_EXPIRATION_SECS),
            recipient_type_full: RecipientTypeFull::Witness { vout: None },
            blind_seal: None,
            // not a script of the BDK wallet
            script_pubkey: None,
            recipient_pubkey: operation_sk.verifying_key().to_bytes().to_vec(),
            operation_secret_key: operation_sk.to_bytes().to_vec(),
            encryption: Encryption::Optional,
            quota: 1,
            retention_deadline: None,
            invoice_deadline: None,
            receive_dir: None,
        };
        let batch_transfer_idx =
            self.store_receive_transfer(&txn, &receive_data, min_confirmations)?;
        let db_data = txn.get_db_data(false)?;
        let batch_transfer =
            txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
        let (asset_transfer, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;

        let receive_path = self.get_receive_consignment_path(&transfer);
        atomic_write_with(&receive_path, |tmp| {
            fs::copy(&consignment_path, tmp)?;
            Ok(())
        })?;
        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        let updated = self.process_received_consignment(
            &txn,
            &batch_transfer,
            &asset_transfer,
            &transfer,
            &receive_path,
            ReceiveMode::OutOfBand {
                media_file_paths: vec![],
            },
            &mut updated_batch_transfer,
        )?;
        // from here on an error rolls back everything, including the RGB data
        let Some(updated) = updated.filter(|t| !t.failed()) else {
            return Err(Error::InvalidConsignment);
        };
        if updated.txid.as_deref() != Some(outpoint.txid.as_str()) {
            return Err(Error::InvalidConsignment);
        }
        let mut received = 0u64;
        for coloring in txn.iter_colorings()? {
            if coloring.asset_transfer_idx != asset_transfer.idx {
                continue;
            }
            let Assignment::Fungible(amt) = coloring.assignment else {
                return Err(Error::InvalidConsignment);
            };
            received = received.checked_add(amt).ok_or(Error::InvalidConsignment)?;
        }
        if received != amount {
            return Err(Error::InvalidConsignment);
        }
        txn.set_silent_payment_output(&outpoint, &output.tweak.secret_bytes(), batch_transfer_idx)?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        info!(self.logger(), "Receive silent payment completed");
        Ok(batch_transfer_idx)
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
