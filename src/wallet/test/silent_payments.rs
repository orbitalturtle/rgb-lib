use super::*;

use bdk_wallet::bitcoin::secp256k1::SecretKey;

use crate::wallet::silent_payments::{SilentPaymentPubkeys, SilentPaymentRecipient};

fn recipient(amount: u64) -> SilentPaymentRecipient {
    let secp = Secp256k1::new();
    let pubkey = |byte| {
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&secp)
    };
    SilentPaymentRecipient {
        pubkeys: SilentPaymentPubkeys {
            scan: pubkey(1),
            spend: pubkey(2),
        },
        amount,
        amount_sat: 1000,
        blinding: Some(777),
    }
}

/// A send to a silent payment recipient, spending multiple UTXOs, pays an output derived from its
/// final inputs, which both the transfer and the consignment are for.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_success() {
    initialize();

    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(Some(&[AMOUNT, AMOUNT, AMOUNT]));
    let amount = AMOUNT * 2 + 1;
    let begin = party
        .wallet
        .send_begin_silent_payment(
            party.online,
            asset.asset_id.clone(),
            recipient(amount),
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
        )
        .unwrap();
    let psbt = Psbt::from_str(&begin.send_begin.psbt).unwrap();
    assert!(psbt.unsigned_tx.input.len() > 1);
    let output = &psbt.unsigned_tx.output[begin.vout as usize];
    assert_eq!(output.value.to_sat(), 1000);
    assert!(output.script_pubkey.is_p2tr());
    let recipient_id = crate::no_wallet::recipient_id_from_script_buf(
        output.script_pubkey.clone(),
        BitcoinNetwork::Regtest,
    );
    assert!(party.check_test_transfer_status_recipient(&recipient_id, TransferStatus::Initiated));

    let signed_psbt = party.wallet.sign_psbt(begin.send_begin.psbt, None).unwrap();
    party
        .wallet
        .create_consignments(signed_psbt.clone())
        .unwrap();
    let res = party.wallet.send_end(party.online, signed_psbt).unwrap();
    let consignment = RgbTransfer::load_file(
        party
            .wallet
            .get_send_consignment_path(&asset.asset_id, &res.txid),
    )
    .unwrap();
    let bundle = consignment
        .bundles
        .iter()
        .find(|b| b.witness_id().to_string() == res.txid)
        .unwrap();
    assert!(bundle.tx.input.iter().all(|i| !i.witness.is_empty()));
    mine(false);
    party.wait_for_refresh(None);
    assert!(party.check_test_transfer_status_recipient(&recipient_id, TransferStatus::Settled));
    assert_eq!(
        party.get_asset_balance(&asset.asset_id).settled,
        AMOUNT * 3 - amount
    );
}

/// Only a wallet with private keys on regtest can send to a silent payment recipient.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_fail() {
    initialize();

    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(None);
    let mut send = |recipient| {
        party.wallet.send_begin_silent_payment(
            party.online,
            asset.asset_id.clone(),
            recipient,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
        )
    };
    let result = send(recipient(AMOUNT + 1));
    assert_matches!(result, Err(Error::InsufficientAssignments { .. }));
    let result = send(recipient(0));
    assert_matches!(result, Err(Error::InvalidAmountZero));

    let mut wallet_data = party.wallet.get_wallet_data();
    let data_dir = tempfile::tempdir().unwrap();
    wallet_data.data_dir = data_dir.path().to_str().unwrap().to_string();
    let mut keys = party.wallet.get_keys();
    keys.mnemonic = None;
    let mut watch_only = Wallet::new(wallet_data, keys).unwrap();
    let online = watch_only.go_online(test_go_online_options(None)).unwrap();
    let result = watch_only.send_begin_silent_payment(
        online,
        asset.asset_id,
        recipient(1),
        FEE_RATE,
        MIN_CONFIRMATIONS,
        default_send_expiration(),
    );
    assert_matches!(result, Err(Error::WatchOnly));
}

/// A silent payment is found by the recipient only and its proof is imported once validated. The
/// received assets are in the settled balance but can't be spent.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn receive_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();
    let amount = AMOUNT + 1;

    let asset = party.issue_asset_nia(Some(&[AMOUNT, AMOUNT]));
    let pubkeys = rcv_party.wallet.get_silent_payment_pubkeys().unwrap();
    let begin = party
        .wallet
        .send_begin_silent_payment(
            party.online,
            asset.asset_id.clone(),
            SilentPaymentRecipient {
                pubkeys,
                ..recipient(amount)
            },
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
        )
        .unwrap();
    let prevouts: Vec<_> = Psbt::from_str(&begin.send_begin.psbt)
        .unwrap()
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let signed_psbt = party.wallet.sign_psbt(begin.send_begin.psbt, None).unwrap();
    let tx = Psbt::from_str(&signed_psbt).unwrap().extract_tx().unwrap();
    let txid = tx.compute_txid().to_string();
    party
        .wallet
        .create_consignments(signed_psbt.clone())
        .unwrap();
    let consignment_path = party
        .wallet
        .get_send_consignment_path(&asset.asset_id, &txid)
        .to_str()
        .unwrap()
        .to_string();

    // found by the recipient, with the same shared secret, but not by others
    let payment = rcv_party
        .wallet
        .scan_silent_payment(&tx, &prevouts)
        .unwrap()
        .unwrap();
    assert_eq!(payment.outpoint.txid, txid);
    assert_eq!(payment.outpoint.vout, begin.vout);
    assert_eq!(payment.amount_sat, 1000);
    assert_eq!(payment.shared_secret, begin.shared_secret);
    let found = party.wallet.scan_silent_payment(&tx, &prevouts).unwrap();
    assert!(found.is_none());
    // wrong data is ignored
    let found = rcv_party.wallet.scan_silent_payment(&tx, &prevouts[1..]);
    assert!(found.unwrap().is_none());

    let receive = |rcv_party: &mut SinglesigParty, amount| {
        rcv_party.wallet.receive_silent_payment(
            rcv_party.online,
            &tx,
            &prevouts,
            consignment_path.clone(),
            asset.asset_id.clone(),
            amount,
            MIN_CONFIRMATIONS,
        )
    };
    // not confirmed
    assert_matches!(
        receive(&mut rcv_party, amount),
        Err(Error::InvalidRecipientData { .. })
    );
    party.wallet.send_end(party.online, signed_psbt).unwrap();
    assert_matches!(
        receive(&mut rcv_party, amount),
        Err(Error::InvalidRecipientData { .. })
    );
    mine(false);
    assert!(wait_for_function(
        || !matches!(
            receive(&mut rcv_party, 1),
            Err(Error::InvalidRecipientData { .. })
        ),
        30,
        500
    ));
    // wrong amount: nothing is saved, not even the asset
    assert_matches!(
        receive(&mut rcv_party, amount - 1),
        Err(Error::InvalidConsignment)
    );
    assert!(rcv_party.list_transfers(None).is_empty());
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();
    assert!(!rcv_party.wallet.is_asset_known(contract_id).unwrap());

    // success, once
    let idx = receive(&mut rcv_party, amount).unwrap();
    assert_eq!(receive(&mut rcv_party, amount).unwrap(), idx);
    assert_eq!(rcv_party.list_transfers(Some(&asset.asset_id)).len(), 1);
    rcv_party.wait_for_refresh(None);
    assert_eq!(
        rcv_party.db_batch_transfer(idx).status,
        TransferStatus::Settled
    );
    let balance = Balance {
        settled: amount,
        future: amount,
        spendable: 0,
    };
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id), balance);

    // not spendable, nor used to receive other assets
    let result = rcv_party.wallet.send_begin_silent_payment(
        rcv_party.online,
        asset.asset_id.clone(),
        recipient(1),
        FEE_RATE,
        MIN_CONFIRMATIONS,
        default_send_expiration(),
    );
    assert_matches!(result, Err(Error::InsufficientAssignments { .. }));
    let other_asset = rcv_party.issue_asset_nia(None);
    assert!(
        rcv_party
            .list_unspents_with_sync(false)
            .iter()
            .filter(|u| u.utxo.outpoint == payment.outpoint)
            .flat_map(|u| &u.rgb_allocations)
            .all(|a| a.asset_id.as_ref() != Some(&other_asset.asset_id))
    );

    // still there once the wallet is opened again
    let wallet_data = rcv_party.wallet.get_wallet_data();
    let keys = rcv_party.wallet.get_keys();
    drop(rcv_party);
    let mut wallet = Wallet::new(wallet_data, keys).unwrap();
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let rcv_party = party!(wallet, online);
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id), balance);
}

/// The silent payment keys differ from the ones of BIP352 bitcoin-only wallets.
#[test]
#[parallel]
fn rgb_specific_keys() {
    let party = get_empty_party!();
    let pubkeys = party.wallet.get_silent_payment_pubkeys().unwrap();
    assert_ne!(pubkeys.scan, pubkeys.spend);
    let mnemonic = Mnemonic::parse(party.wallet.get_keys().mnemonic.unwrap()).unwrap();
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(BitcoinNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    for (path, pubkey) in [
        ("m/352h/1h/0h/1h/0", pubkeys.scan),
        ("m/352h/1h/0h/0h/0", pubkeys.spend),
    ] {
        let path = DerivationPath::from_str(path).unwrap();
        let key = master.derive_priv(&secp, &path).unwrap().private_key;
        assert_ne!(key.public_key(&secp), pubkey);
    }
}
