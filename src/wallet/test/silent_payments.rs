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
/// received assets are in the balance and their output isn't used to receive other ones.
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
        spendable: amount,
    };
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id), balance);

    // not used to receive other assets
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
    initialize();

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

/// Pay a silent payment recipient and have them receive it, returning the TX and the outpoint.
#[cfg(feature = "electrum")]
fn pay(
    party: &mut SinglesigParty,
    rcv_party: &mut SinglesigParty,
    asset_id: &str,
    amount: u64,
) -> (BdkTransaction, Outpoint) {
    let begin = party
        .wallet
        .send_begin_silent_payment(
            party.online,
            asset_id.to_string(),
            SilentPaymentRecipient {
                pubkeys: rcv_party.wallet.get_silent_payment_pubkeys().unwrap(),
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
    let consignment_path = party.wallet.get_send_consignment_path(asset_id, &txid);
    party.wallet.send_end(party.online, signed_psbt).unwrap();
    mine(false);
    party.wait_for_refresh(None);
    let payment = rcv_party
        .wallet
        .scan_silent_payment(&tx, &prevouts)
        .unwrap()
        .unwrap();
    assert!(wait_for_function(
        || rcv_party
            .wallet
            .receive_silent_payment(
                rcv_party.online,
                &tx,
                &prevouts,
                consignment_path.to_str().unwrap().to_string(),
                asset_id.to_string(),
                amount,
                MIN_CONFIRMATIONS,
            )
            .is_ok(),
        30,
        500
    ));
    rcv_party.wait_for_refresh(None);
    (tx, payment.outpoint)
}

/// The assets received with a silent payment can be sent, both to another silent payment recipient
/// and to an ordinary one, and stay available if the send fails.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn spend_success() {
    initialize();

    let mut party_1 = get_funded_party!();
    let mut party_2 = get_funded_party!();
    let mut party_3 = get_funded_party!();
    let spends = |tx: &BdkTransaction, outpoint: &Outpoint| {
        tx.input
            .iter()
            .any(|i| i.previous_output.to_string() == outpoint.to_string())
    };

    let asset = party_1.issue_asset_nia(None);
    let asset_id = asset.asset_id;
    let (_, outpoint) = pay(&mut party_1, &mut party_2, &asset_id, 100);
    assert_eq!(party_2.get_asset_balance(&asset_id).spendable, 100);

    // a failed send, then deleted, leaves the output spendable
    let begin = party_2
        .wallet
        .send_begin_silent_payment(
            party_2.online,
            asset_id.clone(),
            recipient(10),
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
        )
        .unwrap();
    assert!(spends(
        &Psbt::from_str(&begin.send_begin.psbt).unwrap().unsigned_tx,
        &outpoint
    ));
    assert_eq!(party_2.get_asset_balance(&asset_id).spendable, 0);
    assert!(party_2.fail_transfers_single(begin.send_begin.batch_transfer_idx.unwrap()));
    assert!(party_2.delete_transfers(begin.send_begin.batch_transfer_idx, false));
    assert_eq!(party_2.get_asset_balance(&asset_id).settled, 100);
    assert_eq!(party_2.get_asset_balance(&asset_id).spendable, 100);

    // silent payment to silent payment, with change
    let (tx, outpoint) = {
        let (tx, new_outpoint) = pay(&mut party_2, &mut party_3, &asset_id, 60);
        assert!(spends(&tx, &outpoint));
        (tx, new_outpoint)
    };
    assert_eq!(party_2.get_asset_balance(&asset_id).spendable, 40);
    assert_eq!(party_3.get_asset_balance(&asset_id).spendable, 60);
    assert_eq!(outpoint.txid, tx.compute_txid().to_string());

    // silent payment to an ordinary receive, not a donation
    let receive_data = party_1.blind_receive();
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(25),
            recipient_id: receive_data.recipient_id.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Encryption::Optional,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    party_3.send(recipient_map, FEE_RATE, None);
    party_1.wait_for_refresh(None);
    party_3.wait_for_refresh(None);
    mine(false);
    party_1.wait_for_refresh(None);
    party_3.wait_for_refresh(None);
    assert_eq!(party_3.get_asset_balance(&asset_id).spendable, 35);
    assert_eq!(
        party_1.get_asset_balance(&asset_id).spendable,
        AMOUNT - 100 + 25
    );

    // the wallet is consistent when opened again
    let wallet_data = party_3.wallet.get_wallet_data();
    let keys = party_3.wallet.get_keys();
    drop(party_3);
    let mut wallet = Wallet::new(wallet_data, keys).unwrap();
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let mut party_3 = party!(wallet, online);
    // and the change can be spent
    pay(&mut party_3, &mut party_2, &asset_id, 35);
    assert_eq!(party_3.get_asset_balance(&asset_id).settled, 0);
    assert_eq!(party_2.get_asset_balance(&asset_id).spendable, 75);
}
