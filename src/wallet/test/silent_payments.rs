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
