use super::*;

/// Number of outputs of the TX of `psbt` hosting an allocation of `asset_id` in the RGB runtime,
/// i.e. zero until the fascia of the TX has been applied to the RGB state.
fn rgb_allocated_outputs(party: &SinglesigParty, asset_id: &str, psbt: &str) -> usize {
    let psbt = Psbt::from_str(psbt).unwrap();
    let txid = psbt.unsigned_tx.compute_txid();
    let outpoints: Vec<OutPoint> = (0..psbt.unsigned_tx.output.len() as u32)
        .map(|vout| OutPoint { txid, vout })
        .collect();
    party
        .wallet
        .rgb_runtime()
        .unwrap()
        .contract_assignments_for(ContractId::from_str(asset_id).unwrap(), outpoints)
        .unwrap()
        .values()
        .filter(|assignments| !assignments.is_empty())
        .count()
}

fn recipient_map(
    asset_id: &str,
    recipient_id: &str,
    amount: u64,
) -> HashMap<String, Vec<Recipient>> {
    HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: recipient_id.to_string(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )])
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let amount: u64 = 66;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);

    // begin a send and mark it to apply its RGB state only once final (twice: it's idempotent)
    let receive_data = rcv_party.blind_receive();
    let recipient_map = recipient_map(&asset.asset_id, &receive_data.recipient_id, amount);
    let begin = party.send_begin_result(&recipient_map).unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();
    party
        .wallet
        .set_apply_when_final(batch_transfer_idx)
        .unwrap();
    party
        .wallet
        .set_apply_when_final(batch_transfer_idx)
        .unwrap();
    let (_, _, batch_transfer) = party.get_test_transfer_sender(
        &Psbt::from_str(&begin.psbt)
            .unwrap()
            .unsigned_tx
            .compute_txid()
            .to_string(),
    );
    assert!(batch_transfer.apply_when_final);

    // end the send: the consignment is posted but nothing is applied yet
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    let txid = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingCounterparty));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );

    // once the receiver ACKs, the sender broadcasts the TX but still leaves the RGB state untouched
    let guard = stop_mining();
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );
    drop(guard);

    // once the TX is final the fascia is applied and the transfer settles
    mine(false);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert!(
        rcv_party.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::Settled
        )
    );
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt) > 0);
    assert_eq!(
        party.get_asset_balance(&asset.asset_id).settled,
        AMOUNT - amount
    );
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id).settled, amount);

    // the RGB change is spendable: send all of it with a regular transfer
    let receive_data_2 = rcv_party.blind_receive();
    let recipient_map_2 = self::recipient_map(
        &asset.asset_id,
        &receive_data_2.recipient_id,
        AMOUNT - amount,
    );
    let txid_2 = party.send_retry(&recipient_map_2);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    mine(false);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid_2, TransferStatus::Settled));
    assert_eq!(party.get_asset_balance(&asset.asset_id).settled, 0);
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id).settled, AMOUNT);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn applied_only_at_min_confirmations() {
    initialize();

    let amount: u64 = 66;
    let min_confirmations = 2;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);

    let receive_data = rcv_party.blind_receive();
    let recipient_map = recipient_map(&asset.asset_id, &receive_data.recipient_id, amount);
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            false,
            FEE_RATE,
            min_confirmations,
            default_send_expiration(),
            false,
        )
        .unwrap();
    party
        .wallet
        .set_apply_when_final(begin.batch_transfer_idx.unwrap())
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    // stop mining before broadcasting so that no concurrent test can confirm the TX
    let guard = stop_mining_when_alone();
    let txid = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));

    // 1 confirmation is not enough: still nothing applied
    force_mine_no_resume_when_alone(false);
    assert_eq!(get_tx_height(false, &txid), Some(1));
    assert!(!party.refresh_asset(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );
    drop(guard);

    // 2 confirmations: applied and settled
    mine(false);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt) > 0);
    assert_eq!(
        party.get_asset_balance(&asset.asset_id).settled,
        AMOUNT - amount
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn donation() {
    initialize();

    let amount: u64 = 66;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);

    // a donation is broadcast by send_end itself, via finalize_transfer_end
    let receive_data = rcv_party.blind_receive();
    let recipient_map = recipient_map(&asset.asset_id, &receive_data.recipient_id, amount);
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            false,
        )
        .unwrap();
    party
        .wallet
        .set_apply_when_final(begin.batch_transfer_idx.unwrap())
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    let guard = stop_mining_when_alone();
    let txid = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );
    drop(guard);

    mine(false);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt) > 0);
    assert_eq!(
        party.get_asset_balance(&asset.asset_id).settled,
        AMOUNT - amount
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fail() {
    initialize();

    let amount: u64 = 66;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);

    // unknown batch transfer
    assert!(matches!(
        party.wallet.set_apply_when_final(9999),
        Err(Error::BatchTransferNotFound { idx: 9999 })
    ));

    // incoming batch transfer
    let receive_data = rcv_party.blind_receive();
    assert!(matches!(
        rcv_party
            .wallet
            .set_apply_when_final(receive_data.batch_transfer_idx),
        Err(Error::CannotSetApplyWhenFinal { details: _ })
    ));

    // 0 min_confirmations
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map(&asset.asset_id, &receive_data.recipient_id, amount),
            false,
            FEE_RATE,
            0,
            default_send_expiration(),
            false,
        )
        .unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();
    assert!(matches!(
        party.wallet.set_apply_when_final(batch_transfer_idx),
        Err(Error::CannotSetApplyWhenFinal { details: _ })
    ));
    assert!(party.fail_transfers_single(batch_transfer_idx));

    // no longer in Initiated status
    let receive_data = rcv_party.blind_receive();
    let begin = party
        .send_begin_result(&recipient_map(
            &asset.asset_id,
            &receive_data.recipient_id,
            amount,
        ))
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt, None).unwrap();
    party.wallet.send_end(party.online, signed_psbt).unwrap();
    assert!(matches!(
        party
            .wallet
            .set_apply_when_final(begin.batch_transfer_idx.unwrap()),
        Err(Error::CannotSetApplyWhenFinal { details: _ })
    ));
}
