use super::*;

/// Number of outputs of `tx` hosting an allocation of `asset_id` in the RGB runtime.
fn rgb_allocated_outputs(party: &SinglesigParty, asset_id: &str, tx: &BdkTransaction) -> usize {
    let txid = tx.compute_txid();
    let outpoints: Vec<OutPoint> = (0..tx.output.len() as u32)
        .map(|vout| OutPoint { txid, vout })
        .collect();
    let txn = party.wallet.database().begin_transaction().unwrap();
    let stock = party.wallet.rgb_stock(&txn).unwrap();
    stock
        .contract_assignments_for(ContractId::from_str(asset_id).unwrap(), outpoints)
        .unwrap()
        .values()
        .filter(|assignments| !assignments.is_empty())
        .count()
}

/// Begin a send of `amount` of `asset_id` to `rcv_party`, returning the receive data and the
/// unsigned PSBT.
fn send_begin(
    party: &mut SinglesigParty,
    rcv_party: &mut SinglesigParty,
    asset_id: &str,
    amount: u64,
    min_confirmations: u8,
) -> (ReceiveData, String) {
    let receive_data = rcv_party.blind_receive();
    let recipient_map = blind_recipient_map(asset_id, &receive_data, Assignment::Fungible(amount));
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            false,
            FEE_RATE,
            min_confirmations,
            default_send_expiration(),
            Some(PROXY_ENDPOINT.clone()),
            false,
        )
        .unwrap();
    (receive_data, begin.psbt)
}

/// A signed TX spending `outpoint` back to the wallet, paying more fee than `tx` so it can
/// replace it.
fn conflicting_tx(
    party: &mut SinglesigParty,
    tx: &BdkTransaction,
    outpoint: BdkOutPoint,
) -> BdkTransaction {
    let input_value: u64 = tx
        .input
        .iter()
        .map(|i| {
            party
                .wallet
                .bdk_wallet()
                .get_utxo(i.previous_output)
                .unwrap()
                .txout
                .value
                .to_sat()
        })
        .sum();
    let output_value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = input_value - output_value;
    let address = BdkAddress::from_str(&party.get_address()).unwrap();
    let mut tx_builder = party.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_utxo(outpoint)
        .unwrap()
        .manually_selected_only()
        .drain_to(address.assume_checked().script_pubkey())
        .fee_absolute(BdkAmount::from_sat(fee + 200));
    let psbt = tx_builder.finish().unwrap();
    let psbt = party.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    Psbt::from_str(&psbt).unwrap().extract_tx().unwrap()
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn lost_to_conflicting_tx() {
    initialize();

    // more than one allocation holds, so that the send spends 2 inputs
    let amount: u64 = AMOUNT + 66;
    let min_confirmations = 2;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(Some(&[AMOUNT, AMOUNT]));

    let (_, psbt) = send_begin(
        &mut party,
        &mut rcv_party,
        &asset.asset_id,
        amount,
        min_confirmations,
    );
    let unsigned_tx = Psbt::from_str(&psbt).unwrap().unsigned_tx;
    assert!(unsigned_tx.input.len() >= 2);
    let conflicting_tx = conflicting_tx(
        &mut party,
        &unsigned_tx,
        unsigned_tx.input[0].previous_output,
    );
    let conflicting_txid = conflicting_tx.compute_txid().to_string();

    // the send is broadcast once the receiver ACKs and its RGB state is applied (stop mining so
    // that no concurrent test can add confirmations to the conflicting TX)
    let guard = stop_mining_when_alone();
    let signed_psbt = party.wallet.sign_psbt(psbt, None).unwrap();
    let txid = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &unsigned_tx) > 0);

    // the conflicting TX replaces it, but with fewer than min_confirmations the send isn't failed
    party.wallet.broadcast_tx(conflicting_tx).unwrap();
    force_mine_no_resume_when_alone(false);
    assert_eq!(get_tx_height(&conflicting_txid), Some(1));
    party.refresh_asset(&asset.asset_id);
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &unsigned_tx) > 0);

    // at min_confirmations the send is failed and its RGB state undone
    force_mine_no_resume_when_alone(false);
    assert_eq!(get_tx_height(&conflicting_txid), Some(2));
    party.refresh_asset(&asset.asset_id);
    drop(guard);
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Failed));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &unsigned_tx),
        0
    );

    // the inputs the conflicting TX didn't spend are unspent again, with their allocations, and
    // the outputs of the send, which will never exist, can't be selected
    let unspents = party.list_unspents(false);
    for input in &unsigned_tx.input[1..] {
        let outpoint = Outpoint::from(input.previous_output);
        let unspent = unspents
            .iter()
            .find(|u| u.utxo.outpoint == outpoint)
            .unwrap();
        assert!(!unspent.rgb_allocations.is_empty());
    }
    assert!(
        unspents
            .iter()
            .filter(|u| u.utxo.outpoint.txid == txid)
            .all(|u| !u.utxo.exists)
    );
    // the allocation on the input the conflicting TX spent is gone
    let balance = party.get_asset_balance(&asset.asset_id);
    assert_eq!(balance.settled, AMOUNT);
    assert_eq!(balance.spendable, AMOUNT);

    // the restored allocation can be sent and the receiver validates its history
    let (receive_data, psbt) = send_begin(
        &mut party,
        &mut rcv_party,
        &asset.asset_id,
        AMOUNT,
        MIN_CONFIRMATIONS,
    );
    let signed_psbt = party.wallet.sign_psbt(psbt, None).unwrap();
    let txid_2 = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    mine(false);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid_2, TransferStatus::Settled));
    assert!(
        rcv_party.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::Settled
        )
    );
    assert_eq!(party.get_asset_balance(&asset.asset_id).settled, 0);
    assert_eq!(rcv_party.get_asset_balance(&asset.asset_id).settled, AMOUNT);
}
