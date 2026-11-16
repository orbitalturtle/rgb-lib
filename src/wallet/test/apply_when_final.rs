use super::*;

impl Wallet {
    pub(crate) fn set_apply_when_final(&mut self, batch_transfer_idx: i32) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        self.set_apply_when_final_in_txn(&txn, batch_transfer_idx)?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)
    }

    pub(crate) fn hand_off_deferred_transfer_for_test(
        &mut self,
        batch_transfer_idx: i32,
    ) -> Result<DbBatchTransfer, Error> {
        let txn = self.database().begin_transaction()?;
        let batch_transfer = self.hand_off_deferred_transfer(&txn, batch_transfer_idx)?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(batch_transfer)
    }
}

/// Number of outputs of the TX of `psbt` hosting an allocation of `asset_id` in the RGB runtime,
/// i.e. zero until the fascia of the TX has been applied to the RGB state.
fn rgb_allocated_outputs(party: &SinglesigParty, asset_id: &str, psbt: &str) -> usize {
    let psbt = Psbt::from_str(psbt).unwrap();
    let txid = psbt.unsigned_tx.compute_txid();
    let outpoints: Vec<OutPoint> = (0..psbt.unsigned_tx.output.len() as u32)
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

fn recipient_map(
    asset_id: &str,
    receive_data: &ReceiveData,
    amount: u64,
) -> HashMap<String, Vec<Recipient>> {
    blind_recipient_map(asset_id, receive_data, Assignment::Fungible(amount))
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
    let recipient_map = recipient_map(&asset.asset_id, &receive_data, amount);
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
    let recipient_map_2 = self::recipient_map(&asset.asset_id, &receive_data_2, AMOUNT - amount);
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
    let recipient_map = recipient_map(&asset.asset_id, &receive_data, amount);
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
    assert_eq!(get_tx_height(&txid), Some(1));
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
    let recipient_map = recipient_map(&asset.asset_id, &receive_data, amount);
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            Some(PROXY_ENDPOINT.clone()),
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
fn inputs_spent_elsewhere() {
    initialize();

    // more than one allocation holds, so that the send spends 2 inputs
    let amount: u64 = AMOUNT + 66;
    let min_confirmations = 2;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(Some(&[AMOUNT, AMOUNT]));

    let receive_data = rcv_party.blind_receive();
    let recipient_map = recipient_map(&asset.asset_id, &receive_data, amount);
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
    party
        .wallet
        .set_apply_when_final(begin.batch_transfer_idx.unwrap())
        .unwrap();

    // prepare a TX spending an input of the send, paying a higher fee than the send so it can
    // replace it
    let unsigned_tx = Psbt::from_str(&begin.psbt).unwrap().unsigned_tx;
    let input_value: u64 = unsigned_tx
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
    let output_value: u64 = unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let send_fee = input_value - output_value;
    assert!(unsigned_tx.input.len() >= 2);
    let outpoint = unsigned_tx.input[0].previous_output;
    let address = BdkAddress::from_str(&party.get_address()).unwrap();
    let mut tx_builder = party.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_utxo(outpoint)
        .unwrap()
        .manually_selected_only()
        .drain_to(address.assume_checked().script_pubkey())
        .fee_absolute(BdkAmount::from_sat(send_fee + 200));
    let conflicting_psbt = tx_builder.finish().unwrap();
    let conflicting_psbt = party
        .wallet
        .sign_psbt(conflicting_psbt.to_string(), None)
        .unwrap();
    let conflicting_tx = Psbt::from_str(&conflicting_psbt)
        .unwrap()
        .extract_tx()
        .unwrap();

    // the send is broadcast once the receiver ACKs, its RGB state left untouched (stop mining
    // so that no concurrent test can add confirmations to the conflicting TX)
    let guard = stop_mining_when_alone();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    let txid = party
        .wallet
        .send_end(party.online, signed_psbt)
        .unwrap()
        .txid;
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));

    // the conflicting TX replaces it and gets 1 confirmation: it could still be reorged out, so
    // the send isn't failed yet
    let conflicting_txid = conflicting_tx.compute_txid().to_string();
    party.wallet.broadcast_tx(conflicting_tx).unwrap();
    force_mine_no_resume_when_alone(false);
    assert_eq!(get_tx_height(&conflicting_txid), Some(1));
    party.refresh_asset(&asset.asset_id);
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));

    // at the transfer's min_confirmations the conflicting TX could still be reorged out by a short
    // reorg, which failing the send would make final: it waits for LOST_TX_MIN_CONFIRMATIONS
    force_mine_no_resume_when_alone(false);
    assert_eq!(get_tx_height(&conflicting_txid), Some(2));
    party.refresh_asset(&asset.asset_id);
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    drop(guard);

    // once the conflicting TX is final the send can never confirm: it is failed, with nothing to
    // roll back in the RGB state
    for _ in 0..2 * LOST_TX_MIN_CONFIRMATIONS {
        if party.check_test_transfer_status_sender(&txid, TransferStatus::Failed) {
            break;
        }
        mine(false);
        party.refresh_asset(&asset.asset_id);
    }
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Failed));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );

    // the inputs the conflicting TX didn't spend are unspent again, with their allocations, and
    // the outputs of the send, which will never exist, can't be selected
    let unspents = party.list_unspents(false);
    for input in &unsigned_tx.input[1..] {
        let outpoint = Outpoint::from(input.previous_output);
        assert!(unspents.iter().any(|u| u.utxo.outpoint == outpoint));
    }
    assert!(
        unspents
            .iter()
            .filter(|u| u.utxo.outpoint.txid == txid)
            .all(|u| !u.utxo.exists)
    );
    assert!(party.get_asset_balance(&asset.asset_id).spendable >= AMOUNT);
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
        Err(Error::Internal { details: _ })
    ));

    // 0 min_confirmations
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map(&asset.asset_id, &receive_data, amount),
            false,
            FEE_RATE,
            0,
            default_send_expiration(),
            Some(PROXY_ENDPOINT.clone()),
            false,
        )
        .unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();
    assert!(matches!(
        party.wallet.set_apply_when_final(batch_transfer_idx),
        Err(Error::Internal { details: _ })
    ));
    assert!(party.fail_transfers_single(batch_transfer_idx));

    // no longer in Initiated status
    let receive_data = rcv_party.blind_receive();
    let begin = party
        .send_begin_result(&recipient_map(&asset.asset_id, &receive_data, amount))
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt, None).unwrap();
    party.wallet.send_end(party.online, signed_psbt).unwrap();
    assert!(matches!(
        party
            .wallet
            .set_apply_when_final(begin.batch_transfer_idx.unwrap()),
        Err(Error::Internal { details: _ })
    ));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn handed_off() {
    initialize();

    let amount: u64 = 66;

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);

    let receive_data = rcv_party.blind_receive();
    let recipient_map = recipient_map(&asset.asset_id, &receive_data, amount);
    let begin = party.send_begin_result(&recipient_map).unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();
    let txid = Psbt::from_str(&begin.psbt)
        .unwrap()
        .unsigned_tx
        .compute_txid()
        .to_string();

    // only a transfer applying its RGB state once final can be handed off
    assert_matches!(
        party
            .wallet
            .hand_off_deferred_transfer_for_test(batch_transfer_idx),
        Err(Error::Internal { details: _ })
    );
    party
        .wallet
        .set_apply_when_final(batch_transfer_idx)
        .unwrap();

    // a flow whose TX isn't prepared by a *_begin call saves the files refresh needs itself, the
    // fascia committing to the TX of the PSBT
    let transfer_dir = party.wallet.get_transfer_dir(&txid);
    let fascia = read_fascia(&transfer_dir.join(FASCIA_FILE)).unwrap();
    let psbt = Psbt::from_str(&begin.psbt).unwrap();
    fs::remove_file(transfer_dir.join(UNSIGNED_PSBT_FILE)).unwrap();
    let mut other_psbt = psbt.clone();
    other_psbt.unsigned_tx.lock_time =
        bdk_wallet::bitcoin::absolute::LockTime::from_height(1).unwrap();
    assert_matches!(
        party
            .wallet
            .save_deferred_transfer_files(&other_psbt, &fascia),
        Err(Error::Internal { details: _ })
    );
    party
        .wallet
        .save_deferred_transfer_files(&psbt, &fascia)
        .unwrap();
    assert!(transfer_dir.join(UNSIGNED_PSBT_FILE).exists());

    // once handed off (twice: it's idempotent) it waits for confirmations and can't be failed
    for _ in 0..2 {
        let batch_transfer = party
            .wallet
            .hand_off_deferred_transfer_for_test(batch_transfer_idx)
            .unwrap();
        assert_eq!(batch_transfer.status, TransferStatus::WaitingConfirmations);
    }
    assert!(matches!(
        party
            .wallet
            .fail_transfers(party.online, Some(batch_transfer_idx), false, false),
        Err(Error::CannotFailBatchTransfer)
    ));

    // the TX is signed and broadcast outside of the transfer flow, its RGB state left untouched
    // and its inputs reserved until it is final
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    let tx = Psbt::from_str(&signed_psbt).unwrap().extract_tx().unwrap();
    let guard = stop_mining();
    party.wallet.broadcast_tx(tx).unwrap();
    party
        .wallet
        .refresh(party.online, None, vec![], false)
        .unwrap();
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations));
    assert_eq!(
        rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt),
        0
    );
    let reserved = |party: &SinglesigParty| {
        let txn = party.wallet.database().begin_transaction().unwrap();
        let reserved = txn
            .iter_reserved_txos()
            .unwrap()
            .into_iter()
            .filter(|r| r.reserved_for_colored == Some(batch_transfer_idx))
            .count();
        txn.commit().unwrap();
        reserved
    };
    assert!(reserved(&party) > 0);

    // once final its RGB state is applied, the transfer settles and its inputs are released
    drop(guard);
    mine(false);
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert!(rgb_allocated_outputs(&party, &asset.asset_id, &begin.psbt) > 0);
    assert_eq!(reserved(&party), 0);
}
