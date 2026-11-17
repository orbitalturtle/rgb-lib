//! Utilities.
//!
//! This module defines some utility methods and structures.

use super::*;

pub use crate::no_wallet::{recipient_id_from_script_buf, script_buf_from_recipient_id};

const TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour repr:24]:[minute]:[second].[subsecond digits:3]+00"
);

#[cfg(feature = "rgb_fs_store_migration")]
pub(crate) const RGB_RUNTIME_DIR: &str = "rgb";

/// Where the legacy filesystem RGB store is moved to be deleted, once migrated into the DB, so
/// that retiring it is atomic. Only ever on disk between that rename and the delete: a crash in
/// between leaves this dir, which the next wallet open sweeps up and every backup skips.
pub(crate) const RGB_RUNTIME_DELETING_DIR: &str = "rgb.deleting";
pub(crate) const LOG_FILE: &str = "log";

pub(crate) const PURPOSE: u8 = 86;
pub(crate) const COIN_RGB_MAINNET: u32 = 827166;
pub(crate) const COIN_RGB_TESTNET: u32 = 827167;
pub(crate) const ACCOUNT: u8 = 0;
pub(crate) const KEYCHAIN_RGB: u8 = 0;
pub(crate) const KEYCHAIN_BTC: u8 = 0;

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const INDEXER_STOP_GAP: usize = 20;
#[cfg(feature = "electrum")]
pub(crate) const INDEXER_BATCH_SIZE: usize = 5;
#[cfg(feature = "esplora")]
pub(crate) const INDEXER_PARALLEL_REQUESTS: usize = 5;

#[cfg(feature = "_online")]
const PROXY_PROTOCOL_VERSION: &str = "1.0";

// sea-orm with runtime-tokio-rustls needs a tokio runtime for connection pool management
static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("failed to create the runtime"));

/// Block on a future, spawning a new thread if already inside a Tokio runtime.
pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        // avoid blocking the Tokio runtime thread; spawn a new thread
        std::thread::scope(|s| {
            s.spawn(|| TOKIO_RUNTIME.block_on(future))
                .join()
                .expect("rgb-lib block_on thread panicked")
        })
    } else {
        TOKIO_RUNTIME.block_on(future)
    }
}

/// Make a newly created file's directory entry durable.
///
/// [`File::sync_all`](fs::File::sync_all) covers a file's own data and metadata but not the entry
/// that names it, so without this a freshly created file can still vanish on power loss.
#[cfg(not(target_os = "windows"))]
pub(crate) fn sync_dir<P: AsRef<Path>>(dir: P) -> Result<(), io::Error> {
    fs::File::open(dir)?.sync_all()
}

/// Windows cannot open a directory as a file and offers no portable equivalent, so the directory
/// entry is left to the filesystem's own ordering there.
#[cfg(target_os = "windows")]
pub(crate) fn sync_dir<P: AsRef<Path>>(_dir: P) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
    p.as_ref().display().to_string()
}

#[cfg(target_os = "windows")]
pub(crate) fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
    const VERBATIM_PREFIX: &str = r#"\\?\"#;
    let p = p.as_ref().display().to_string();
    if p.starts_with(VERBATIM_PREFIX) {
        p[VERBATIM_PREFIX.len()..].to_string()
    } else {
        p
    }
}

fn deserialize_str_or_number<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    struct StringOrNumberVisitor<T>(std::marker::PhantomData<T>);

    impl<T> Visitor<'_> for StringOrNumberVisitor<T>
    where
        T: FromStr + Copy,
        T::Err: fmt::Display,
    {
        type Value = Option<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string, a number, or null")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::from_str(&value.to_string())
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::from_str(&value.to_string())
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<T>().map(Some).map_err(|e| {
                de::Error::invalid_value(Unexpected::Str(value), &e.to_string().as_str())
            })
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrNumberVisitor(std::marker::PhantomData))
}

pub(crate) fn from_str_or_number_mandatory<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    match deserialize_str_or_number(deserializer)? {
        Some(val) => Ok(val),
        None => Err(de::Error::custom("expected a number but got null")),
    }
}

pub(crate) fn from_str_or_number_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    deserialize_str_or_number(deserializer)
}

pub(crate) fn str_to_xpub(xpub: &str, network_kind: &NetworkKind) -> Result<Xpub, Error> {
    let pubkey_btc = Xpub::from_str(xpub)?;
    let extended_key_btc: ExtendedKey = ExtendedKey::from(pubkey_btc);
    Ok(extended_key_btc.into_xpub(*network_kind, &Secp256k1::new()))
}

pub(crate) fn get_coin_type(bitcoin_network: &BitcoinNetwork, rgb: bool) -> u32 {
    match (bitcoin_network, rgb) {
        (BitcoinNetwork::Mainnet, true) => COIN_RGB_MAINNET,
        (_, true) => COIN_RGB_TESTNET,
        (_, false) => u32::from(*bitcoin_network != BitcoinNetwork::Mainnet),
    }
}

pub(crate) fn get_account_derivation_children(
    witness_version: WitnessVersion,
    coin_type: u32,
) -> Vec<ChildNumber> {
    vec![
        ChildNumber::from_hardened_idx(witness_version.purpose()).unwrap(),
        ChildNumber::from_hardened_idx(coin_type).unwrap(),
        ChildNumber::from_hardened_idx(ACCOUNT as u32).unwrap(),
    ]
}

fn derive_account_xprv_from_mnemonic(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    rgb: bool,
    witness_version: WitnessVersion,
) -> Result<(Xpriv, Fingerprint), Error> {
    let coin_type = get_coin_type(bitcoin_network, rgb);
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic.to_string())?;
    let master_xprv = Xpriv::new_master(*bitcoin_network, &mnemonic.to_seed("")).unwrap();
    let master_xpub = Xpub::from_priv(&Secp256k1::new(), &master_xprv);
    let master_fingerprint = master_xpub.fingerprint();
    let account_xprv = master_xprv.derive_priv(&Secp256k1::new(), &account_derivation_children)?;
    Ok((account_xprv, master_fingerprint))
}

fn get_xpub_from_xprv(xprv: &Xpriv) -> Xpub {
    Xpub::from_priv(&Secp256k1::new(), xprv)
}

/// Get the account-level xPriv and xPub for the given mnemonic, Bitcoin network and witness
/// version, based on the requested wallet side (colored or vanilla).
pub fn get_account_data(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    rgb: bool,
    witness_version: WitnessVersion,
) -> Result<(Xpriv, Xpub, Fingerprint), Error> {
    let (account_xprv, master_fingerprint) =
        derive_account_xprv_from_mnemonic(bitcoin_network, mnemonic, rgb, witness_version)?;
    let account_xpub = get_xpub_from_xprv(&account_xprv);
    Ok((account_xprv, account_xpub, master_fingerprint))
}

pub(crate) fn get_account_xpubs(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    witness_version: WitnessVersion,
) -> Result<(Xpub, Xpub), Error> {
    let (_, account_xpub_vanilla, _) =
        get_account_data(bitcoin_network, mnemonic, false, witness_version)?;
    let (_, account_xpub_colored, _) =
        get_account_data(bitcoin_network, mnemonic, true, witness_version)?;
    Ok((account_xpub_vanilla, account_xpub_colored))
}

fn derive_descriptor(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    rgb: bool,
    keychain: u8,
    expected_xpub: &Xpub,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    let (account_xprv, account_xpub, master_fingerprint) =
        get_account_data(bitcoin_network, mnemonic, rgb, witness_version)?;
    if account_xpub != *expected_xpub {
        return Err(Error::InvalidBitcoinKeys);
    }
    let coin_type = get_coin_type(bitcoin_network, rgb);
    calculate_descriptor_from_xprv(
        &master_fingerprint,
        coin_type,
        account_xprv,
        keychain,
        witness_version,
    )
}

pub(crate) fn get_descriptors(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    vanilla_keychain: Option<u8>,
    expected_xpub_btc: &Xpub,
    expected_xpub_rgb: &Xpub,
    witness_version: WitnessVersion,
) -> Result<WalletDescriptors, Error> {
    let colored = derive_descriptor(
        bitcoin_network,
        mnemonic,
        true,
        KEYCHAIN_RGB,
        expected_xpub_rgb,
        witness_version,
    )?;
    let vanilla = derive_descriptor(
        bitcoin_network,
        mnemonic,
        false,
        vanilla_keychain.unwrap_or(KEYCHAIN_BTC),
        expected_xpub_btc,
        witness_version,
    )?;
    Ok(WalletDescriptors { colored, vanilla })
}

pub(crate) fn get_descriptors_from_xpubs(
    bitcoin_network: &BitcoinNetwork,
    master_fingerprint: &str,
    xpub_rgb: &Xpub,
    xpub_btc: &Xpub,
    vanilla_keychain: Option<u8>,
    witness_version: WitnessVersion,
) -> Result<WalletDescriptors, Error> {
    let master_fingerprint =
        Fingerprint::from_str(master_fingerprint).map_err(|_| Error::InvalidFingerprint)?;
    let colored = calculate_descriptor_from_xpub(
        &master_fingerprint,
        get_coin_type(bitcoin_network, true),
        xpub_rgb,
        KEYCHAIN_RGB,
        witness_version,
    )?;
    let vanilla = calculate_descriptor_from_xpub(
        &master_fingerprint,
        get_coin_type(bitcoin_network, false),
        xpub_btc,
        vanilla_keychain.unwrap_or(KEYCHAIN_BTC),
        witness_version,
    )?;
    Ok(WalletDescriptors { colored, vanilla })
}

pub(crate) fn parse_address_str(
    address: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<BdkAddress, Error> {
    BdkAddress::from_str(address)
        .map_err(|e| Error::InvalidAddress {
            details: e.to_string(),
        })?
        .require_network(bitcoin_network.into())
        .map_err(|_| Error::InvalidAddress {
            details: s!("belongs to another network"),
        })
}

/// The URL of a BFA reject list, if the contract declares one served at a URL.
///
/// This is only the URL recorded in the DB and reported in the asset metadata: a reject list kept
/// by an EVM contract has no URL, so it gives `None` here, but it is still enforced, as the reject
/// list of a BFA asset is read off its genesis when needed (see `genesis_reject_list_source`).
pub(crate) fn bfa_reject_list_url(location: Option<RejectListLocation>) -> Option<String> {
    match location? {
        RejectListLocation::Url(url) => Some(url.to_string()),
        RejectListLocation::Evm(_) => None,
    }
}

fn get_derivation_path(keychain: u8) -> DerivationPath {
    let derivation_path = vec![ChildNumber::from_normal_idx(keychain as u32).unwrap()];
    DerivationPath::from_iter(derivation_path.clone())
}

pub(crate) fn get_extended_derivation_path(
    mut account_derivation_children: Vec<ChildNumber>,
    keychain: u8,
) -> DerivationPath {
    let keychain_child = ChildNumber::from_normal_idx(keychain as u32).unwrap();
    account_derivation_children.push(keychain_child);
    DerivationPath::from_iter(account_derivation_children.clone())
}

pub(crate) fn calculate_descriptor_from_xprv(
    master_fingerprint: &Fingerprint,
    coin_type: u32,
    xprv: Xpriv,
    keychain: u8,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    // derive final xpub from account-level xpub
    let path = get_derivation_path(keychain);
    let der_xprv = &xprv
        .derive_priv(&Secp256k1::new(), &path)
        .expect("provided path should be derivable in an xprv");
    // derive descriptor with master fingerprint and full derivation path
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let full_path = get_extended_derivation_path(account_derivation_children, keychain);
    let origin_prv: KeySource = (*master_fingerprint, full_path.clone());
    let der_xprv_desc_key: DescriptorKey<Segwitv0> = der_xprv
        .into_descriptor_key(Some(origin_prv), DerivationPath::default())
        .expect("should be able to convert xprv in a descriptor key");
    let Secret(key, _, _) = der_xprv_desc_key else {
        unreachable!("into_descriptor_key on an Xpriv always yields a Secret variant")
    };
    Ok(format!("{}({key})", witness_version.descriptor_fn()))
}

pub(crate) fn calculate_descriptor_from_xpub(
    master_fingerprint: &Fingerprint,
    coin_type: u32,
    xpub: &Xpub,
    keychain: u8,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    // derive final xpub from account-level xpub
    let path = get_derivation_path(keychain);
    let der_xpub = xpub
        .derive_pub(&Secp256k1::new(), &path)
        .expect("provided path should be derivable in an xpub");
    // derive descriptor with master fingerprint and full derivation path
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let full_path = get_extended_derivation_path(account_derivation_children, keychain);
    let origin_pub: KeySource = (*master_fingerprint, full_path);
    let der_xpub_desc_key: DescriptorKey<Segwitv0> = der_xpub
        .into_descriptor_key(Some(origin_pub), DerivationPath::default())
        .expect("should be able to convert xpub in a descriptor key");
    let Public(key, _, _) = der_xpub_desc_key else {
        unreachable!("into_descriptor_key on an Xpub always yields a Public variant")
    };
    Ok(format!("{}({key})", witness_version.descriptor_fn()))
}

/// The retention grace advertised by a proxy (`retention_grace_secs`), i.e. how long after an
/// expiration it keeps the data awaiting retrieval. A proxy not advertising it is considered to
/// grant none.
#[cfg(feature = "_online")]
pub(crate) fn proxy_retention_grace(info: &ServerInfoResponse) -> u32 {
    #[cfg(test)]
    if let Some(grace) = mock_retention_grace() {
        return grace;
    }
    info.retention_grace_secs
        .as_ref()
        .and_then(|grace| grace.parse::<u32>().ok())
        .unwrap_or(0)
}

/// The max number of media per transfer advertised by a proxy (`max_media`), `None` if it doesn't
/// advertise a valid one.
#[cfg(feature = "_online")]
pub(crate) fn proxy_max_media(info: &ServerInfoResponse) -> Option<usize> {
    info.max_media.as_ref().and_then(|max| max.parse().ok())
}

/// Check that the proxy at `proxy_url` runs the supported protocol version, returning its info.
#[cfg(feature = "_online")]
pub(crate) fn check_proxy(proxy_url: &str) -> Result<ServerInfoResponse, Error> {
    let proxy_client = ProxyClient::new(proxy_url)?;
    let server_info = proxy_client.get_info()?;
    if let Some(info) = server_info.result {
        if info.protocol_version == *PROXY_PROTOCOL_VERSION {
            return Ok(info);
        } else {
            return Err(Error::InvalidProxyProtocol {
                version: info.protocol_version,
            });
        }
    }
    let details = match server_info.error {
        Some(err) => err.message,
        None => s!("proxy response has neither result nor error"),
    };
    Err(Error::Proxy { details })
}

#[cfg(feature = "_online")]
pub(crate) fn get_indexer_and_resolver(
    indexer_config: &IndexerConfig,
    bitcoin_network: BitcoinNetwork,
) -> Result<(Indexer, AnyResolver), Error> {
    #[cfg_attr(not(feature = "bitcoind"), allow(unused_mut))]
    let mut indexer = build_indexer(indexer_config)?;
    // this also checks connectivity (and credentials for bitcoind)
    indexer.block_hash(0).map_err(|e| Error::InvalidIndexer {
        details: unreachable_indexer_details(indexer_config, &e),
    })?;
    #[allow(irrefutable_let_patterns)]
    #[cfg(feature = "bitcoind")]
    if let Indexer::Bitcoind(client) = &mut indexer {
        client.block_filters = checked_bitcoind_indexes(&client.inner)?.block_filters;
    }

    let resolver = get_resolver(indexer_config, bitcoin_network)?;

    Ok((indexer, resolver))
}

/// Build the indexer client described by `indexer_config`.
///
/// Fails if support for the configured indexer is not compiled in. The returned client has not
/// contacted the service yet, except for electrum, whose client connects on creation.
#[cfg(feature = "_online")]
pub(crate) fn build_indexer(indexer_config: &IndexerConfig) -> Result<Indexer, Error> {
    match indexer_config {
        #[cfg(feature = "bitcoind")]
        IndexerConfig::Bitcoind { url, auth } => {
            let client =
                BitcoindRpcClient::new(url, auth.into()).map_err(|e| Error::InvalidIndexer {
                    details: unreachable_indexer_details(indexer_config, &e),
                })?;
            Ok(Indexer::Bitcoind(Box::new(BitcoindClient {
                inner: client,
                block_filters: false,
            })))
        }
        #[cfg(feature = "electrum")]
        IndexerConfig::Electrum { url } => {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let client = ElectrumClient::from_config(url, electrum_config()).map_err(|e| {
                Error::InvalidIndexer {
                    details: unreachable_indexer_details(indexer_config, &e),
                }
            })?;
            Ok(Indexer::Electrum(Box::new(BdkElectrumClient::new(client))))
        }
        #[cfg(feature = "esplora")]
        IndexerConfig::Esplora { url } => Ok(Indexer::Esplora(Box::new(
            EsploraClient::from_builder(esplora_config(url)),
        ))),
        #[cfg(not(all(feature = "bitcoind", feature = "electrum", feature = "esplora")))]
        _ => {
            let feature = match indexer_config {
                IndexerConfig::Bitcoind { .. } => "bitcoind",
                IndexerConfig::Electrum { .. } => "electrum",
                IndexerConfig::Esplora { .. } => "esplora",
            };
            Err(Error::InvalidIndexer {
                details: format!(
                    "{feature} support is not enabled (requires the `{feature}` feature)"
                ),
            })
        }
    }
}

/// Detect which indexer is served at `indexer_url`: a Bitcoin Core node when `bitcoind_auth` is
/// provided, otherwise an electrum or esplora server (detected by trying electrum first).
///
/// Returns `None` if no supported indexer can be detected.
#[cfg(feature = "_online")]
pub(crate) fn detect_indexer(
    indexer_url: &str,
    bitcoind_auth: Option<&BitcoindAuth>,
) -> Option<IndexerConfig> {
    if let Some(auth) = bitcoind_auth {
        return cfg!(feature = "bitcoind").then(|| IndexerConfig::Bitcoind {
            url: indexer_url.to_string(),
            auth: auth.clone(),
        });
    }
    let electrum = IndexerConfig::Electrum {
        url: indexer_url.to_string(),
    };
    if build_indexer(&electrum).is_ok() {
        return Some(electrum);
    }
    cfg!(feature = "esplora").then(|| IndexerConfig::Esplora {
        url: indexer_url.to_string(),
    })
}

pub(crate) fn hash_bytes(data: &[u8]) -> Vec<u8> {
    sha256_digest(data).to_vec()
}

pub(crate) fn hash_bytes_hex(data: &[u8]) -> String {
    hex::encode(hash_bytes(data))
}

/// Atomically materialize a file at `path`.
///
/// The `write` closure writes to a temporary file in the same directory, which
/// is then fsynced and renamed into place. Since `rename` is atomic on a
/// single filesystem, a reader (or a crash) never observes a partially-written
/// file. The fsync (plus a best-effort directory fsync) makes the result
/// durable across a power loss.
pub(crate) fn atomic_write_with<F>(path: &Path, write: F) -> Result<(), Error>
where
    F: FnOnce(&Path) -> Result<(), Error>,
{
    let parent = path.parent().ok_or_else(|| Error::Internal {
        details: format!("cannot atomically write {path:?}: no parent directory"),
    })?;
    fs::create_dir_all(parent)?;
    let tmp = atomic_tmp_path(path)?;
    // drop any temp file leaked by an earlier crash
    let _ = fs::remove_file(&tmp);
    if let Err(e) = write(&tmp) {
        // don't leave a partial temp file behind (best-effort)
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // fsync the temp file contents before making them visible
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, path)?;
    // fsync the parent directory so the rename entry itself is durable (a no-op on Windows, where
    // a directory can't be opened as a file: the data is already fsynced and only the durability
    // of the rename across a power loss is left to the filesystem)
    sync_dir(parent)?;
    Ok(())
}

/// The temporary file `atomic_write_with` stages `path` in before renaming it into place.
///
/// Exposed so a loader can recover a temp file left behind by a crash between the write and the
/// rename.
pub(crate) fn atomic_tmp_path(path: &Path) -> Result<PathBuf, Error> {
    let parent = path.parent().ok_or_else(|| Error::Internal {
        details: format!("cannot atomically write {path:?}: no parent directory"),
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Internal {
            details: format!("cannot atomically write {path:?}: invalid file name"),
        })?;
    Ok(parent.join(format!(".{file_name}.tmp")))
}

/// Atomically write `bytes` to `path`.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    atomic_write_with(path, |tmp| Ok(fs::write(tmp, bytes)?))
}

/// Remove the RGB data (operations, consumers and commitment data) from the given PSBT, once they
/// are committed: the commitment is in its TX and the operations are in the fascia, so they aren't
/// needed to sign it and broadcast its TX, and, spending UTXOs with many allocations, they could
/// make the PSBT too large to be parsed back (see [`check_psbt_parsable`]).
#[cfg(feature = "wallet")]
pub(crate) fn strip_rgb_data(psbt: &mut Psbt) {
    psbt.proprietary.retain(|key, _| !is_rgb_key(key));
    for input in &mut psbt.inputs {
        input.proprietary.retain(|key, _| !is_rgb_key(key));
    }
    for output in &mut psbt.outputs {
        output.proprietary.retain(|key, _| !is_rgb_key(key));
    }
}

/// Whether the given PSBT proprietary key holds RGB data (transitions, commitments or their
/// hosts).
#[cfg(feature = "wallet")]
pub(crate) fn is_rgb_key(key: &bdk_wallet::bitcoin::psbt::raw::ProprietaryKey) -> bool {
    [
        &PSBT_RGB_PREFIX[..],
        &PSBT_MPC_PREFIX[..],
        &PSBT_OPRET_PREFIX[..],
        &PSBT_TAPRET_PREFIX[..],
    ]
    .contains(&key.prefix.as_slice())
}

/// Maximum number of inputs, and of outputs, of a PSBT built outside of the wallet.
#[cfg(feature = "_online")]
const MAX_EXTERNAL_PSBT_IO: usize = 1000;

#[cfg(feature = "_online")]
fn invalid_coloring_info(details: impl Into<String>) -> Error {
    Error::InvalidColoringInfo {
        details: details.into(),
    }
}

// used by the on-chain swap and HTLC flows built on top of them
#[cfg(feature = "_online")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn input_set(psbt: &Psbt) -> HashSet<OutPoint> {
    psbt.unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect()
}

/// Check a PSBT built outside of the wallet before coloring it, and return a copy of it with the
/// OP_RETURN output hosting the RGB commitment, plus whether that output is first (i.e. whether
/// the PSBT has Taproot outputs). As in `color_psbt`, output indexes in the coloring info then
/// exclude the OP_RETURN output and shift by one, whether the output was added here or was
/// already in the PSBT.
///
/// The PSBT is refused when coloring it could commit to the wrong data or produce a TX that
/// can't carry the commitment: when it is already (partially) signed, carries RGB data already,
/// spends inputs other than P2WPKH, P2WSH or P2TR ones, has duplicate inputs or inconsistent
/// input data, asks for a sighash type other than ALL (or DEFAULT on Taproot inputs), which would
/// let its outputs, and so the commitment, change after signing, is too heavy to be relayed once
/// the commitment is added or has an OP_RETURN output that can't host the commitment (with
/// unrelated data, after a Taproot output or more than one). The input and output data of the
/// PSBT are kept, and the PSBT itself is never modified.
#[cfg(feature = "_online")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn prepare_external_psbt(psbt: &Psbt) -> Result<(Psbt, bool), Error> {
    if psbt.inputs.is_empty() || psbt.outputs.is_empty() {
        return Err(invalid_coloring_info("PSBT has no inputs or no outputs"));
    }
    if psbt.inputs.len() > MAX_EXTERNAL_PSBT_IO || psbt.outputs.len() > MAX_EXTERNAL_PSBT_IO {
        return Err(invalid_coloring_info(format!(
            "PSBT has more than {MAX_EXTERNAL_PSBT_IO} inputs or outputs"
        )));
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(invalid_coloring_info(
            "PSBT input or output maps don't match its TX",
        ));
    }
    if input_set(psbt).len() != psbt.inputs.len() {
        return Err(invalid_coloring_info("PSBT has duplicate inputs"));
    }
    if psbt.proprietary.keys().any(is_rgb_key)
        || psbt
            .outputs
            .iter()
            .any(|output| output.proprietary.keys().any(is_rgb_key))
    {
        return Err(invalid_coloring_info(
            "PSBT already contains RGB commitments",
        ));
    }
    for (index, (input, txin)) in psbt.inputs.iter().zip(&psbt.unsigned_tx.input).enumerate() {
        if !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || !txin.script_sig.is_empty()
            || !txin.witness.is_empty()
        {
            return Err(invalid_coloring_info("cannot color an already signed PSBT"));
        }
        if input.proprietary.keys().any(is_rgb_key) {
            return Err(invalid_coloring_info(
                "PSBT input already contains RGB consumers",
            ));
        }
        let witness = input.witness_utxo.as_ref().ok_or_else(|| {
            invalid_coloring_info(format!("PSBT input {index} has no witness_utxo"))
        })?;
        let script = &witness.script_pubkey;
        if !(script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr())
            || input.redeem_script.is_some()
        {
            return Err(invalid_coloring_info(
                "PSBT inputs must be P2WPKH, P2WSH or P2TR",
            ));
        }
        // ALL (0x01) commits to every output, and so does DEFAULT (0x00), which only Taproot has
        if input.sighash_type.is_some_and(|sighash_type| {
            let sighash_type = sighash_type.to_u32();
            sighash_type > 1 || (sighash_type == 0 && !script.is_p2tr())
        }) {
            return Err(invalid_coloring_info(
                "PSBT inputs must be signed with sighash type ALL",
            ));
        }
        if let Some(previous) = &input.non_witness_utxo
            && (previous.compute_txid() != txin.previous_output.txid
                || previous.output.get(txin.previous_output.vout as usize) != Some(witness))
        {
            return Err(invalid_coloring_info(
                "PSBT previous output does not match witness_utxo",
            ));
        }
    }
    let mut working = psbt.clone();
    let shift = working
        .unsigned_tx
        .output
        .iter()
        .any(|output| output.script_pubkey.is_p2tr());
    let hosts: Vec<usize> = working
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| output.script_pubkey.is_op_return().then_some(index))
        .collect();
    match hosts.as_slice() {
        [] => {
            let host = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            if shift {
                working.unsigned_tx.output.insert(0, host);
                working.outputs.insert(0, Default::default());
            } else {
                working.unsigned_tx.output.push(host);
                working.outputs.push(Default::default());
            }
        }
        [index] if !shift || *index == 0 => {
            // an empty OP_RETURN or rgb-lib's own placeholder, sized for the commitment so that
            // fee estimation accounts for it (see prepare_psbt)
            let host = &working.unsigned_tx.output[*index];
            if host.value != BdkAmount::ZERO
                || (host.script_pubkey != ScriptBuf::new_op_return([])
                    && host.script_pubkey != ScriptBuf::new_op_return([0; 32]))
            {
                return Err(invalid_coloring_info(
                    "PSBT OP_RETURN contains unrelated data",
                ));
            }
        }
        _ => {
            return Err(invalid_coloring_info(
                "PSBT needs one OP_RETURN before Taproot outputs",
            ));
        }
    }
    // the weight without witnesses, with the 32-byte commitment the host gets once colored, is
    // a lower bound: a TX over the limit can never be relayed
    let commitment_weight = if working
        .unsigned_tx
        .output
        .iter()
        .any(|output| output.script_pubkey == ScriptBuf::new_op_return([]))
    {
        // the host's script grows from OP_RETURN to OP_RETURN OP_PUSHBYTES_32 <32 bytes>
        33 * 4
    } else {
        0
    };
    if working.unsigned_tx.weight().to_wu() + commitment_weight
        > u64::from(bdk_wallet::bitcoin::policy::MAX_STANDARD_TX_WEIGHT)
    {
        return Err(invalid_coloring_info("PSBT TX is too heavy to be relayed"));
    }
    Ok((working, shift))
}

/// Check that the given PSBT can be parsed back, which fails if its global map exceeds
/// MAX_VEC_SIZE bytes. Such a PSBT can't be signed by an external signer nor be read back to
/// broadcast its TX.
///
/// This is a safety check, run before anything is saved or posted: once its RGB data are removed
/// (see [`strip_rgb_data`]), the PSBT of an operation stays far below that bound.
#[cfg(feature = "wallet")]
pub(crate) fn check_psbt_parsable(psbt: &Psbt) -> Result<(), Error> {
    Psbt::deserialize(&psbt.serialize())
        .map(|_| ())
        .map_err(|e| Error::Internal {
            details: format!("PSBT can't be parsed back: {e}"),
        })
}

/// Write a fascia file atomically, so a crash mid-write cannot leave a torn one behind.
#[cfg(any(feature = "_online", feature = "rgb_fs_store_migration"))]
pub(crate) fn write_fascia(path: &Path, fascia: &Fascia) -> Result<(), Error> {
    let bytes = fascia
        .to_strict_serialized::<FASCIA_MAX_LEN>()
        .map_err(|e| Error::Internal {
            details: format!("cannot serialize fascia {}: {e}", path.display()),
        })?;
    atomic_write(path, &bytes)
}

#[cfg(feature = "_online")]
pub(crate) fn hash_file(path: &Path) -> Result<String, Error> {
    let mut file = fs::File::open(path)?;
    let mut engine = sha256::HashEngine::default();
    let mut buffer = [0u8; 8192];
    while let Ok(n) = file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        engine.input(&buffer[..n]);
    }
    Ok(sha256::Hash::from_engine(engine).to_string())
}

fn log_timestamp(io: &mut dyn io::Write) -> io::Result<()> {
    let now: time::OffsetDateTime = now();
    write!(
        io,
        "{}",
        now.format(TIMESTAMP_FORMAT)
            .expect("OffsetDateTime::format with a static format description is infallible")
    )
}

pub(crate) fn setup_logger<P: AsRef<Path>>(
    log_path: P,
    log_name: Option<&str>,
) -> Result<(Logger, AsyncGuard), Error> {
    let log_file = log_name.unwrap_or(LOG_FILE);
    let log_filepath = log_path.as_ref().join(log_file);
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_filepath)?;

    let decorator = PlainDecorator::new(file);
    let drain = FullFormat::new(decorator)
        .use_custom_timestamp(log_timestamp)
        .use_file_location();
    let (drain, async_guard) = slog_async::Async::new(drain.build().fuse()).build_with_guard();
    let logger = Logger::root(drain.fuse(), o!());

    Ok((logger, async_guard))
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) struct DumbResolver;

impl ResolveWitness for DumbResolver {
    fn resolve_witness(&self, _: RgbTxid) -> Result<WitnessStatus, WitnessResolverError> {
        unreachable!()
    }

    fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> {
        Ok(())
    }
}

/// Wrapper for the RGB stock.
///
/// Every read and write goes through the borrowed database transaction, so concurrent access is
/// serialized by the database itself (a single connection per process, SQLite locking across
/// processes) and no separate lock is needed.
// `pub` only because it appears in the signatures of `WalletOffline`/`WalletOnline` methods,
// supertraits of the public `RgbWalletOps*` traits; not part of the public API
#[doc(hidden)]
#[derive(Debug)]
pub struct RgbStock<'txn> {
    /// The RGB stock, writing through the shared database transaction borrowed for `'txn`
    stock: Stock<&'txn DbTxn>,
}

impl<'txn> RgbStock<'txn> {
    /// Build an [`RgbStock`] whose `Stock` reads and writes through the shared rgb-lib
    /// transaction. The store borrows `db_txn` for `'txn`, so the stock cannot outlive the
    /// transaction's commit.
    pub(crate) fn new(db_txn: &'txn DbTxn) -> Self {
        Self {
            stock: Stock::with(db_txn),
        }
    }

    #[cfg(feature = "_online")]
    pub(crate) fn accept_transfer<R: ResolveWitness>(
        &mut self,
        contract: ValidTransfer,
        resolver: &R,
    ) -> Result<(), Error> {
        self.stock
            .accept_transfer(contract, resolver)
            .map_err(Error::from)
    }

    pub(crate) fn consume_fascia(
        &mut self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        struct FasciaResolver {
            witness_id: RgbTxid,
            witness_ord: WitnessOrd,
        }
        impl WitnessOrdProvider for FasciaResolver {
            fn witness_ord(&self, witness_id: RgbTxid) -> Result<WitnessOrd, WitnessResolverError> {
                debug_assert_eq!(witness_id, self.witness_id);
                Ok(self.witness_ord)
            }
        }

        let resolver = FasciaResolver {
            witness_id: fascia.witness_id(),
            witness_ord: witness_ord.unwrap_or(WitnessOrd::Tentative),
        };

        self.stock
            .consume_fascia(fascia, resolver)
            .map_err(Error::from)
    }

    pub(crate) fn contract_wrapper<C: IssuerWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<C::Wrapper<ContractStateSnapshot>, Error> {
        self.stock
            .contract_wrapper::<C>(contract_id)
            .map_err(Error::from)
    }

    /// The assignments on the given outpoints of every contract assigning state there, in a
    /// single store query
    #[cfg(feature = "_online")]
    pub(crate) fn assignments_by_contract(
        &self,
        outpoints: impl IntoIterator<Item = impl Into<OutPoint>>,
    ) -> Result<BTreeMap<ContractId, ContractAssignments>, Error> {
        self.stock
            .assignments_by_contract(outpoints)
            .map_err(Error::from)
    }

    pub(crate) fn genesis(&self, contract_id: ContractId) -> Result<Genesis, Error> {
        self.stock
            .as_store()
            .genesis(contract_id)?
            .ok_or_else(|| Error::Internal {
                details: format!("genesis {contract_id} not found"),
            })
    }

    pub(crate) fn import_contract<R: ResolveWitness>(
        &mut self,
        contract: ValidContract,
        resolver: &R,
    ) -> Result<(), Error> {
        self.stock
            .import_contract(contract, resolver)
            .map_err(Error::from)
    }

    pub(crate) fn import_schema_definition(
        &mut self,
        schema_def: SchemaDefinition,
    ) -> Result<(), Error> {
        self.stock
            .import_schema_definition(schema_def)
            .map_err(Error::from)
    }

    pub(crate) fn consignment_data<const TRANSFER: bool>(
        &self,
        consignment: &ValidConsignment<TRANSFER>,
    ) -> Result<ContractData<FilteredContractState>, Error> {
        self.stock
            .consignment_data(consignment)
            .map_err(Error::from)
    }

    pub(crate) fn contract_assignments_for(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<OutPoint>>,
    ) -> Result<ContractAssignments, Error> {
        self.stock
            .contract_assignments_for(contract_id, outpoints)
            .map_err(Error::from)
    }

    #[cfg(feature = "_online")]
    pub(crate) fn contract_schema(&self, contract_id: ContractId) -> Result<Schema, Error> {
        self.stock
            .as_store()
            .contract_schema(contract_id)?
            .ok_or_else(|| Error::Internal {
                details: format!("schema for contract {contract_id} not found"),
            })
    }

    pub(crate) fn schemata(&self) -> Result<Vec<SchemaInfo>, Error> {
        self.stock
            .schemata()
            .map(|r| r.map_err(Error::from))
            .collect()
    }

    pub(crate) fn seal_of_secret(
        &mut self,
        secret: SecretSeal,
    ) -> Result<Option<GraphSeal>, Error> {
        self.stock.as_store().seal_of_secret(secret)
    }

    pub(crate) fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<(), Error> {
        self.stock.store_secret_seal(seal).map_err(Error::from)
    }

    pub(crate) fn store_spv_proofs(&mut self, proofs: RetrievedSpvProofs) -> Result<(), Error> {
        if !proofs.is_empty() {
            self.stock.store_spv_proofs(proofs)?;
        }
        Ok(())
    }

    pub(crate) fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        witness_id: Option<RgbTxid>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(RgbTransfer, RetrievedSpvProofs), Error> {
        self.stock
            .transfer(
                contract_id,
                outputs,
                secret_seals,
                [],
                witness_id,
                spv_resolver,
            )
            .map_err(Error::from)
    }

    pub(crate) fn transfer_from_fascia(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(RgbTransfer, RetrievedSpvProofs), Error> {
        self.stock
            .transfer_from_fascia(
                contract_id,
                outputs,
                secret_seals,
                opids,
                fascia,
                spv_resolver,
            )
            .map_err(Error::from)
    }

    #[cfg(feature = "_online")]
    pub(crate) fn transfer_from_fascia_with_dag(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
    ) -> Result<(RgbTransfer, OpsDag, RetrievedSpvProofs), Error> {
        self.stock
            .transfer_from_fascia_with_dag(contract_id, outputs, secret_seals, opids, fascia, None)
            .map_err(Error::from)
    }

    pub(crate) fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, Error> {
        self.stock
            .transition_builder(contract_id, transition_name)
            .map_err(Error::from)
    }

    #[cfg(feature = "_online")]
    pub(crate) fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, Error> {
        self.stock
            .transition_builder_raw(contract_id, transition_type)
            .map_err(Error::from)
    }

    #[cfg(feature = "_online")]
    pub(crate) fn update_witnesses<R: ResolveWitness>(
        &mut self,
        resolver: &R,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        self.stock
            .update_witnesses(resolver, after_height, force_witnesses)
            .map_err(Error::from)
    }

    pub(crate) fn upsert_witness(
        &mut self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        self.stock.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    #[cfg(all(test, feature = "electrum"))]
    pub(crate) fn witness_spv_proof(&self, witness_id: RgbTxid) -> Result<Option<SpvProof>, Error> {
        self.stock.as_store().witness_spv_proof(witness_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "_online")]
    #[test]
    fn reject_list_parse() {
        let opid = "a8a9fb2e43bd4d1d02c6c4c5e1a8dd4ce9a4f9ea1e04a4dd4a1d4bdd4b0c4c4d";
        let rejected = Opout::from_str(&format!("{opid}/4000/0")).unwrap();
        let allowed = Opout::from_str(&format!("{opid}/4000/1")).unwrap();
        let list = format!("\n  {rejected} \n\t!{allowed}\t\n\n# a comment\n{opid}\n");
        let (reject_list, invalid) = RejectList::parse(&list);
        assert!(reject_list.rejects(&rejected));
        assert!(!reject_list.allows(&rejected));
        assert!(reject_list.allows(&allowed));
        assert!(!reject_list.rejects(&allowed));
        assert_eq!(invalid, 2);
    }

    #[derive(Debug, Deserialize)]
    struct MandatoryField {
        #[serde(deserialize_with = "from_str_or_number_mandatory")]
        val: u64,
    }

    #[derive(Debug, Deserialize)]
    struct OptionalField {
        #[serde(deserialize_with = "from_str_or_number_optional")]
        val: Option<u64>,
    }

    #[test]
    fn test_block_on_inside_tokio_runtime() {
        // calling block_on from within an active Tokio runtime takes the thread-spawn path
        // to avoid blocking the runtime thread
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { block_on(async { 42u32 }) });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_from_str_or_number_mandatory() {
        // integer value
        let result: MandatoryField = serde_json::from_str(r#"{"val": 42}"#).unwrap();
        assert_eq!(result.val, 42);

        // float value (visit_f64 path)
        let result: MandatoryField = serde_json::from_str(r#"{"val": 42.0}"#).unwrap();
        assert_eq!(result.val, 42);

        // string value
        let result: MandatoryField = serde_json::from_str(r#"{"val": "99"}"#).unwrap();
        assert_eq!(result.val, 99);

        // null -> error
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": null}"#).unwrap_err();
        assert!(
            err.to_string().contains("expected a number but got null"),
            "unexpected error message: {err}"
        );

        // invalid string -> parse error
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": "abc"}"#).unwrap_err();
        assert!(
            err.to_string().contains("invalid value"),
            "unexpected error message: {err}"
        );

        // unexpected type (bool) -> error names the expected types via `expecting`
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": true}"#).unwrap_err();
        assert!(
            err.to_string().contains("a string, a number, or null"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_from_str_or_number_optional() {
        // integer value
        let result: OptionalField = serde_json::from_str(r#"{"val": 42}"#).unwrap();
        assert_eq!(result.val, Some(42));

        // float value (visit_f64 path)
        let result: OptionalField = serde_json::from_str(r#"{"val": 42.0}"#).unwrap();
        assert_eq!(result.val, Some(42));

        // string value
        let result: OptionalField = serde_json::from_str(r#"{"val": "99"}"#).unwrap();
        assert_eq!(result.val, Some(99));

        // null -> None (visit_unit path)
        let result: OptionalField = serde_json::from_str(r#"{"val": null}"#).unwrap();
        assert_eq!(result.val, None);

        // invalid string -> parse error
        let err = serde_json::from_str::<OptionalField>(r#"{"val": "abc"}"#).unwrap_err();
        assert!(
            err.to_string().contains("invalid value"),
            "unexpected error message: {err}"
        );

        // visit_none path: triggered by deserializer formats that signal absence via visit_none
        // rather than visit_unit (serde_json uses visit_unit for null, but other formats differ)
        struct VisitNoneDeserializer;
        impl<'de> Deserializer<'de> for VisitNoneDeserializer {
            type Error = serde::de::value::Error;
            fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
                visitor.visit_none()
            }
            serde::forward_to_deserialize_any! {
                bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
                bytes byte_buf option unit unit_struct newtype_struct seq tuple
                tuple_struct map struct enum identifier ignored_any
            }
        }
        let result: Option<u64> = from_str_or_number_optional(VisitNoneDeserializer).unwrap();
        assert_eq!(result, None);
    }

    #[cfg(feature = "_online")]
    #[test]
    fn test_check_proxy_json_rpc_error() {
        // server returns HTTP 200 with result=null and a JSON-RPC error field
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":null,"result":null,"error":{"code":-32601,"message":"method not found"}}"#,
            )
            .create();
        let result = check_proxy(&server.url());
        assert_matches!(result, Err(Error::Proxy { details }) if details == "method not found");
        mock.assert();
    }

    #[cfg(feature = "_online")]
    #[test]
    fn test_check_proxy_invalid_body_error_details() {
        // server returns HTTP 200 with a body that is not a JSON-RPC response: the transport
        // error (body decoding) must be reported, not the generic connection message
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not json")
            .create();
        let result = check_proxy(&server.url());
        let expected = format!("error decoding response body for url ({}/)", server.url());
        assert_matches!(result, Err(Error::Proxy { details }) if details == expected);
        mock.assert();
    }

    #[cfg(feature = "_online")]
    #[test]
    fn test_check_proxy_connection_error_details() {
        // bind then drop a listener to get a port that refuses connections: the transport error
        // (connection refused) must be reported, not the generic connection message
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let result = check_proxy(&format!("http://127.0.0.1:{port}"));
        let expected = format!("error sending request for url (http://127.0.0.1:{port}/)");
        assert_matches!(result, Err(Error::Proxy { details }) if details == expected);
    }

    #[test]
    fn test_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        // parent dir does not exist yet: it must be created
        let path = dir.path().join("sub").join("f.bin");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        // overwrites cleanly
        atomic_write(&path, b"world!!").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"world!!");
        // no temp file is left behind
        let tmp = path.parent().unwrap().join(".f.bin.tmp");
        assert!(!tmp.exists());
        // a failing write leaves the previous file intact and no partial temp file behind
        let res = atomic_write_with(&path, |tmp| {
            fs::write(tmp, b"partial")?;
            Err(Error::Internal {
                details: s!("write failed"),
            })
        });
        assert!(matches!(res, Err(Error::Internal { .. })));
        assert_eq!(fs::read(&path).unwrap(), b"world!!");
        assert!(!tmp.exists());
    }

    // The None return from detect_indexer is only reachable when electrum is enabled but esplora
    // is not, and the URL is not a valid electrum server. With esplora enabled detection always
    // falls back to Some(IndexerConfig::Esplora) instead.
    #[cfg(all(feature = "electrum", not(feature = "esplora")))]
    #[test]
    fn test_detect_indexer_invalid_url_returns_none() {
        let result = detect_indexer("not_a_valid_url", None);
        assert!(result.is_none());
    }

    #[cfg(feature = "_online")]
    #[test]
    fn test_build_indexer_invalid_url() {
        let result = build_indexer(&IndexerConfig::Electrum {
            url: s!("not_a_valid_url"),
        });
        #[cfg(feature = "electrum")]
        let details = "not a valid electrum server";
        #[cfg(not(feature = "electrum"))]
        let details = "electrum support is not enabled (requires the `electrum` feature)";
        // Indexer is not Debug, so the Ok variant cannot be printed by assert_matches
        assert!(matches!(result, Err(Error::InvalidIndexer { details: m }) if m == details));
    }

    #[test]
    fn test_bitcoin_network_str_roundtrip() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // signet
        let network = BitcoinNetwork::Signet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // invalid network
        let network_str = "invalid";
        let result = BitcoinNetwork::from_str(network_str).unwrap_err();
        assert_matches!(result, Error::InvalidBitcoinNetwork { network } if network == "invalid");

        // signet- prefix with invalid hash
        let network_str = "signet-notahash";
        let result = BitcoinNetwork::from_str(network_str).unwrap_err();
        assert_matches!(result, Error::InvalidBitcoinNetwork { network } if network == "signet-notahash");
    }

    #[test]
    fn test_bitcoin_network_chain_net_roundtrip() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let chain_net = ChainNet::BitcoinMainnet;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let chain_net = ChainNet::BitcoinTestnet3;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let chain_net = ChainNet::BitcoinTestnet4;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // signet
        let network = BitcoinNetwork::Signet;
        let chain_net = ChainNet::BitcoinSignet;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let chain_net = ChainNet::BitcoinRegtest;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let chain_net = ChainNet::BitcoinSignetCustom;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // invalid chain net
        let chain_net = ChainNet::LiquidMainnet;
        let result = BitcoinNetwork::try_from(chain_net).unwrap_err();
        assert_matches!(result, Error::UnsupportedLayer1 { layer_1 } if layer_1 == "liquid");
    }

    #[test]
    fn test_bitcoin_network_try_from_rust_bitcoin_network() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Bitcoin);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Testnet);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Testnet4);

        // signet
        let network = BitcoinNetwork::Signet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Signet);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Regtest);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Signet);
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn get_indexer_and_resolver_resolver_connection_refused() {
        // the indexer connects, then the resolver connection is refused
        let url = start_single_connection_electrum_mock();
        let result =
            get_indexer_and_resolver(&IndexerConfig::Electrum { url }, BitcoinNetwork::Regtest);
        // Indexer is not Debug, so the Ok variant cannot be printed by assert_matches
        assert!(matches!(result, Err(Error::InvalidIndexer { .. })));
    }

    #[cfg(feature = "_online")]
    mod external_psbt {
        use super::*;
        use bdk_wallet::bitcoin::{
            Sequence, TxIn, Witness, absolute::LockTime, transaction::Version,
        };
        use serial_test::parallel;
        fn unsigned() -> Psbt {
            let script = ScriptBuf::from_bytes([vec![0x51, 0x20], vec![1; 32]].concat());
            let mut psbt = Psbt::from_unsigned_tx(BdkTransaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(Txid::from_str(&"01".repeat(32)).unwrap(), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: BdkAmount::from_sat(9000),
                    script_pubkey: script.clone(),
                }],
            })
            .unwrap();
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: BdkAmount::from_sat(10000),
                script_pubkey: script,
            });
            psbt
        }

        #[test]
        #[parallel]
        fn keeps_maps_and_never_mutates_on_error() {
            let mut psbt = unsigned();
            psbt.inputs[0].proprietary.insert(
                bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                    prefix: b"application".to_vec(),
                    subtype: 1,
                    key: vec![2],
                },
                vec![3],
            );
            psbt.outputs[0].proprietary.insert(
                bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                    prefix: b"application".to_vec(),
                    subtype: 4,
                    key: vec![5],
                },
                vec![6],
            );
            // sighash type ALL is accepted
            psbt.inputs[0].sighash_type =
                Some(bdk_wallet::bitcoin::psbt::PsbtSighashType::from_u32(0x01));
            let before = psbt.clone();
            let (prepared, shift) = prepare_external_psbt(&psbt).unwrap();
            assert!(shift);
            assert_eq!(psbt, before);
            assert_eq!(prepared.inputs, before.inputs);
            assert_eq!(prepared.outputs[1], before.outputs[0]);
            assert_eq!(prepared.proprietary, before.proprietary);
            assert!(prepared.unsigned_tx.output[0].script_pubkey.is_op_return());
        }

        #[test]
        #[parallel]
        fn shifts_taproot_outputs_after_existing_opreturn() {
            let mut psbt = unsigned();
            psbt.unsigned_tx.output.insert(
                0,
                TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return([]),
                },
            );
            psbt.outputs.insert(0, Default::default());
            let (prepared, shift) = prepare_external_psbt(&psbt).unwrap();
            assert!(shift);
            assert_eq!(prepared.unsigned_tx, psbt.unsigned_tx);
        }

        fn error(result: Result<(Psbt, bool), Error>) -> String {
            match result {
                Err(Error::InvalidColoringInfo { details }) => details,
                other => panic!("unexpected result: {other:?}"),
            }
        }

        #[test]
        #[parallel]
        fn checks_input_types_and_sighash() {
            let p2wpkh = ScriptBuf::from_bytes([vec![0x00, 0x14], vec![1; 20]].concat());
            let sighash = |value| Some(bdk_wallet::bitcoin::psbt::PsbtSighashType::from_u32(value));
            // a future witness version is not an input type that can be signed as expected
            let mut psbt = unsigned();
            psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
                ScriptBuf::from_bytes([vec![0x52, 0x20], vec![1; 32]].concat());
            assert_eq!(
                error(prepare_external_psbt(&psbt)),
                "PSBT inputs must be P2WPKH, P2WSH or P2TR"
            );
            // DEFAULT (0x00) only exists for Taproot inputs
            let mut psbt = unsigned();
            psbt.inputs[0].sighash_type = sighash(0);
            prepare_external_psbt(&psbt).unwrap();
            psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = p2wpkh.clone();
            assert_eq!(
                error(prepare_external_psbt(&psbt)),
                "PSBT inputs must be signed with sighash type ALL"
            );
            psbt.inputs[0].sighash_type = sighash(1);
            prepare_external_psbt(&psbt).unwrap();
        }

        #[test]
        #[parallel]
        fn checks_the_opreturn_host() {
            let with_host = |script: ScriptBuf, value| {
                let mut psbt = unsigned();
                psbt.unsigned_tx.output.insert(
                    0,
                    TxOut {
                        value: BdkAmount::from_sat(value),
                        script_pubkey: script,
                    },
                );
                psbt.outputs.insert(0, Default::default());
                psbt
            };
            // rgb-lib's placeholder, sized for the commitment, is a valid host
            let (prepared, _) =
                prepare_external_psbt(&with_host(ScriptBuf::new_op_return([0; 32]), 0)).unwrap();
            assert_eq!(prepared.unsigned_tx.output.len(), 2);
            // a host burning sats or carrying other data is not
            for psbt in [
                with_host(ScriptBuf::new_op_return([]), 1),
                with_host(ScriptBuf::new_op_return([1; 32]), 0),
            ] {
                assert_eq!(
                    error(prepare_external_psbt(&psbt)),
                    "PSBT OP_RETURN contains unrelated data"
                );
            }
        }

        #[test]
        #[parallel]
        fn counts_the_commitment_in_the_weight() {
            let max = u64::from(bdk_wallet::bitcoin::policy::MAX_STANDARD_TX_WEIGHT);
            let padded = |len: usize| {
                let mut psbt = unsigned();
                psbt.unsigned_tx.output.push(TxOut {
                    value: BdkAmount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51; len]),
                });
                psbt.outputs.push(Default::default());
                psbt
            };
            // the longest padding keeping the TX, with an empty host added, within the limit
            let weight = |len| {
                let mut tx = padded(len).unsigned_tx;
                tx.output.push(TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return([]),
                });
                tx.weight().to_wu()
            };
            let len = (90_000..100_000)
                .rev()
                .find(|len| weight(*len) <= max)
                .unwrap();
            // fits without the commitment, but not once the host holds it
            assert!(weight(len) + 33 * 4 > max);
            assert_eq!(
                error(prepare_external_psbt(&padded(len))),
                "PSBT TX is too heavy to be relayed"
            );
            // leaving room for the commitment is fine
            prepare_external_psbt(&padded(len - 33)).unwrap();
        }

        #[test]
        #[parallel]
        fn rejects_unsafe_psbts() {
            let base = unsigned();
            for case in 0..8 {
                let mut psbt = base.clone();
                match case {
                    0 => psbt.inputs[0].final_script_witness = Some(Witness::new()),
                    1 => psbt.inputs[0].redeem_script = Some(ScriptBuf::new()),
                    2 => psbt.inputs[0].witness_utxo = None,
                    3 => {
                        psbt.inputs.push(psbt.inputs[0].clone());
                        psbt.unsigned_tx
                            .input
                            .push(psbt.unsigned_tx.input[0].clone());
                    }
                    4 => {
                        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
                            ScriptBuf::new();
                    }
                    5 => {
                        psbt.inputs[0].proprietary.insert(
                            bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                                prefix: b"RGB".to_vec(),
                                subtype: 1,
                                key: vec![],
                            },
                            vec![1],
                        );
                    }
                    6 => {
                        psbt.inputs[0].sighash_type =
                            Some(bdk_wallet::bitcoin::psbt::PsbtSighashType::from_u32(0x02));
                    }
                    7 => {
                        psbt.unsigned_tx.output.push(TxOut {
                            value: BdkAmount::from_sat(1000),
                            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 100_000]),
                        });
                        psbt.outputs.push(Default::default());
                    }
                    _ => unreachable!(),
                }
                let before = psbt.clone();
                assert!(prepare_external_psbt(&psbt).is_err());
                assert_eq!(psbt, before);
            }
        }

        #[test]
        #[parallel]
        fn rejects_ambiguous_opreturn_hosts() {
            for case in 0..3 {
                let mut psbt = unsigned();
                let script = if case == 0 {
                    ScriptBuf::new_op_return([7])
                } else {
                    ScriptBuf::new_op_return([])
                };
                let host = TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: script,
                };
                if case < 2 {
                    psbt.unsigned_tx.output.push(host);
                    psbt.outputs.push(Default::default());
                } else {
                    psbt.unsigned_tx.output.insert(0, host.clone());
                    psbt.outputs.insert(0, Default::default());
                    psbt.unsigned_tx.output.push(host);
                    psbt.outputs.push(Default::default());
                }
                assert!(prepare_external_psbt(&psbt).is_err());
            }
        }
    }
}
