use std::collections::HashMap;
use std::*;

use factom_did::client::constants::ENTRY_SCHEMA_V100;
use factom_did::client::enums::{EntryType, Network};
use factom_did::resolver::entry_processors::{
    process_did_deactivation_entry_v100, process_did_management_entry_v100,
    process_did_method_version_upgrade_entry_v100, process_did_update_entry_v100,
};
use factom_did::resolver::exceptions::{InvalidDIDChain, MalformedDIDManagementEntry};
use factom_did::resolver::schema::get_schema_validator;
use factom_did::resolver::validators::{
    validate_did_deactivation_ext_ids_v100, validate_did_management_ext_ids_v100,
    validate_did_method_version_upgrade_ext_ids_v100, validate_did_update_ext_ids_v100,
    EmptyEntryContentValidator,
};
use json::JSONDecodeError;
use jsonschema::exceptions::ValidationError;
const DID_MANAGEMENT_SCHEMA: _ = "did_management_entry.json";
const DID_UPDATE_SCHEMA: _ = "did_update_entry.json";
const DID_METHOD_VERSION_UPGRADE_SCHEMA: _ = "did_method_version_upgrade_entry.json";
const ENTRY_SCHEMA_VALIDATORS: _ = [(
    ENTRY_SCHEMA_V100,
    [
        (
            EntryType::Create.value,
            get_schema_validator(DID_MANAGEMENT_SCHEMA),
        ),
        (
            EntryType::Update.value,
            get_schema_validator(DID_UPDATE_SCHEMA),
        ),
        (
            EntryType::VersionUpgrade.value,
            get_schema_validator(DID_METHOD_VERSION_UPGRADE_SCHEMA),
        ),
        (EntryType::Deactivation.value, EmptyEntryContentValidator),
    ]
    .iter()
    .cloned()
    .collect::<HashMap<_, _>>(),
)]
.iter()
.cloned()
.collect::<HashMap<_, _>>();
const ENTRY_EXT_ID_VALIDATORS: _ = [(
    ENTRY_SCHEMA_V100,
    [
        (
            EntryType::Create.value,
            validate_did_management_ext_ids_v100,
        ),
        (EntryType::Update.value, validate_did_update_ext_ids_v100),
        (
            EntryType::VersionUpgrade.value,
            validate_did_method_version_upgrade_ext_ids_v100,
        ),
        (
            EntryType::Deactivation.value,
            validate_did_deactivation_ext_ids_v100,
        ),
    ]
    .iter()
    .cloned()
    .collect::<HashMap<_, _>>(),
)]
.iter()
.cloned()
.collect::<HashMap<_, _>>();
const ENTRY_PROCESSORS: _ = [(
    ENTRY_SCHEMA_V100,
    [
        (EntryType::Create.value, process_did_management_entry_v100),
        (EntryType::Update.value, process_did_update_entry_v100),
        (
            EntryType::VersionUpgrade.value,
            process_did_method_version_upgrade_entry_v100,
        ),
        (
            EntryType::Deactivation.value,
            process_did_deactivation_entry_v100,
        ),
    ]
    .iter()
    .cloned()
    .collect::<HashMap<_, _>>(),
)]
.iter()
.cloned()
.collect::<HashMap<_, _>>();
fn parse_did_chain_entries<T0, T1, T2, RT>(entries: T0, chain_id: T1, network: T2) -> RT {
    "
    Attempts to parse the entries in a DIDManagement chain.

    Parameters
    ----------
    entries: list of dict
        A list of entries in the DIDManagement chain as returned by the Python factom-api library, or an equivalent
        API/library. Each element of the list is a dictionary, with keys 'content', 'extids' and 'entryhash' and the
        values are bytes
    chain_id: str
        The DIDManagement chain ID
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        A 4-tuple containing the active management keys, the active DID key, the active services and the number of
        entries skipped while parsing the chain.

    Raises
    ------
    InvalidDIDChain
       If the first entry in the chain is not a valid DIDManagement entry
    ";
    let active_management_keys = HashMap::new();
    let active_did_keys = HashMap::new();
    let active_services = HashMap::new();
    let all_keys = set();
    let processed_entry_hashes = set();
    let method_version = None;
    let mut skipped_entries = 0;
    let keep_parsing = true;
    for (i, entry) in entries.iter().enumerate() {
        if !keep_parsing {
            return (
                active_management_keys,
                active_did_keys,
                active_services,
                ((skipped_entries + entries.len()) - i),
            );
        }
        let ext_ids = entry["extids"];
        let binary_content = entry["content"];
        let entry_hash = entry["entryhash"];
        if processed_entry_hashes.iter().any(|&x| x == entry_hash) {
            skipped_entries += 1;
            continue;
        }
        processed_entry_hashes.add(entry_hash);
        if i == 0 {
            let try_dummy = {
                //unsupported
                let mut entry_type = ext_ids[0].decode();
                if entry_type != EntryType::Create.value {
                    raise!(InvalidDIDChain("First entry must be of type DIDManagement"));
                    //unsupported
                }
                let mut parsed_content = json.loads(binary_content.decode());
                let mut schema_version = ext_ids[1].decode();
                ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](ext_ids);
                ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(parsed_content);
                let (keep_parsing, method_version, skipped_entries) = ENTRY_PROCESSORS
                    [schema_version][entry_type](
                    chain_id,
                    parsed_content,
                    active_management_keys,
                    active_did_keys,
                    active_services,
                    skipped_entries,
                    network,
                );
                all_keys.update(active_management_keys.values(), active_did_keys.values());
            };
            let except!((UnicodeDecodeError, JSONDecodeError)) = {
                //unsupported
                raise!(InvalidDIDChain(
                    "DIDManagement entry content must be valid JSON"
                )); //unsupported
            };
            let except!(KeyError) = {
                //unsupported
                raise!(InvalidDIDChain("Unknown schema version or entry type"));
                //unsupported
            };
            let except!(IndexError) = {
                //unsupported
                raise!(InvalidDIDChain(
                    "DIDManagement entry has insufficient ExtIDs"
                )); //unsupported
            };
            let except!(ValidationError) = {
                //unsupported
                raise!(InvalidDIDChain("Invalid DIDManagement entry content")); //unsupported
            };
            let except!(MalformedDIDManagementEntry) = {
                //unsupported
                raise!(InvalidDIDChain(
                    "Malformed DIDManagement entry: {}".format(e.args[0])
                )); //unsupported
            };
        } else {
            if ext_ids.len() >= 4 {
                let try_dummy = {
                    //unsupported
                    entry_type = ext_ids[0].decode();
                    schema_version = ext_ids[1].decode();
                    if entry_type == EntryType::Create.value
                        || ENTRY_SCHEMA_VALIDATORS.iter().all(|&x| x != schema_version)
                        || ENTRY_SCHEMA_VALIDATORS[schema_version]
                            .iter()
                            .all(|&x| x != entry_type)
                        || !ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](
                            ext_ids, chain_id, network,
                        )
                    {
                        skipped_entries += 1;
                        continue;
                    }
                    let decoded_content = binary_content.decode();
                    parsed_content = decoded_content;
                    if entry_type != EntryType::Deactivation.value {
                        parsed_content = json.loads(decoded_content);
                    }
                    ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(parsed_content);
                    let (keep_parsing, method_version, skipped_entries) = ENTRY_PROCESSORS
                        [schema_version][entry_type](
                        chain_id,
                        ext_ids,
                        binary_content,
                        parsed_content,
                        method_version,
                        active_management_keys,
                        active_did_keys,
                        active_services,
                        skipped_entries,
                        all_keys,
                        network,
                    );
                    all_keys.update(active_management_keys.values(), active_did_keys.values());
                };
                let except!((UnicodeDecodeError, JSONDecodeError, ValidationError)) = {
                    //unsupported
                    skipped_entries += 1;
                    continue;
                };
            } else {
                skipped_entries += 1;
            }
        }
    }
    return (
        active_management_keys,
        active_did_keys,
        active_services,
        skipped_entries,
    );
}
