use std::*;
use std::collections::HashMap;

"Helper functions for parser.py which are used to update the currently active management and DID keys,
and services.";
use packaging::{version};
use factom_did::client::constants::{DID_METHOD_SPEC_V020};
use factom_did::client::enums::{DIDKeyPurpose, Network};
use factom_did::client::keys::did::{DIDKey};
use factom_did::client::keys::management::{ManagementKey};
use factom_did::client::service::{Service};
use factom_did::resolver::exceptions::{MalformedDIDManagementEntry};
use factom_did::resolver::validators::{validate_management_key_id_against_chain_id, validate_id_against_network, validate_signature};
fn _is_method_version_upgrade<T0, T1, RT>(current_version: T0, new_version: T1) -> RT {
"
    Checks if the new version is an upgrade over the current version

    Parameters
    ----------
    current_version: str
    new_version: str

    Returns
    -------
    bool
    ";
return version::parse(current_version) < version::parse(new_version);
}
fn _get_alias<T0, RT>(full_or_partial_id: T0) -> RT {
"
    Returns the alias from a full or partial id

    Parameters
    ----------
    full_or_partial_id: str

    Returns
    -------
    str
    ";
return full_or_partial_id.split("#")[-1];
}
fn exists_management_key_with_priority_zero<T0, T1, T2, RT>(active_management_keys: T0, new_management_keys: T1, management_keys_to_revoke: T2) -> RT {
"
    Checks if a management key of priority zero would be present if the management keys will be updated according
    to the given parameters.

    Parameters
    ----------
    active_management_keys: dict
        The currently active management keys
    new_management_keys: dict
        The management keys to be added
    management_keys_to_revoke: set
        The management keys to be revoked

    Returns
    -------
    bool
    ";
let orig_management_keys = active_management_keys.copy();
for alias in management_keys_to_revoke {
orig_management_keys[alias].drop();
}
orig_management_keys.update(new_management_keys);
return orig_management_keys.values().iter().map(|key| key.priority).iter().min().unwrap() == 0;
}
fn process_did_management_entry_v100<T0, T1, T2, T3, T4, T5, T6, RT>(chain_id: T0, parsed_content: T1, management_keys: T2, did_keys: T3, services: T4, skipped_entries: T5, network: T6) -> RT {
"
    Extracts the management keys, DID keys and services from a DIDManagement entry.

    This method only does validation of the logic rules for a DIDManagement entry (e.g. that at least one management
    key with priority 0 is present). Thus, it must be called only with a parsed entry, which has already undergone
    validation checks for proper formatting of its ExtIDs and content.

    Parameters
    ----------
    chain_id: str
        The DIDManagement chain ID.
    parsed_content: dict
        The parsed DIDManagement entry.
    management_keys: dict
        Will be updated to contain the management keys found in the entry.
    did_keys: dict
        Will be updated to contain the DID keys found in the entry.
    services: dict
        Will be updated to contain the services found in the entry.
    skipped_entries: int
        Will be incremented by one in case the DIDManagement entry is not valid.
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.

    Raises
    ------
    MalformedDIDManagementEntry
        If the DIDManagement entry does not conform to the DID specification
    ";
let new_management_keys = HashMap::new();
let new_did_keys = HashMap::new();
let new_services = HashMap::new();
let method_version = parsed_content["didMethodVersion"];
let mut found_key_with_priority_zero = false;
for key_data in parsed_content["managementKey"] {
if !validate_management_key_id_against_chain_id(key_data["id"], chain_id) {
raise!(MalformedDIDManagementEntry("Invalid key identifier '{}' for chain ID '{}'".format(key_data["id"], chain_id))); //unsupported
}
if !validate_id_against_network(key_data["id"], network) {
raise!(MalformedDIDManagementEntry("Invalid key identifier '{}' for network ID '{}'".format(key_data["id"], network.value))); //unsupported
}
let mut alias = _get_alias(key_data["id"]);
if new_management_keys.iter().any(|&x| x == alias) {
raise!(MalformedDIDManagementEntry("Duplicate management key found")); //unsupported
}
new_management_keys[alias] = ManagementKey::from_entry_dict(key_data);
if key_data["priority"] == 0 {
found_key_with_priority_zero = true;
}
}
if !found_key_with_priority_zero {
raise!(MalformedDIDManagementEntry("Entry must contain at least one management key with priority 0")); //unsupported
}
for key_data in parsed_content.get("didKey", vec![]) {
if !validate_id_against_network(key_data["id"], network) {
raise!(MalformedDIDManagementEntry("Invalid key identifier '{}' for network ID '{}'".format(key_data["id"], network.value))); //unsupported
}
let mut alias = _get_alias(key_data["id"]);
if new_did_keys.iter().any(|&x| x == alias) {
raise!(MalformedDIDManagementEntry("Duplicate DID key found")); //unsupported
}
new_did_keys[alias] = DIDKey::from_entry_dict(key_data);
}
for service_data in parsed_content.get("service", vec![]) {
if !validate_id_against_network(service_data["id"], network) {
raise!(MalformedDIDManagementEntry("Invalid service identifier '{}' for network ID '{}'".format(service_data["id"], network.value))); //unsupported
}
let mut alias = _get_alias(service_data["id"]);
if new_services.iter().any(|&x| x == alias) {
raise!(MalformedDIDManagementEntry("Duplicate service found")); //unsupported
}
new_services[alias] = Service::from_entry_dict(service_data);
}
management_keys.update(new_management_keys);
did_keys.update(new_did_keys);
services.update(new_services);
return (true, method_version, skipped_entries);
}
fn process_did_update_entry_v100<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, RT>(chain_id: T0, ext_ids: T1, binary_content: T2, parsed_content: T3, method_version: T4, active_management_keys: T5, active_did_keys: T6, active_services: T7, skipped_entries: T8, all_keys: T9, network: T10) -> RT {
"
    Updates the management keys, DID keys and services based on the contents of the entry.

    This method only does validation of the logic rules for a DIDUpdate entry (e.g. that the signature is valid).
    Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    chain_id: str
        The DIDManagement chain ID.
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    parsed_content: dict
        The parsed DIDUpdate entry.
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active management keys. Will be updated to contain the management keys found in the entry.
    active_did_keys: dict
        The currently active DID keys. Will be updated to contain the DID keys found in the entry.
    active_services: dict
        The currently active services. Will be updated to contain the services found in the entry.
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    all_keys: set
        The set of all management and DID keys that have been active at some point for the current DIDManagement chain.
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    ";
let management_keys_to_revoke = set();
let did_keys_to_revoke = set();
let did_key_purposes_to_revoke = dict();
let services_to_revoke = set();
let new_management_keys = HashMap::new();
let new_did_keys = HashMap::new();
let new_services = HashMap::new();
if method_version == DID_METHOD_SPEC_V020 {
let key_id = ext_ids[2].decode();
let signing_key = active_management_keys.get(_get_alias(key_id));
if !signing_key||!validate_signature(ext_ids, binary_content, signing_key) {
return (true, method_version, (skipped_entries + 1));
}
let signing_key_required_priority = math.inf;
if parsed_content.iter().any(|&x| x == "revoke") {
let (skip_entry, signing_key_required_priority) = _process_management_key_revocations(parsed_content, signing_key_required_priority, management_keys_to_revoke, active_management_keys, chain_id, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
let (skip_entry, signing_key_required_priority) = _process_did_key_revocations(parsed_content, signing_key_required_priority, did_keys_to_revoke, did_key_purposes_to_revoke, active_did_keys, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
let (skip_entry, signing_key_required_priority) = _process_service_revocations(parsed_content, signing_key_required_priority, services_to_revoke, active_services, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
}
if parsed_content.iter().any(|&x| x == "add") {
let (skip_entry, signing_key_required_priority) = _process_management_key_additions(parsed_content, signing_key_required_priority, new_management_keys, active_management_keys, all_keys, chain_id, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
let (skip_entry, signing_key_required_priority) = _process_did_key_additions(parsed_content, signing_key_required_priority, new_did_keys, active_did_keys, all_keys, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
let mut skip_entry = _process_service_additions(parsed_content, new_services, active_services, network);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
}
if signing_key.priority > signing_key_required_priority {
return (true, method_version, (skipped_entries + 1));
}
if !exists_management_key_with_priority_zero(active_management_keys, new_management_keys, management_keys_to_revoke) {
return (true, method_version, (skipped_entries + 1));
}
let mut skip_entry = _apply_self_revocation_rules(signing_key, new_management_keys, management_keys_to_revoke);
if skip_entry {
return (true, method_version, (skipped_entries + 1));
}
for alias in management_keys_to_revoke {
active_management_keys[alias].drop();
}
active_management_keys.update(new_management_keys);
for alias in did_keys_to_revoke {
active_did_keys[alias].drop();
}
active_did_keys.update(new_did_keys);
for (alias, revoked_purpose) in did_key_purposes_to_revoke.items() {
let key = active_did_keys[alias];
let new_purpose = if key.purpose[0] == revoked_purpose { key.purpose[1] } else { key.purpose[0] };
key.purpose = vec![new_purpose];
}
for alias in services_to_revoke {
active_services[alias].drop();
}
active_services.update(new_services);
} else {
skipped_entries += 1;
}
return (true, method_version, skipped_entries);
}
fn process_did_deactivation_entry_v100<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, RT>(_chain_id: T0, ext_ids: T1, binary_content: T2, _parsed_content: T3, method_version: T4, active_management_keys: T5, active_did_keys: T6, active_services: T7, skipped_entries: T8, _all_keys: T9, _network: T10) -> RT {
"
    Deactivates the DID by resetting the currently active management and DID keys, and services.

    This method only does validation of the logic rules for a DIDDeactivation entry (e.g. that the signature is valid).
    Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    _chain_id: str
        Unused
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    _parsed_content: dict
        Unused
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active management keys. Will be reset.
    active_did_keys: dict
        The currently active DID keys. Will be reset.
    active_services: dict
        The currently active services. Will be reset.
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    _all_keys: set
        Unused
    _network: Network
        Unused

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    ";
if method_version == DID_METHOD_SPEC_V020 {
let key_id = ext_ids[2].decode();
let signing_key = active_management_keys.get(_get_alias(key_id));
if !signing_key||signing_key.priority != 0||!validate_signature(ext_ids, binary_content, signing_key) {
return (true, method_version, (skipped_entries + 1));
}
active_management_keys.clear();
active_did_keys.clear();
active_services.clear();
} else {
skipped_entries += 1;
}
return (false, method_version, skipped_entries);
}
fn process_did_method_version_upgrade_entry_v100<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, RT>(_chain_id: T0, ext_ids: T1, binary_content: T2, parsed_content: T3, method_version: T4, active_management_keys: T5, _active_did_keys: T6, _active_services: T7, skipped_entries: T8, _all_keys: T9, _network: T10) -> RT {
"
    Upgrades the DID method version.

    This method only does validation of the logic rules for a DIDMethodVersionUpgrade entry (e.g. that the signature is
    valid). Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    _chain_id: str
        Unused
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    parsed_content: dict
        Unused
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active DID management keys.
    _active_did_keys: dict
        Unused
    _active_services: dict
        Unused
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    _all_keys: set
        Unused
    _network: Network
        Unused

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    ";
let mut new_method_version = method_version;
if method_version == DID_METHOD_SPEC_V020 {
let key_id = ext_ids[2].decode();
let signing_key = active_management_keys.get(_get_alias(key_id));
if signing_key&&_is_method_version_upgrade(method_version, parsed_content["didMethodVersion"])&&validate_signature(ext_ids, binary_content, signing_key) {
new_method_version = parsed_content["didMethodVersion"];
} else {
skipped_entries += 1;
}
} else {
skipped_entries += 1;
}
return (true, new_method_version, skipped_entries);
}
fn _process_management_key_revocations<T0, T1, T2, T3, T4, T5, RT>(entry_content: T0, signing_key_required_priority: T1, keys_to_revoke: T2, active_keys: T3, chain_id: T4, network: T5) -> RT {
for key in entry_content["revoke"].get("managementKey", vec![]) {
let alias = _get_alias(key["id"]);
if !validate_management_key_id_against_chain_id(key["id"], chain_id)||!validate_id_against_network(key["id"], network)||active_keys.iter().all(|&x| x != alias)||keys_to_revoke.iter().any(|&x| x == alias) {
return (true, signing_key_required_priority);
}
keys_to_revoke.add(alias);
if active_keys[alias].priority_requirement != None {
signing_key_required_priority = signing_key_required_priority.iter().min().unwrap();
} else {
signing_key_required_priority = signing_key_required_priority.iter().min().unwrap();
}
}
return (false, signing_key_required_priority);
}
fn _process_did_key_revocations<T0, T1, T2, T3, T4, T5, RT>(entry_content: T0, signing_key_required_priority: T1, keys_to_revoke: T2, key_purposes_to_revoke: T3, active_keys: T4, network: T5) -> RT {
for key_data in entry_content["revoke"].get("didKey", vec![]) {
let alias = _get_alias(key_data["id"]);
if active_keys.iter().all(|&x| x != alias)||keys_to_revoke.iter().any(|&x| x == alias)||!validate_id_against_network(key_data["id"], network) {
return (true, signing_key_required_priority);
}
if key_data.iter().any(|&x| x == "purpose") {
let purposes = key_data["purpose"];
if purposes.len() != set(purposes).len() {
return (true, signing_key_required_priority);
}
let active_purposes = set(active_keys[alias].purpose.iter().map(|p| p.value));
let valid_purposes = [DIDKeyPurpose::AuthenticationKey.value, DIDKeyPurpose::PublicKey.value].iter().cloned().collect::<HashSet<_>>();
for purpose in purposes {
if valid_purposes.iter().all(|&x| x != purpose)||active_purposes.iter().all(|&x| x != purpose) {
return (true, signing_key_required_priority);
}
}
if set(purposes) == active_purposes {
keys_to_revoke.add(alias);
} else {
assert!(purposes.len() == 1);
key_purposes_to_revoke[alias] = DIDKeyPurpose::from_str(purposes[0]);
}
} else {
if key_purposes_to_revoke.iter().any(|&x| x == alias) {
key_purposes_to_revoke[alias].drop();
}
keys_to_revoke.add(alias);
}
if active_keys[alias].priority_requirement != None {
signing_key_required_priority = signing_key_required_priority.iter().min().unwrap();
}
}
return (false, signing_key_required_priority);
}
fn _process_service_revocations<T0, T1, T2, T3, T4, RT>(entry_content: T0, signing_key_required_priority: T1, services_to_revoke: T2, active_services: T3, network: T4) -> RT {
for service in entry_content["revoke"].get("service", vec![]) {
let alias = _get_alias(service["id"]);
if active_services.iter().all(|&x| x != alias)||services_to_revoke.iter().any(|&x| x == alias)||!validate_id_against_network(service["id"], network) {
return (true, signing_key_required_priority);
}
services_to_revoke.add(alias);
if active_services[alias].priority_requirement != None {
signing_key_required_priority = signing_key_required_priority.iter().min().unwrap();
}
}
return (false, signing_key_required_priority);
}
fn _process_management_key_additions<T0, T1, T2, T3, T4, T5, T6, RT>(entry_content: T0, signing_key_required_priority: T1, new_keys: T2, active_keys: T3, all_keys: T4, chain_id: T5, network: T6) -> RT {
for key_data in entry_content["add"].get("managementKey", vec![]) {
let alias = _get_alias(key_data["id"]);
if !validate_management_key_id_against_chain_id(key_data["id"], chain_id)||!validate_id_against_network(key_data["id"], network)||new_keys.iter().any(|&x| x == alias)||active_keys.iter().any(|&x| x == alias) {
return (true, signing_key_required_priority);
}
let new_management_key = ManagementKey::from_entry_dict(key_data);
if all_keys.iter().any(|&x| x == new_management_key) {
return (true, signing_key_required_priority);
}
new_keys[alias] = new_management_key;
signing_key_required_priority = signing_key_required_priority.iter().min().unwrap();
}
return (false, signing_key_required_priority);
}
fn _process_did_key_additions<T0, T1, T2, T3, T4, T5, RT>(entry_content: T0, signing_key_required_priority: T1, new_keys: T2, active_keys: T3, all_keys: T4, network: T5) -> RT {
for key_data in entry_content["add"].get("didKey", vec![]) {
let alias = _get_alias(key_data["id"]);
if new_keys.iter().any(|&x| x == alias)||active_keys.iter().any(|&x| x == alias)||!validate_id_against_network(key_data["id"], network) {
return (true, signing_key_required_priority);
}
let new_did_key = DIDKey::from_entry_dict(key_data);
if all_keys.iter().any(|&x| x == new_did_key) {
return (true, signing_key_required_priority);
}
new_keys[alias] = new_did_key;
}
return (false, signing_key_required_priority);
}
fn _process_service_additions<T0, T1, T2, T3, RT>(entry_content: T0, new_services: T1, active_services: T2, network: T3) -> RT {
for service_data in entry_content["add"].get("service", vec![]) {
let alias = _get_alias(service_data["id"]);
if new_services.iter().any(|&x| x == alias)||active_services.iter().any(|&x| x == alias)||!validate_id_against_network(service_data["id"], network) {
return true;
}
new_services[alias] = Service::from_entry_dict(service_data);
}
return false;
}
fn _apply_self_revocation_rules<T0, T1, T2, RT>(signing_key: T0, new_management_keys: T1, management_keys_to_revoke: T2) -> RT {
if signing_key.priority == 0 {
return false;
}
let num_same_priority_keys = new_management_keys.values().into_iter().filter(|k| k.priority == signing_key.priority).collect::<Vec<_>>().len();
if num_same_priority_keys == 0 {
return false;
}
if num_same_priority_keys > 1 {
return true;
}
if management_keys_to_revoke.iter().all(|&x| x != signing_key.alias) {
management_keys_to_revoke.add(signing_key.alias);
return false;
}
}