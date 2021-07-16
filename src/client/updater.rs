use std::*;
use std::collections::HashMap;

use collections::{defaultdict};
use factom_did::client::blockchain::{calculate_entry_size, record_entry};
use factom_did::client::constants::{ENTRY_SCHEMA_V100, ENTRY_SIZE_LIMIT};
use factom_did::client::did::{KeyType};
use factom_did::client::enums::{DIDKeyPurpose, EntryType};
use factom_did::client::keys::did::{DIDKey};
struct DIDUpdater {
did: ST0,
orig_management_keys: ST1,
orig_did_keys: ST2,
orig_services: ST3,
did_key_purposes_to_revoke: HashMap<_,_>,
}

impl DIDUpdater {
"
    Facilitates the creation of an update entry for an existing DID.

    Provides support for adding and revoking management keys, DID keys and services.

    Attributes
    ----------
    did: client.did.DID
        The DID object to update
    ";
fn init<T0>(&self, did: T0)  {
self.did = did;
self.orig_management_keys = set(self.did.management_keys.copy());
self.orig_did_keys = set(self.did.did_keys.copy());
self.orig_services = set(self.did.services.copy());
self.did_key_purposes_to_revoke = HashMap::new();
}
fn get_updated<RT>(&self) -> RT {
let mut new_did_keys = vec![];
for key in self.did.did_keys {
let mut revoked = false;
for (revoked_key_alias, revoked_purpose) in self.did_key_purposes_to_revoke.items() {
if key.alias == revoked_key_alias {
new_did_keys.push(DIDKey(key.alias, if key.purpose[0] == revoked_purpose { key.purpose[1] } else { key.purpose[0] }, key.key_type, key.controller, key.priority_requirement, key.public_key, key.private_key));
revoked = true;
break;
}
}
if !revoked {
new_did_keys.push(key);
}
}
self.did.did_keys = new_did_keys;
return self.did;
}
fn add_management_key<T0, T1, T2, T3, T4, RT>(&self, alias: T0, priority: T1, key_type: T2, controller: T3, priority_requirement: T4) -> RT {
"
        Adds a management key to the DID object.

        Parameters
        ----------
        alias: str
        priority: int
        key_type: KeyType, optional
        controller: str, optional
        priority_requirement: int, optional
        ";
self.did.management_key(alias, priority, key_type, controller, priority_requirement);
return self;
}
fn add_did_key<T0, T1, T2, T3, T4, RT>(&self, alias: T0, purpose: T1, key_type: T2, controller: T3, priority_requirement: T4) -> RT {
"
        Adds a DID key to the DID object.

        Parameters
        ----------
        alias: str
        purpose: did.enums.DIDKeyPurpose
        key_type: KeyType, optional
        controller: str, optional
        priority_requirement: int, optional
        ";
self.did.did_key(alias, purpose, key_type, controller, priority_requirement);
return self;
}
fn add_service<T0, T1, T2, T3, T4, RT>(&self, alias: T0, service_type: T1, endpoint: T2, priority_requirement: T3, custom_fields: T4) -> RT {
"
        Adds a service to the DID object.

        Parameters
        ----------
        alias: str
        service_type: str
        endpoint: str
        priority_requirement: int, optional
        custom_fields: dict, optional
        ";
self.did.service(alias, service_type, endpoint, priority_requirement, custom_fields);
return self;
}
fn revoke_management_key<T0, RT>(&self, alias: T0) -> RT {
"
        Revokes a management key from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the key to be revoked
        ";
self.did.management_keys = self._revoke(self.did.management_keys, |key| key.alias == alias);
return self;
}
fn revoke_did_key<T0, RT>(&self, alias: T0) -> RT {
"
        Revokes a DID key from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the key to be revoked
        ";
self.did.did_keys = self._revoke(self.did.did_keys, |key| key.alias == alias);
return self;
}
fn revoke_did_key_purpose<T0, T1, RT>(&self, alias: T0, purpose: T1) -> RT {
"
        Revokes a single purpose of a DID key from DID object.

        Parameters
        ----------
        alias: str
            The alias of the DID key
        purpose: DIDKeyPurpose
            The purpose to revoke
        ";
if [DIDKeyPurpose::AuthenticationKey, DIDKeyPurpose::PublicKey].iter().cloned().collect::<HashSet<_>>().iter().all(|&x| x != purpose) {
return self;
}
let matching_did_keys = self.did.did_keys.into_iter().filter(|k| k.alias == alias).collect::<Vec<_>>();
if !matching_did_keys {
return self;
}
assert!(matching_did_keys.len() == 1);
let key = matching_did_keys[0];
if key.purpose.iter().all(|&x| x != purpose) {
return self;
} else {
if key.purpose.len() == 1 {
return self.revoke_did_key(alias);
} else {
self.did_key_purposes_to_revoke[alias] = purpose;
return self;
}
}
}
fn revoke_service<T0, RT>(&self, alias: T0) -> RT {
"
        Revokes a service from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the service to be revoked
        ";
self.did.services = self._revoke(self.did.services, |service| service.alias == alias);
return self;
}
fn rotate_management_key<T0, RT>(&self, alias: T0) -> RT {
"
        Rotates a management key.

        Parameters
        ----------
        alias: str
            The alias of the management key to be rotated
        ";
for mgt_key in self.did.management_keys {
if mgt_key.alias == alias {
mgt_key.rotate();
return self;
}
}
return self;
}
fn rotate_did_key<T0, RT>(&self, alias: T0) -> RT {
"
        Rotates a DID key.

        Parameters
        ----------
        alias: str
            The alias of the DID key to be rotated
        ";
for did_key in self.did.did_keys {
if did_key.alias == alias {
did_key.rotate();
return self;
}
}
return self;
}
fn export_entry_data<RT>(&self) -> RT {
"
        Constructs a signed DIDUpdate entry ready for recording on-chain.

        Returns
        -------
        dict
            A dictionary with ExtIDs and content for the entry

        Raises
        ------
        RuntimeError
            If a management key of sufficient priority is not available to sign the update.
        ";
let (revoked_management_keys, revoked_did_keys, revoked_services) = self._get_revoked();
let (new_management_keys, new_did_keys, new_services) = self._get_new();
if !self.exists_management_key_with_priority_zero(self.orig_management_keys, new_management_keys, revoked_management_keys) {
raise!(ValueError("DIDUpdate entry would leave no management keys of priority zero")); //unsupported
}
let revoke_dict = defaultdict(list);
let mut update_key_required_priority = math.inf;
for key in revoked_management_keys {
revoke_dict["managementKey"].append([("id", key.alias)].iter().cloned().collect::<HashMap<_,_>>());
update_key_required_priority = self._get_required_key_priority_for_update(key, update_key_required_priority, |k| k.priority_requirement);
if key.priority_requirement == None {
update_key_required_priority = self._get_required_key_priority_for_update(key, update_key_required_priority, |k| k.priority);
}
}
for key in revoked_did_keys {
revoke_dict["didKey"].append([("id", key.alias)].iter().cloned().collect::<HashMap<_,_>>());
update_key_required_priority = self._get_required_key_priority_for_update(key, update_key_required_priority, |k| k.priority_requirement);
}
for (alias, purpose) in self.did_key_purposes_to_revoke.items() {
revoke_dict["didKey"].append([("id", alias), ("purpose", vec![purpose.value])].iter().cloned().collect::<HashMap<_,_>>());
}
for service in revoked_services {
revoke_dict["service"].append([("id", service.alias)].iter().cloned().collect::<HashMap<_,_>>());
update_key_required_priority = self._get_required_key_priority_for_update(service, update_key_required_priority, |s| s.priority_requirement);
}
let add_dict = defaultdict(list);
for key in new_management_keys {
add_dict["managementKey"].append(key.to_entry_dict(self.did.id));
update_key_required_priority = self._get_required_key_priority_for_update(key, update_key_required_priority, |k| k.priority);
}
for key in new_did_keys {
add_dict["didKey"].append(key.to_entry_dict(self.did.id));
}
for service in new_services {
add_dict["service"].append(service.to_entry_dict(self.did.id));
}
if !revoke_dict&&!add_dict {
return None;
}
let signing_key = sorted(self.orig_management_keys, op.attrgetter("priority"))[0];
if signing_key.priority > update_key_required_priority {
raise!(RuntimeError("The update requires a key with priority <= {}, but the highest priority key available is with priority {}".format(update_key_required_priority, signing_key.priority))); //unsupported
}
let entry_content_dict = HashMap::new();
if revoke_dict {
entry_content_dict["revoke"] = revoke_dict;
}
if add_dict {
entry_content_dict["add"] = add_dict;
}
let entry_content = json.dumps(entry_content_dict, (",", ":"));
let data_to_sign = "".join(vec![EntryType::Update.value, ENTRY_SCHEMA_V100, signing_key.full_id(self.did.id), entry_content]);
let signature = signing_key.sign(hashlib.sha256(data_to_sign.encode("utf-8")).digest());
let ext_ids = vec![EntryType::Update.value.encode("utf-8"), ENTRY_SCHEMA_V100::encode("utf-8"), signing_key.full_id(self.did.id).encode("utf-8"), signature];
let entry_size = calculate_entry_size(ext_ids, entry_content.encode("utf-8"));
if entry_size > ENTRY_SIZE_LIMIT {
raise!(RuntimeError("You have exceeded the entry size limit! Please remove some of your keys or services.")); //unsupported
}
return [("ext_ids", ext_ids), ("content", entry_content.encode("utf-8"))].iter().cloned().collect::<HashMap<_,_>>();
}
fn record_on_chain<T0, T1, T2, T3>(&self, factomd: T0, walletd: T1, ec_address: T2, verbose: T3)  {
"
        Attempts to record the DIDUpdate entry on-chain.

        Parameters
        ----------
        factomd: obj
            Factomd instance, instantiated from the Python factom-api package.
        walletd: obj
            Factom walletd instance, instantiated from the Python factom-api package.
        ec_address: str
            EC address used to pay for the chain & entry creation.
        verbose: bool, optional
            If true, display the contents of the entry that will be recorded
            on-chain.

        Raises
        ------
        RuntimeError
            If the entry cannot be recorded
        ";
record_entry(self.did.get_chain(), self.export_entry_data(), factomd, walletd, ec_address, verbose);
}
fn exists_management_key_with_priority_zero<T0, T1, T2, RT>(active_management_keys: T0, new_management_keys: T1, management_keys_to_revoke: T2) -> RT {
"
        Checks if a management key of priority zero would be present if the management keys will be updated according
        to the given parameters.

        Parameters
        ----------
        active_management_keys: set
            The currently active management keys
        new_management_keys: set
            The management keys to be added
        management_keys_to_revoke: set
            The management keys to be revoked

        Returns
        -------
        bool
        ";
active_management_keys = active_management_keys.copy();
active_management_keys.update(new_management_keys);
let remaining_keys = active_management_keys.difference(management_keys_to_revoke);
return remaining_keys.iter().map(|key| key.priority).iter().min().unwrap() == 0;
}
fn _get_revoked<RT>(&self) -> RT {
let revoked_management_keys = self.orig_management_keys.difference(set(self.did.management_keys));
let revoked_did_keys = self.orig_did_keys.difference(set(self.did.did_keys));
let revoked_services = self.orig_services.difference(set(self.did.services));
return (revoked_management_keys, revoked_did_keys, revoked_services);
}
fn _get_new<RT>(&self) -> RT {
let new_management_keys = set(self.did.management_keys).difference(self.orig_management_keys);
let new_did_keys = set(self.did.did_keys).difference(self.orig_did_keys);
let new_services = set(self.did.services).difference(self.orig_services);
return (new_management_keys, new_did_keys, new_services);
}
fn _get_required_key_priority_for_update<T0, T1, T2, RT>(key_or_service: T0, current_required_priority: T1, priority_f: T2) -> RT {
let required_priority = priority_f(key_or_service);
if required_priority != None&&required_priority < current_required_priority {
return required_priority;
} else {
return current_required_priority;
}
}
fn _revoke<T0, T1, RT>(l: T0, criteria: T1) -> RT {
return l.into_iter().filter(|x| !criteria(x)).collect::<Vec<_>>();
} 
}