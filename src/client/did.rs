use std::*;
use std::collections::HashMap;

use base64::{urlsafe_b64encode};
use factom_did::client::blockchain::{calculate_chain_id, calculate_entry_size, create_chain};
use factom_did::client::constants::{*};
use factom_did::client::deactivator::{DIDDeactivator};
use factom_did::client::encryptor::{encrypt_keys};
use factom_did::client::enums::{DIDKeyPurpose, EntryType, KeyType, Network};
use factom_did::client::keys::did::{DIDKey};
use factom_did::client::keys::management::{ManagementKey};
use factom_did::client::service::{Service};
use factom_did::client::updater::{DIDUpdater};
use factom_did::client::validators::{validate_did};
use factom_did::client::version_upgrader::{DIDVersionUpgrader};
let __all__ = vec!["DID", "KeyType", "DIDKeyPurpose"];
struct DID {
_id: ST0,
management_keys: ST1,
did_keys: ST2,
services: ST3,
network: ST4,
spec_version: ST5,
used_key_aliases: ST6,
used_service_aliases: ST7,
nonce: ST8,
}

impl DID {
"
    Enables the construction of a DID document, by facilitating the construction of management keys and DID keys and the
    addition of services. Allows exporting of the resulting DID object into a format suitable for recording on the
    Factom blockchain.

    Provides encryption functionality of private keys for the DID and their export to a string or to a JSON file.

    Attributes
    ----------
    did: str, optional
        The decentralized identifier, a 32 byte hexadecimal string
    management_keys: ManagementKey[], optional
        A list of management keys
    did_keys: DIDKey[], optional
        A list of DID keys
    services: Service[], optional
        A list of services
    ";
fn __init__<T0, T1, T2, T3, T4>(&self, did: T0, management_keys: T1, did_keys: T2, services: T3, spec_version: T4)  {
self._id = if did == None||!self.is_valid_did(did) { self._generate_did() } else { did };
self.management_keys = if management_keys == None { vec![] } else { management_keys };
self.did_keys = if did_keys == None { vec![] } else { did_keys };
self.services = if services == None { vec![] } else { services };
self.network = DID::_get_network_from_id(self._id);
self.spec_version = spec_version;
self.used_key_aliases = set();
self.used_service_aliases = set();
for key in self.management_keys {
self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, key.alias);
}
for key in self.did_keys {
self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, key.alias);
}
for service in self.services {
self._check_alias_is_unique_and_add_to_used(self.used_service_aliases, service.alias);
}
}
fn __repr__<RT>(&self) -> RT {
return "<{}.{} (management_keys={}, did_keys={}, services={})>".format(self.__module__, type_(self).__name__, self.management_keys.len(), self.did_keys.len(), self.services.len());
}
fn id<RT>(&self) -> RT {
if self.network == Network::Unspecified {
return self._id;
} else {
return ":".join(vec![DID_METHOD_NAME, self.network.value, self.get_chain()]);
}
}
fn get_chain<RT>(&self) -> RT {
"
        Returns
        -------
        str
            The chain ID where this DID is (or will be) stored
        ";
return self._id.split(":")[-1];
}
fn update<RT>(&self) -> RT {
"
        Raises
        ------
        RuntimeError
            If no management keys are available for the DID

        Returns
        -------
        DIDUpdater
            An object allowing updates to the existing DID
        ";
if !self.management_keys {
raise!(RuntimeError("Cannot update DID without management keys.")); //unsupported
}
return DIDUpdater(self);
}
fn method_spec_version_upgrade<T0, RT>(&self, new_spec_version: T0) -> RT {
"
        Parameters
        ----------
        new_spec_version: str
            The new DID Method version

        Raises
        ------
        RuntimeError
            If no management keys are available for the DID
        ValueError
            If the new version is not an upgrade on the current version

        Returns
        -------
        DIDVersionUpgrader
        ";
if !self.management_keys {
raise!(RuntimeError("Cannot upgrade method spec version for DID without management keys.")); //unsupported
}
return DIDVersionUpgrader(self, new_spec_version);
}
fn deactivate<RT>(&self) -> RT {
"
        Raises
        ------
        RuntimeError
            If no management keys are available for the DID

        Returns
        -------
        DIDDeactivator
        ";
if !self.management_keys {
raise!(RuntimeError("Cannot deactivate DID without a management key of priority 0.")); //unsupported
}
return DIDDeactivator(self);
}
fn mainnet<RT>(&self) -> RT {
"
        Sets the DID network to mainnet.
        ";
self.network = Network::Mainnet;
return self;
}
fn testnet<RT>(&self) -> RT {
"
        Sets the DID network to testnet.
        ";
self.network = Network::Testnet;
return self;
}
fn management_key<T0, T1, T2, T3, T4, RT>(&self, alias: T0, priority: T1, key_type: T2, controller: T3, priority_requirement: T4) -> RT {
"
        Creates a new management key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        priority: int
            A non-negative integer showing the hierarchical level of the key. Keys with lower priority
            override keys with higher priority.
        key_type: KeyType, optional
            Identifies the type of signature that the key pair can be used to generate and verify.
        controller: str, optional
            An entity that controls the key. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        ";
if !controller {
controller = self.id;
}
let key = ManagementKey(alias, priority, key_type, controller, priority_requirement);
self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, alias);
self.management_keys.append(key);
return self;
}
fn did_key<T0, T1, T2, T3, T4, RT>(&self, alias: T0, purpose: T1, key_type: T2, controller: T3, priority_requirement: T4) -> RT {
"
        Creates a new DID key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        purpose: DIDKeyPurpose or DIDKeyPurpose[]
            Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
        key_type: KeyType, optional
            Identifies the type of signature that the key pair can be used to generate and verify.
        controller: str, optional
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        ";
if !controller {
controller = self.id;
}
let key = DIDKey(alias, purpose, key_type, controller, priority_requirement);
self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, alias);
self.did_keys.append(key);
return self;
}
fn service<T0, T1, T2, T3, T4, RT>(&self, alias: T0, service_type: T1, endpoint: T2, priority_requirement: T3, custom_fields: T4) -> RT {
"
        Adds a new service to the DID Document.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the service endpoint. It should be unique across the services defined in the
            DID document.
        service_type: str
            Type of the service endpoint.
        endpoint: str
            A service endpoint may represent any type of service the subject wishes to advertise, including
            decentralized identity management services for further discovery, authentication, authorization, or
            interaction.
            The service endpoint must be a valid URL.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this
            service.
        custom_fields: dict, optional
            A dictionary containing custom fields (e.g "description": "My public social inbox").
        ";
let service = Service(alias, service_type, endpoint, priority_requirement, custom_fields);
self._check_alias_is_unique_and_add_to_used(self.used_service_aliases, alias);
self.services.append(service);
return self;
}
fn export_entry_data<RT>(&self) -> RT {
"
        Exports content that can be recorded on-chain to create the DID.

        Returns
        -------
        dict
            A dictionary with the ExtIDs and entry content of strings used that are the header columns.

        Raises
        ------
        ValueError
            If there are no management keys.
            If there is no management key with priority 0.
            If the entry size exceeds the entry size limit.
        ";
let management_keys = self.management_keys.iter().map(|k| k.to_entry_dict(self.id)).collect::<Vec<_>>();
if management_keys.len() < 1 {
raise!(ValueError("The DID must have at least one management key.")); //unsupported
}
if !any(management_keys.iter().map(|key| key["priority"] == 0)) {
raise!(ValueError("At least one management key must have priority 0.")); //unsupported
}
let ext_ids = vec![EntryType::Create.value.encode("utf-8"), ENTRY_SCHEMA_V100.encode("utf-8"), self.nonce];
let entry_content = json.dumps(self._get_did_document(), (",", ":")).encode("utf-8");
let entry_size = calculate_entry_size(ext_ids, entry_content);
if entry_size > ENTRY_SIZE_LIMIT {
raise!(RuntimeError("You have exceeded the entry size limit! Please remove some of your keys or services.")); //unsupported
}
return [("ext_ids", ext_ids), ("content", entry_content)].iter().cloned().collect::<HashMap<_,_>>();
}
fn export_encrypted_keys_as_str<T0, RT>(&self, password: T0) -> RT {
"
        Exports encrypted keys cipher text.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys cipher text.
        ";
let encryption_result = encrypt_keys(self.management_keys, self.did_keys, password);
let cipher_text_b64 = urlsafe_b64encode(((encryption_result["salt"] + encryption_result["iv"]) + encryption_result["data"]));
return String::from(cipher_text_b64, "utf8");
}
fn export_encrypted_keys_as_json<T0, RT>(&self, password: T0) -> RT {
"
        Exports encrypted keys as JSON.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys JSON.
        ";
let encryption_result = encrypt_keys(self.management_keys, self.did_keys, password);
return json.dumps([("data", String::from(urlsafe_b64encode(encryption_result["data"]), "utf8")), ("encryptionAlgo", [("name", "AES-GCM"), ("iv", String::from(urlsafe_b64encode(encryption_result["iv"]), "utf8")), ("salt", String::from(urlsafe_b64encode(encryption_result["salt"]), "utf8")), ("tagLength", 128)].iter().cloned().collect::<HashMap<_,_>>()), ("did", self.id)].iter().cloned().collect::<HashMap<_,_>>());
}
fn record_on_chain<T0, T1, T2, T3>(&self, factomd: T0, walletd: T1, ec_address: T2, verbose: T3)  {
"
        Attempts to create the DIDManagement chain.

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
            If the chain cannot be created
        ";
create_chain(self.export_entry_data(), factomd, walletd, ec_address, verbose);
}
fn _get_did_document<RT>(&self) -> RT {
"
        Builds a DID Document.

        Returns
        -------
        dict
            A dictionary with the DID Document properties.
        ";
let management_keys = self.management_keys.iter().map(|k| k.to_entry_dict(self.id)).collect::<Vec<_>>();
let did_document = [("didMethodVersion", self.spec_version), ("managementKey", management_keys)].iter().cloned().collect::<HashMap<_,_>>();
let did_keys = self.did_keys.iter().map(|k| k.to_entry_dict(self.id)).collect::<Vec<_>>();
if did_keys.len() > 0 {
did_document["didKey"] = did_keys;
}
let services = self.services.iter().map(|s| s.to_entry_dict(self.id)).collect::<Vec<_>>();
if services.len() > 0 {
did_document["service"] = services;
}
return did_document;
}
fn _generate_did<RT>(&self) -> RT {
"
        Generates a new DID Id.

        Returns
        -------
        str
            A DID Id.
        ";
self.nonce = os.urandom(32);
let chain_id = calculate_chain_id(vec![EntryType::Create.value, ENTRY_SCHEMA_V100, self.nonce]);
let did_id = "{}:{}".format(DID_METHOD_NAME, chain_id);
return did_id;
}
fn is_valid_did<T0, RT>(did: T0) -> RT {
let try_dummy = { //unsupported
validate_did(did);
};
let except!(ValueError) = { //unsupported
return false;
};
}
fn _check_alias_is_unique_and_add_to_used<T0, T1>(used_aliases: T0, alias: T1)  {
if used_aliases.iter().any(|&x| x == alias) {
raise!(ValueError("Duplicate alias "{}" detected.".format(alias))); //unsupported
}
used_aliases.add(alias);
}
fn _get_network_from_id<T0, RT>(did: T0) -> RT {
"
        Returns the Factom network for this DID (either mainnet or testnet)

        Parameters
        ----------
        did: str

        Returns
        -------
        str
        ";
let parts = did.split(":");
if parts.len() == 4 {
return Network::from_str(parts[2]);
} else {
return Network::Unspecified;
}
} 
}