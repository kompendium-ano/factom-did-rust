use std::*;
use std::collections::HashMap;

use packaging::{version};
use factom_did::client::blockchain::{record_entry};
use factom_did::client::constants::{ENTRY_SCHEMA_V100};
use factom_did::client::enums::{EntryType};
struct DIDVersionUpgrader {
did: ST0,
new_spec_version: ST1,
}

impl DIDVersionUpgrader {
"
    Facilitates the creation of an DIDMethodVersionUpgrade entry for an existing DID.

    Attributes
    ----------
    did: client.did.DID
        The DID object to update
    new_spec_version: str
        The new version to upgrade to

    Raises
    ------
    ValueError
        If the new version is not an upgrade on the current version
    ";
fn init<T0, T1>(&self, did: T0, new_spec_version: T1)  {
if version::parse(did.spec_version) >= version::parse(new_spec_version) {
raise!(ValueError("New version must be an upgrade on old version")); //unsupported
}
self.did = did;
self.new_spec_version = new_spec_version;
}
fn export_entry_data<RT>(&self) -> RT {
"
        Constructs a signed DIDMethodVersionUpgrade entry ready for recording on-chain.

        Returns
        -------
        dict
            A dictionary with ExtIDs and content for the entry
        ";
let signing_key = sorted(self.did.management_keys, op.attrgetter("priority"), true)[0];
let entry_content = json.dumps([("didMethodVersion", self.new_spec_version)].iter().cloned().collect::<HashMap<_,_>>()).replace(" ", "");
let data_to_sign = "".join(vec![EntryType::VersionUpgrade.value, ENTRY_SCHEMA_V100, signing_key.full_id(self.did.id), entry_content]);
let signature = signing_key.sign(hashlib.sha256(data_to_sign.encode("utf-8")).digest());
let ext_ids = vec![EntryType::VersionUpgrade.value.encode("utf-8"), ENTRY_SCHEMA_V100::encode("utf-8"), signing_key.full_id(self.did.id).encode("utf-8"), signature];
return [("ext_ids", ext_ids), ("content", entry_content.encode("utf-8"))].iter().cloned().collect::<HashMap<_,_>>();
}
fn record_on_chain<T0, T1, T2, T3>(&self, factomd: T0, walletd: T1, ec_address: T2, verbose: T3)  {
"
        Attempts to record the DIDMethodVersionUpgrade entry on-chain.

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
}