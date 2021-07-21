use std::*;
use std::collections::HashMap;

use factom_did::client::constants::{ENTRY_SCHEMA_V100};
use factom_did::client::enums::{DIDKeyPurpose, KeyType};
use factom_did::client::keys::abstract::{AbstractDIDKey};
struct DIDKey {
purpose: ST0,
}

impl DIDKey {
// "
//     Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.

//     Attributes
//     ----------
//     alias: str
//     purpose: DIDKeyPurpose or DIDKeyPurpose[]
//         Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
//     key_type: KeyType
//     controller: str
//     priority_requirement: int, optional
//     public_key: str, optional
//     private_key: str, optional
//     ";

fn init<T0, T1, T2, T3, T4, T5, T6>(&self, alias: T0, purpose: T1, key_type: T2, controller: T3, priority_requirement: T4, public_key: T5, private_key: T6)  {
super().init(alias, key_type, controller, priority_requirement, public_key, private_key);

if type_(purpose) == list {
purpose_l = purpose;
} else {
purpose_l = vec![purpose];
}
assert!(set(purpose_l).len() == purpose_l.len()&&purpose_l.len() == 1||purpose_l.len() == 2);
for purpose_type in purpose_l {
if [DIDKeyPurpose::PublicKey, DIDKeyPurpose::AuthenticationKey].iter().cloned().collect::<HashSet<_>>().iter().all(|&x| x != purpose_type) {
raise!(ValueError("Purpose must contain only valid DIDKeyPurpose values.")); //unsupported
}
}
self.purpose = purpose_l;
}
fn __eq__<T0, RT>(&self, other: T0) -> RT {
if self.__class__ == other.__class__ {
return super().__eq__(other)&&self.purpose == other.purpose;
}
return NotImplemented;
}
fn __hash__<RT>(&self) -> RT {
return hash((self.alias, "".join(self.purpose.iter().map(|x| x.value)), self.key_type, self.controller, self.priority_requirement, self.public_key, self.private_key));
}
fn __repr__<RT>(&self) -> RT {
return "<{}.{}(alias={}, purpose={}, key_type={}, controller={}, priority_requirement={})>".format(self.__module__, type_(self).__name__, self.alias, self.purpose, self.underlying, self.controller, self.priority_requirement);
}
fn to_entry_dict<T0, T1, RT>(&self, did: T0, version: T1) -> RT {
if version == ENTRY_SCHEMA_V100 {
let d = super().to_entry_dict(did);
d["purpose"] = self.purpose.iter().map(|x| x.value).collect::<Vec<_>>();
return d;
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
}
fn from_entry_dict<T0, T1, RT>(entry_dict: T0, version: T1) -> RT {
if version == ENTRY_SCHEMA_V100 {
return DIDKey(entry_dict["id"].split("#")[-1], entry_dict.get("purpose").iter().map(DIDKeyPurpose::from_str).collect::<Vec<_>>(), KeyType::from_str(entry_dict["type"]), entry_dict["controller"], entry_dict.get("priorityRequirement"), if entry_dict.iter().any(|&x| x == "publicKeyBase58") { base58.b58decode(entry_dict["publicKeyBase58"]) } else { entry_dict["publicKeyPem"] }, None);
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
} 
}