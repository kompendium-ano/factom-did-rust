use std::*;
use std::collections::HashMap;

use factom_did::client::constants::{ENTRY_SCHEMA_V100};
use factom_did::client::enums::{KeyType};
use factom_did::client::keys::abstract::{AbstractDIDKey};
struct ManagementKey {
priority: ST0,
}

impl ManagementKey {
// "
//     A key used to sign updates for an existing DID.

//     Attributes
//     ----------
//     alias: str
//     priority: int
//         A non-negative integer showing the hierarchical level of the key. Keys with lower priority override keys with
//         higher priority.
//     key_type: KeyType
//     controller: str
//     priority_requirement: int, optional
//     public_key: str, optional
//     private_key: str, optional
//     ";
fn init<T0, T1, T2, T3, T4, T5, T6>(&self, alias: T0, priority: T1, key_type: T2, controller: T3, priority_requirement: T4, public_key: T5, private_key: T6)  {
super().init(alias, key_type, controller, priority_requirement, public_key, private_key);
if isinstance(priority, int) == false||priority < 0 {
raise!(ValueError("Priority must be a non-negative integer.")); //unsupported
}
self.priority = priority;
}
fn __eq__<T0, RT>(&self, other: T0) -> RT {
if self.__class__ == other.__class__ {
return super().__eq__(other)&&self.priority == other.priority;
}
return NotImplemented;
}
fn __hash__<RT>(&self) -> RT {
return hash((self.alias, self.priority, self.key_type, self.controller, self.priority_requirement, self.public_key, self.private_key));
}
fn __repr__<RT>(&self) -> RT {
return "<{}.{}(alias={}, priority={}, key_type={}, controller={}, priority_requirement={})>".format(self.__module__, type_(self).__name__, self.alias, self.priority, self.underlying, self.controller, self.priority_requirement);
}
fn to_entry_dict<T0, T1, RT>(&self, did: T0, version: T1) -> RT {
if version == ENTRY_SCHEMA_V100 {
let d = super().to_entry_dict(did);
d["priority"] = self.priority;
return d;
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
}
fn from_entry_dict<T0, T1, RT>(entry_dict: T0, version: T1) -> RT {
if version == ENTRY_SCHEMA_V100 {
return ManagementKey(entry_dict["id"].split("#")[-1], entry_dict["priority"], KeyType::from_str(entry_dict["type"]), entry_dict["controller"], entry_dict.get("priorityRequirement"), if entry_dict.iter().any(|&x| x == "publicKeyBase58") { base58.b58decode(entry_dict["publicKeyBase58"]) } else { entry_dict["publicKeyPem"] }, None);
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
} 
}