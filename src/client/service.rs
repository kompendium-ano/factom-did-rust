use std::*;
use std::collections::HashMap;

use factom_did::client::constants::{ENTRY_SCHEMA_V100};
use factom_did::client::validators::{validate_alias, validate_priority_requirement, validate_service_endpoint};
let __all__ = vec!["Service"];
struct Service {
alias: ST0,
service_type: ST1,
endpoint: ST2,
priority_requirement: ST3,
custom_fields: ST4,
}

impl Service {
"
    Represent a service associated with a DID. A service is an end-point, which can be used to communicate with the DID
    or to carry out different tasks on behalf of the DID (such as signatures, e.g.)

    Attributes
    ----------
    alias: str
        A human-readable nickname for the service endpoint.
    service_type: str
        Type of the service endpoint (e.g. email, credential store).
    endpoint: str
        A service endpoint may represent any type of service the subject wishes to advertise,
        including decentralized identity management services for further discovery,
        authentication, authorization, or interaction.
        The service endpoint must be a valid URL.
    priority_requirement: int, optional
        A non-negative integer showing the minimum hierarchical level a key must have in order to remove this service.
    custom_fields: dict, optional
        A dictionary containing custom fields (e.g "description": "My public social inbox").
    ";
fn __init__<T0, T1, T2, T3, T4>(&self, alias: T0, service_type: T1, endpoint: T2, priority_requirement: T3, custom_fields: T4)  {
self._validate_service_input_params(alias, service_type, endpoint, priority_requirement);
self.alias = alias;
self.service_type = service_type;
self.endpoint = endpoint;
self.priority_requirement = priority_requirement;
self.custom_fields = custom_fields;
}
fn __eq__<T0, RT>(&self, other: T0) -> RT {
if self.__class__ == other.__class__ {
return (self.alias, self.service_type, self.endpoint, self.priority_requirement, self.custom_fields) == (other.alias, other.service_type, other.endpoint, other.priority_requirement, other.custom_fields);
}
return NotImplemented;
}
fn __hash__<RT>(&self) -> RT {
return hash((self.alias, self.service_type, self.endpoint, self.priority_requirement, if self.custom_fields { json.dumps(self.custom_fields) } else { None }));
}
fn __repr__<RT>(&self) -> RT {
return "<{}.{}(alias={}, service_type={}, endpoint={}, priority_requirement={}, custom_fields={})>".format(self.__module__, type_(self).__name__, self.alias, self.service_type, self.endpoint, self.priority_requirement, self.custom_fields);
}
fn to_entry_dict<T0, T1, RT>(&self, did: T0, version: T1) -> RT {
"
        Converts the object to a dictionary suitable for recording on-chain.

        Parameters
        ----------
        did: str
            The DID to which this service belongs.
        version: str
            The entry schema version

        Raises
        ------
        NotImplementedError
            If the entry schema version is not supported
        ";
if version == ENTRY_SCHEMA_V100 {
let d = dict();
d["id"] = self.full_id(did);
d["type"] = self.service_type;
d["serviceEndpoint"] = self.endpoint;
if self.priority_requirement != None {
d["priorityRequirement"] = self.priority_requirement;
}
if self.custom_fields != None {
for key in self.custom_fields {
d[key] = self.custom_fields[key];
}
}
return d;
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
}
fn from_entry_dict<T0, T1, RT>(entry_dict: T0, version: T1) -> RT {
if version == ENTRY_SCHEMA_V100 {
let custom_fields = dict();
for key in entry_dict {
if ("id", "type", "serviceEndpoint", "priorityRequirement").iter().all(|&x| x != key) {
custom_fields[key] = entry_dict[key];
}
}
return Service(entry_dict.get("id", "").split("#")[-1], entry_dict.get("type", ""), entry_dict.get("serviceEndpoint", ""), entry_dict.get("priorityRequirement"), if custom_fields.items().len() > 0 { custom_fields } else { None });
} else {
raise!(NotImplementedError("Unknown schema version: {}".format(version))); //unsupported
}
}
fn full_id<T0, RT>(&self, did: T0) -> RT {
"
        Returns
        -------
        str
            The full id for the service, constituting of the DID_METHOD_NAME, the controller and the service alias.
        ";
return "{}#{}".format(did, self.alias);
}
fn _validate_service_input_params<T0, T1, T2, T3>(alias: T0, service_type: T1, endpoint: T2, priority_requirement: T3)  {
validate_alias(alias);
if !service_type {
raise!(ValueError("Type is required.")); //unsupported
}
validate_service_endpoint(endpoint);
validate_priority_requirement(priority_requirement);
} 
}