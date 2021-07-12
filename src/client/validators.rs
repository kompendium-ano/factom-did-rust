use std::*;
use std::collections::HashMap;

use factom_did::client::constants::{DID_METHOD_NAME};
use factom_did::client::enums::{KeyType, Network};
fn validate_alias<T0>(alias: T0)  {
if !re.match("^[a-z0-9-]{1,32}$", alias) {
raise!(ValueError("Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.")); //unsupported
}
}
fn validate_did<T0>(did: T0)  {
if !re.match("^{}:({}:|{}:)?[a-f0-9]{{64}}$".format(DID_METHOD_NAME, Network::Mainnet.value, Network::Testnet.value), did) {
raise!(ValueError("Controller must be a valid DID.")); //unsupported
}
}
fn validate_full_key_identifier<T0>(did: T0)  {
if !re.match("^{}:({}:|{}:)?[a-f0-9]{{64}}#[a-zA-Z0-9-]{{1,32}}$".format(DID_METHOD_NAME, Network::Mainnet.value, Network::Testnet.value), did) {
raise!(ValueError("Controller must be a valid DID.")); //unsupported
}
}
fn validate_service_endpoint<T0>(endpoint: T0)  {
if !re.match("^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$", endpoint) {
raise!(ValueError("Endpoint must be a valid URL address starting with http:// or https://.")); //unsupported
}
}
fn validate_priority_requirement<T0>(priority_requirement: T0)  {
if priority_requirement != None&&isinstance(priority_requirement, int) == false||priority_requirement < 0 {
raise!(ValueError("Priority requirement must be a non-negative integer.")); //unsupported
}
}
fn validate_key_type<T0>(key_type: T0)  {
if (KeyType::ECDSA, KeyType::EdDSA, KeyType::RSA).iter().all(|&x| x != key_type) {
raise!(ValueError("Type must be a valid signature type.")); //unsupported
}
}