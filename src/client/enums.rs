use std::*;
use std::collections::HashMap;


let __all__ = vec!["KeyType", "EntryType", "DIDKeyPurpose", "Network"];
struct KeyType {

}

impl KeyType {
const EdDSA: _ = "Ed25519VerificationKey";
const ECDSA: _ = "ECDSASecp256k1VerificationKey";
const RSA: _ = "RSAVerificationKey";
fn from_str<T0, RT>(string: T0) -> RT {
if string == "Ed25519VerificationKey" {
return KeyType::EdDSA;
} else {
if string == "ECDSASecp256k1VerificationKey" {
return KeyType::ECDSA;
} else {
if string == "RSAVerificationKey" {
return KeyType::RSA;
} else {
raise!(NotImplementedError("Unknown KeyType value: {}".format(string))); //unsupported
}
}
}
} 
}
struct EntryType {

}

impl EntryType {
const Create: _ = "DIDManagement";
const Update: _ = "DIDUpdate";
const VersionUpgrade: _ = "DIDMethodVersionUpgrade";
const Deactivation: _ = "DIDDeactivation"; 
}
struct DIDKeyPurpose {

}

impl DIDKeyPurpose {
const PublicKey: _ = "publicKey";
const AuthenticationKey: _ = "authentication";
fn from_str<T0, RT>(string: T0) -> RT {
if string == "publicKey" {
return DIDKeyPurpose::PublicKey;
} else {
if string == "authentication" {
return DIDKeyPurpose::AuthenticationKey;
} else {
raise!(NotImplementedError("Unknown DIDKeyPurpose value: {}".format(string))); //unsupported
}
}
} 
}
struct Network {

}

impl Network {
const Mainnet: _ = "mainnet";
const Testnet: _ = "testnet";
const Unspecified: _ = "";
fn from_str<T0, RT>(string: T0) -> RT {
if string == "mainnet" {
return Network::Mainnet;
} else {
if string == "testnet" {
return Network::Testnet;
} else {
if string == "" {
return Network::Unspecified;
} else {
raise!(NotImplementedError("Unknown Network value: {}".format(string))); //unsupported
}
}
}
} 
}