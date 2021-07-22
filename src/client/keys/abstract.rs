use std::collections::HashMap;
use std::*;

use factom_did::client::constants::ENTRY_SCHEMA_V100;
use factom_did::client::enums::KeyType;
use factom_did::client::keys::ecdsa::ECDSASecp256k1Key;
use factom_did::client::keys::eddsa::Ed25519Key;
use factom_did::client::keys::rsa::RSAKey;
use factom_did::client::validators::{
    validate_alias, validate_did, validate_key_type, validate_priority_requirement,
};
struct AbstractDIDKey {
    alias: ST0,
    key_type: ST1,
    controller: ST2,
    priority_requirement: ST3,
    underlying: ST4,
}

//     Represents the common fields and functionality in a ManagementKey and a DidKey.
//     Attributes
//     ----------
//     alias: str
//         A human-readable nickname for the key.
//     key_type: KeyType
//         Identifies the type of signature that the key pair can be used to generate and verify.
//     controller: str
//         An entity that controls the key.
//     priority_requirement: int
//         A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
//     public_key: bytes or str, optional
//         The public key.
//     private_key: bytes or str, optional
//         The private key.
impl AbstractDIDKey {
    fn init<T0, T1, T2, T3, T4, T5>(
        &self,
        alias: T0,
        key_type: T1,
        controller: T2,
        priority_requirement: T3,
        public_key: T4,
        private_key: T5,
    ) {
        self.validate_key_input_params(alias, key_type, controller, priority_requirement);
        self.alias = alias;
        self.key_type = key_type;
        self.controller = controller;
        self.priority_requirement = priority_requirement;
        if self.key_type == KeyType::EdDSA {
            self.underlying = Ed25519Key(public_key, private_key);
        } else {
            if self.key_type == KeyType::ECDSA {
                self.underlying = ECDSASecp256k1Key(public_key, private_key);
            } else {
                if self.key_type == KeyType::RSA {
                    self.underlying = RSAKey(public_key, private_key);
                } else {
                    raise!(NotImplementedError(
                        "Unsupported signature type: {}".format(self.key_type.value)
                    )); //unsupported
                }
            }
        }
    }
    fn equals<T0, RT>(&self, other: T0) -> RT {
        if self.class == other.class {
            return (
                self.alias,
                self.key_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            ) == (
                other.alias,
                other.key_type,
                other.controller,
                other.priority_requirement,
                other.public_key,
                other.private_key,
            );
        }
        return NotImplemented;
    }
    fn verifying_key<RT>(&self) -> RT {
        return self.underlying.verifying_key;
    }
    fn signing_key<RT>(&self) -> RT {
        return self.underlying.signing_key;
    }
    fn public_key<RT>(&self) -> RT {
        return self.underlying.public_key;
    }
    fn private_key<RT>(&self) -> RT {
        return self.underlying.private_key;
    }
    fn sign<T0, T1, RT>(&self, message: T0, hash_f: T1) -> RT {
        return if hash_f != None {
            self.underlying.sign(message, hash_f)
        } else {
            self.underlying.sign(message)
        };
    }
    fn verify<T0, T1, T2, RT>(&self, message: T0, signature: T1, hash_f: T2) -> RT {
        return if hash_f != None {
            self.underlying.verify(message, signature, hash_f)
        } else {
            self.underlying.verify(message, signature)
        };
    }
    fn to_entry_dict<T0, T1, RT>(&self, did: T0, version: T1) -> RT {
        "
        Converts the object to a dictionary suitable for recording on-chain.

        Parameters
        ----------
        did: str
            The DID with which this key is associated. Note that this can be different from the key controller.
        version: str
            The entry schema version

        Returns
        -------
        dict
            Dictionary with `id`, `type`, `controller` and an optional `priorityRequirement` fields. In addition to
            those, there is one extra field for the public key: if the selected signature type is SignatureType.RSA,
            then this field is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.

        ";
        if version == ENTRY_SCHEMA_V100 {
            let d = dict();
            d["id"] = self.full_id(did);
            d["type"] = self.key_type.value;
            d["controller"] = self.controller;
            let (key, value) = self.underlying.get_public_key_on_chain_repr();
            d[key] = value;
            if self.priority_requirement != None {
                d["priorityRequirement"] = self.priority_requirement;
            }
            return d;
        } else {
            raise!(NotImplementedError(
                "Unknown schema version: {}".format(version)
            )); //unsupported
        }
    }
    fn from_entry_dict<T0, T1, RT>(entry_dict: T0, version: T1) -> RT {
        "
        Creates an AbstractDIDKey object from an on-chain entry

        Parameters
        ----------
        entry_dict: dict
            The on-chain entry, represented as a Python dictionary
        version: str
            The entry schema version

        Returns
        -------
        AbstractDIDKey

        Raises
        ------
        NotImplementedError
            If the supplied version is not supported
        ";
        if version == ENTRY_SCHEMA_V100 {
            return AbstractDIDKey(
                entry_dict.get("id", "").split("#")[-1],
                KeyType::from_str(entry_dict.get("type")),
                entry_dict.get("controller"),
                entry_dict.get("priorityRequirement"),
                if entry_dict.iter().any(|&x| x == "publicKeyBase58") {
                    base58.b58decode(entry_dict["publicKeyBase58"])
                } else {
                    entry_dict.get("publicKeyPem")
                },
            );
        } else {
            raise!(NotImplementedError(
                "Unknown schema version: {}".format(version)
            )); //unsupported
        }
    }
    fn rotate(&self) {
        "
        Generates new key pair for the key.
        ";
        assert!(self.signing_key != None);
        self.underlying = self.underlying.class();
    }
    fn full_id<T0, RT>(&self, did: T0) -> RT {
        "
        Constructs the full ID of the key.

        Parameters
        ----------
        did: str

        Returns
        -------
        str
            The full id for the key, constituting of the DID_METHOD_NAME, the network, the chain ID and the key alias.
        ";
        return "{}#{}".format(did, self.alias);
    }
    fn validate_key_input_params<T0, T1, T2, T3>(
        alias: T0,
        key_type: T1,
        controller: T2,
        priority_requirement: T3,
    ) {
        validate_alias(alias);
        validate_key_type(key_type);
        validate_did(controller);
        validate_priority_requirement(priority_requirement);
    }
}
