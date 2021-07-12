use std::collections::HashMap;
use std::*;

use factom_did::client::constants::ENTRY_SCHEMA_V100;
use factom_did::client::enums::{EntryType, Network};
use factom_did::client::validators::validate_full_key_identifier;
use factom_did::resolver::exceptions::MalformedDIDManagementEntry;
use jsonschema::exceptions::ValidationError;
struct EmptyEntryContentValidator {}

impl EmptyEntryContentValidator {
    fn validate<T0>(content: T0) {
        if content {
            raise!(ValidationError("Invalid entry content: must be empty")); //unsupported
        }
    }
}
fn validate_did_management_ext_ids_v100<T0>(ext_ids: T0) {
    "
    Validates the ExtIDs of a DIDManagement entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry

    Raises
    ------
    MalformedDIDManagementEntry
        If the ExtIDs are not valid.
    ";
    if !_validate_ext_ids_length(ext_ids, 2)
        && _validate_entry_type(ext_ids, EntryType::Create)
        && _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
    {
        raise!(MalformedDIDManagementEntry(
            "Invalid or missing {} entry ExtIDs".format(EntryType::Create.value)
        )); //unsupported
    }
}
fn validate_did_update_ext_ids_v100<T0, T1, T2, RT>(ext_ids: T0, chain_id: T1, network: T2) -> RT {
    "
    Validates the ExtIDs of a DIDUpdate entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry
    chain_id: str
        The chain ID where the DIDUpdate is recorded
    network: Network, optional
        The Factom network on which the DID is recorded

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    ";
    return _validate_ext_ids_length(ext_ids, 4)
        && _validate_entry_type(ext_ids, EntryType::Update)
        && _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        && _validate_full_key_identifier(ext_ids)
        && validate_management_key_id_against_chain_id(ext_ids[2], chain_id)
        && validate_id_against_network(ext_ids[2], network);
}
fn validate_did_method_version_upgrade_ext_ids_v100<T0, T1, T2, RT>(
    ext_ids: T0,
    chain_id: T1,
    network: T2,
) -> RT {
    "
    Validates the ExtIDs of a DIDMethodVersionUpgrade entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry
    chain_id: str
        The chain ID where the DIDUpdate is recorded
    network: Network, optional
        The Factom network on which the DID is recorded

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    ";
    return _validate_ext_ids_length(ext_ids, 4)
        && _validate_entry_type(ext_ids, EntryType::VersionUpgrade)
        && _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        && _validate_full_key_identifier(ext_ids)
        && validate_management_key_id_against_chain_id(ext_ids[2], chain_id)
        && validate_id_against_network(ext_ids[2], network);
}
fn validate_did_deactivation_ext_ids_v100<T0, T1, T2, RT>(
    ext_ids: T0,
    chain_id: T1,
    network: T2,
) -> RT {
    "
    Validates the ExtIDs of a DIDDeactivation entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry
    chain_id: str
        The chain ID where the DIDUpdate is recorded
    network: Network, optional
        The Factom network on which the DID is recorded

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    ";
    return _validate_ext_ids_length(ext_ids, 4)
        && _validate_entry_type(ext_ids, EntryType::Deactivation)
        && _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        && _validate_full_key_identifier(ext_ids)
        && validate_management_key_id_against_chain_id(ext_ids[2], chain_id)
        && validate_id_against_network(ext_ids[2], network);
}
fn validate_signature<T0, T1, T2, RT>(ext_ids: T0, content: T1, signing_key: T2) -> RT {
    "
    Checks if the signature contained in the last element of ext_ids is valid.

    The signature is for a DIDUpdate, DIDMethodVersionUpgrade or DIDDeactivation entry and covers the content of the
    entry + the first 3 ext_ids. For more details on the signatures of these entries, refer to
    https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md

    Parameters
    ----------
    ext_ids: list of bytes
    content: bytes
    signing_key: ManagementKey

    Returns
    -------
    bool
    ";
    let signed_data = bytearray();
    for i in (0..3) {
        signed_data.extend(ext_ids[i]);
    }
    signed_data.extend(content);
    return signing_key.verify(hashlib.sha256(signed_data).digest(), ext_ids[3]);
}
fn validate_management_key_id_against_chain_id<T0, T1, RT>(key_id: T0, chain_id: T1) -> RT {
    "
    Checks if the chain in the key_id matches the value supplied in chain_id.

    Parameters
    ----------
    key_id: bytes or str
        The partial or full key identifier
    chain_id: str
        The chain ID

    Raises
    ------
    UnicodeDecodeError
        If the key_id cannot be decoded to a Unicode string

    Returns
    -------
    bool
    ";
    if type_(key_id) == bytes {
        key_id = key_id.decode();
    }
    if key_id.iter().any(|&x| x == ":") {
        let key_id_chain = key_id.split(":")[-1].split("#")[0];
        return key_id_chain == chain_id;
    } else {
        return true;
    }
}
fn validate_id_against_network<T0, T1, RT>(id_value: T0, network: T1) -> RT {
    "
    Checks if the network in the id_value matches the value supplied in network.

    Parameters
    ----------
    id_value: bytes or str
        The partial or full key/service identifier
    network: factom_did.client.enums.Network
        The network

    Raises
    ------
    UnicodeDecodeError
        If the key_id cannot be decoded to a Unicode string

    Returns
    -------
    bool
    ";
    if type_(id_value) == bytes {
        id_value = id_value.decode();
    }
    if id_value.iter().any(|&x| x == ":") {
        let key_id_parts = id_value.split(":");
        if key_id_parts.len() == 4 {
            return key_id_parts[2] == network.value;
        } else {
            return true;
        }
    } else {
        return true;
    }
}
fn _validate_ext_ids_length<T0, T1, RT>(ext_ids: T0, min_length: T1) -> RT {
    return ext_ids.len() >= min_length;
}
fn _validate_entry_type<T0, T1, RT>(ext_ids: T0, entry_type: T1) -> RT {
    let try_dummy = {
        //unsupported
        return ext_ids[0].decode() == entry_type.value;
    };
    let except!(UnicodeDecodeError) = {
        //unsupported
        return false;
    };
}
fn _validate_schema_version<T0, T1, RT>(ext_ids: T0, version: T1) -> RT {
    let try_dummy = {
        //unsupported
        return ext_ids[1].decode() == version;
    };
    let except!(UnicodeDecodeError) = {
        //unsupported
        return false;
    };
}
fn _validate_full_key_identifier<T0, RT>(ext_ids: T0) -> RT {
    let try_dummy = {
        //unsupported
        validate_full_key_identifier(ext_ids[2].decode());
    };
    let except!((UnicodeDecodeError, ValueError)) = {
        //unsupported
        return false;
    };
}
