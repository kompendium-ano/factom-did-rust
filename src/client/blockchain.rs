use std::collections::HashMap;
use std::*;

use factom::exceptions::FactomAPIError;
fn calculate_entry_size<T0, T1, RT>(ext_ids: T0, content: T1) -> RT {
    "
    Calculates entry size in bytes.

    Parameters
    ----------
    ext_ids: bytes[] or str[]
    content: bytes or str

    Returns
    -------
    int
        A total size of the entry in bytes.
    ";
    let mut total_entry_size = 0;
    let fixed_header_size = 35;
    total_entry_size += (fixed_header_size + (2 * ext_ids.len()));
    let hex_str_re = re.compile("[0-9a-f]+");
    for ext_id in ext_ids {
        if type_(ext_id) == bytes {
            total_entry_size += ext_id.len();
        } else {
            assert!(hex_str_re.match(ext_id) != None);
            total_entry_size += (ext_id.len() / 2);
        }
    }
    if type_(content) == bytes {
        total_entry_size += content.len();
    } else {
        assert!(hex_str_re.match(content) != None);
        total_entry_size += (content.len() / 2);
    }
    return total_entry_size;
}
fn calculate_chain_id<T0, RT>(ext_ids: T0) -> RT {
    "
    Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.

    Parameters
    ----------
    ext_ids: list
        A list of ExtIDs.

    Returns
    -------
    str
        A chain id.
    ";
    let ext_ids_hash_bytes = bytearray(b"");
    for ext_id in ext_ids {
        if type_(ext_id) == bytes {
            ext_ids_hash_bytes.extend(hashlib.sha256(ext_id).digest());
        } else {
            ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, "utf-8")).digest());
        }
    }
    return hashlib.sha256(ext_ids_hash_bytes).hexdigest();
}
fn create_chain<T0, T1, T2, T3, T4>(
    entry_data: T0,
    factomd: T1,
    walletd: T2,
    ec_address: T3,
    verbose: T4,
) {
    "
    Attempts to create a Factom chain from the provided entry data.

    Parameters
    ----------
    entry_data: dict
        A dictionary with two keys: ext_ids and content. The value of ext_ids must be a list
        of bytes or hex encoded string, while the value of content must be bytes or hex encoded str.
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
    use pprint::pprint;
    if verbose {
        pprint(entry_data);
    }
    let try_dummy = {
        //unsupported
        walletd.new_chain(
            factomd,
            entry_data["ext_ids"],
            entry_data["content"],
            ec_address,
        );
    };
    let except!(FactomAPIError) = {
        //unsupported
        raise!(RuntimeError(
            "Failed while trying to create the chain: {}".format(e.data)
        )); //unsupported
    };
}
fn record_entry<T0, T1, T2, T3, T4, T5>(
    chain_id: T0,
    entry_data: T1,
    factomd: T2,
    walletd: T3,
    ec_address: T4,
    verbose: T5,
) {
    "
    Attempts to record a Factom entry in the give chain with the provided entry data.

    Parameters
    ----------
    chain_id: str
        The chain in which to record the entry.
    entry_data: dict
        A dictionary with two keys: ext_ids and content. The value of ext_ids must be a list
        of bytes or hex encoded string, while the value of content must be bytes or hex encoded str.
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
            If the entry cannot be created
    ";
    use pprint::pprint;
    if verbose {
        pprint(entry_data);
    }
    let try_dummy = {
        //unsupported
        walletd.new_entry(
            factomd,
            chain_id,
            entry_data["ext_ids"],
            entry_data["content"],
            ec_address,
        );
    };
    let except!(FactomAPIError) = {
        //unsupported
        raise!(RuntimeError(
            "Failed while trying to record entry data on-chain: {}".format(e.data)
        )); //unsupported
    };
}
