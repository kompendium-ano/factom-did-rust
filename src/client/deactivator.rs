use std::collections::HashMap;
use std::*;

use factom_did::client::blockchain::record_entry;
use factom_did::client::constants::ENTRY_SCHEMA_V100;
use factom_did::client::enums::EntryType;

struct DIDDeactivator {
    did: ST0,
    signing_key: ST1,
}

//    Facilitates the creation of a DIDDeactivation entry.
//
//    Attributes
//    ----------
//    did: client.did.DID
//        The DID object to update
//
impl DIDDeactivator {
    fn init<T0>(&self, did: T0) {
        self.did = did;
        self.signing_key = sorted(self.did.management_keys, op.attrgetter("priority"))[0];
        assert!(self.signing_key.priority == 0);
    }

    //        Constructs a signed DIDDeactivation entry ready for recording on-chain.
    //
    //        Returns
    //        -------
    //        dict
    //            A dictionary with ExtIDs and content for the entry

    fn export_entry_data<RT>(&self) -> RT {
        let data_to_sign = "".join(vec![
            EntryType::Deactivation.value,
            ENTRY_SCHEMA_V100,
            self.signing_key.full_id(self.did.id),
        ]);
        let signature = self
            .signing_key
            .sign(hashlib.sha256(data_to_sign.encode("utf-8")).digest());
        let ext_ids = vec![
            EntryType::Deactivation.value.encode("utf-8"),
            ENTRY_SCHEMA_V100::encode("utf-8"),
            self.signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ];
        return [("ext_ids", ext_ids), ("content", b"")]
            .iter()
            .cloned()
            .collect::<HashMap<_, _>>();
    }
    fn record_on_chain<T0, T1, T2, T3>(
        &self,
        factomd: T0,
        walletd: T1,
        ec_address: T2,
        verbose: T3,
    ) {
        // "
        // Attempts to record the DIDDeactivation entry on-chain.

        // Parameters
        // ----------
        // factomd: obj
        //     Factomd instance, instantiated from the Python factom-api package.
        // walletd: obj
        //     Factom walletd instance, instantiated from the Python factom-api package.
        // ec_address: str
        //     EC address used to pay for the chain & entry creation.
        // verbose: bool, optional
        //     If true, display the contents of the entry that will be recorded
        //     on-chain.

        // Raises
        // ------
        // RuntimeError
        //     If the entry cannot be recorded
        // ";
        record_entry(
            self.did.get_chain(),
            self.export_entry_data(),
            factomd,
            walletd,
            ec_address,
            verbose,
        );
    }
}
