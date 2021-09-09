use crate::{did::Did, mock::*, AttributeTransaction, Error};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};

#[test]
fn add_on_chain_and_revoke_off_chain_attribute() {
    new_test_ext().execute_with(|| {
        let name = b"MyAttribute".to_vec();
        let mut value = [1, 2, 3].to_vec();
        let mut validity: u32 = 1000;

        // Create a new account pair and get the public key.
        let alice_pair = account_pair("Alice");
        let alice_public = alice_pair.public();

        // Add a new attribute to an identity. Valid until block 1 + 1000.
        assert_ok!(DID::add_attribute(
            Origin::signed(alice_public),
            alice_public,
            name.clone(),
            value.clone(),
            Some(validity.clone().into())
        ));

        // Validate that the attribute contains_key and has not expired.
        assert_ok!(DID::valid_attribute(&alice_public, &name, &value));

        // Revoke attribute off-chain
        // Set validity to 0 in order to revoke the attribute.
        validity = 0;
        value = [0].to_vec();
        let mut encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let revoke_sig = alice_pair.sign(&encoded);

        let revoke_transaction = AttributeTransaction {
            signature: revoke_sig,
            name: name.clone(),
            value,
            validity,
            signer: alice_public,
            identity: alice_public,
        };

        // Revoke with off-chain signed transaction.
        assert_ok!(DID::execute(
            Origin::signed(alice_public),
            revoke_transaction
        ));

        // Validate that the attribute was revoked.
        assert_noop!(
            DID::valid_attribute(&alice_public, &name, &[1, 2, 3].to_vec()),
            Error::<Test>::InvalidAttribute
        );
    });
}