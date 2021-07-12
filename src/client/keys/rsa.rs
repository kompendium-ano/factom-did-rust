use std::*;
use std::collections::HashMap;

use Crypto::Hash::{SHA256};
use Crypto::PublicKey::{RSA};
use Crypto::Signature::{pkcs1_15};
struct RSAKey {
signing_key: ST0,
verifying_key: ST1,
verifying_key_key: ST2,
}

impl RSAKey {
"
    Representation of an RSA key. Instances of this class allow signing of messages and signature verification, as
    well as key creation and derivation of a public key from a private key.
    ";
const ON_CHAIN_PUB_KEY_NAME: _ = "publicKeyPem";
fn __init__<T0, T1>(&self, public_key: T0, private_key: T1)  {
"
        Creates an RSAKey object.

        If both the public and private keys are not provided, it will generate a new key pair.
        If both are provided, it will check that the public key corresponds to the private key.
        If only a private key is provided, it will derive the public key.
        If only a public key is provided, signing will not work, but signature verification is possible.

        Parameters
        ----------
        public_key: str or bytes (optional)
            The public key to use when creating the object.
        private_key: str or bytes (optional)

        Raises
        ------
        ValueError
            If a private or public key is provided in an invalid format
        AssertionError
            If the public and private keys provided do not correspond to each other
        ";
if public_key != None&&[bytes, str].iter().cloned().collect::<HashSet<_>>().iter().all(|&x| x != type_(public_key)) {
raise!(ValueError("public_key must be either bytes or string")); //unsupported
}
if private_key != None&&[bytes, str].iter().cloned().collect::<HashSet<_>>().iter().all(|&x| x != type_(private_key)) {
raise!(ValueError("private_key must be either bytes or string")); //unsupported
}
self._derive_signing_and_verifying_key(public_key, private_key);
}
fn __repr__<RT>(&self) -> RT {
return "<{}.{}(public_key={}, private_key=({}))>".format(self.__module__, type_(self).__name__, self._minify_public_key(), if self.signing_key != None { "hidden" } else { "not set" });
}
fn public_key<RT>(&self) -> RT {
return self.verifying_key.export_key();
}
fn private_key<RT>(&self) -> RT {
return if self.signing_key != None { self.signing_key.export_key("PEM", None, 8) } else { None };
}
fn sign<T0, T1, RT>(&self, message: T0, hash_f: T1) -> RT {
"
        Signs a message with the existing private key and signature type.

        The message is hashed before being signed, with the provided hash function. The default hash function used is
        SHA-256.

        Parameters
        ----------
        message: bytes
            The message to sign.
        hash_f: function, optional
            The hash function used to compute the digest of the message before signing it.

        Returns
        -------
        bytes
            The bytes of the signatures.

        Raises
        ------
        AssertionError
            If the supplied message is not bytes, or if a private key has not been specified.
        ";
assert!(type_(message) == bytes);
assert!(self.signing_key != None);
return pkcs1_15::new(self.signing_key).sign(hash_f(message));
}
fn verify<T0, T1, T2, RT>(&self, message: T0, signature: T1, hash_f: T2) -> RT {
"
        Verifies the signature of the given message

        Parameters
        ----------
        message: bytes
            The (allegedly) signed message.
        signature: bytes
            The signature to verify.
        hash_f: function, optional
            The hash function used to compute the digest of the message.

        Returns
        -------
        bool
            True if the signature is successfully verified, False otherwise.
        ";
assert!(type_(message) == bytes);
assert!(type_(signature) == bytes);
let try_dummy = { //unsupported
pkcs1_15::new(self.verifying_key).verify(hash_f(message), signature);
};
let except!(ValueError) = { //unsupported
return false;
};
}
fn get_public_key_on_chain_repr<RT>(&self) -> RT {
return (self.ON_CHAIN_PUB_KEY_NAME, self.public_key.decode());
}
fn _minify_public_key<RT>(&self) -> RT {
let public_key = self.public_key.decode();
let start_index = (public_key.find("
") + 1);
let end_index = public_key.rfind("
");
return "{0}...{1}".format(public_key[start_index..(start_index + 20)], public_key[(end_index - 8)..end_index]);
}
fn _derive_signing_and_verifying_key<T0, T1>(&self, public_key: T0, private_key: T1)  {
if public_key == None&&private_key == None {
self.signing_key = RSA::generate(2048);
self.verifying_key = self.signing_key.publickey();
return;
}
if public_key != None&&private_key != None {
self.signing_key = RSA::import_key(private_key);
self.verifying_key = self.signing_key.publickey();
let non_matching_public_key_msg = "The provided public key does not match the one derived from the provided private key";
assert!(RSA::import_key(public_key) == self.verifying_key);
return;
}
if public_key != None {
self.signing_key = None;
self.verifying_key_key = RSA::import_key(public_key);
} else {
self.signing_key = RSA::import_key(private_key);
self.verifying_key = self.signing_key.publickey();
}
} 
}