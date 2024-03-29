use std::collections::HashMap;
use std::*;

use ecdsa::curves::SECP256k1;
struct ECDSASecp256k1Key {
    signing_key: ST0,
    verifying_key: ST1,
}

impl ECDSASecp256k1Key {
    // "
    //     Representation of an ECDSASecp256k1 key. Instances of this class allow signing of messages and signature
    //     verification, as well as key creation and derivation of a public key from a private key.
    //     "
    const ON_CHAIN_PUB_KEY_NAME: _ = "publicKeyBase58";
    fn init<T0, T1>(&self, public_key: T0, private_key: T1) {
        // "
        //         Creates an ECDSASecp256k1Key object.

        //         If both the public and private keys are not provided, it will generate a new key pair.
        //         If both are provided, it will check that the public key corresponds to the private key.
        //         If only a private key is provided, it will derive the public key.
        //         If only a public key is provided, signing will not work, but signature verification is possible.

        //         Parameters
        //         ----------
        //         public_key: str or bytes (optional)
        //             The public key to use when creating the object.
        //         private_key: str or bytes (optional)

        //         Raises
        //         ------
        //         ValueError
        //             If a private or public key is provided in an invalid format
        //         AssertionError
        //             If the public and private keys provided do not correspond to each other
        //         "
        if public_key != None && type_(public_key) != bytes {
            raise!(ValueError("public_key must be bytes")); //unsupported
        }
        if private_key != None && type_(private_key) != bytes {
            raise!(ValueError("private_key must be bytes")); //unsupported
        }
        self._derive_signing_and_verifying_key(public_key, private_key);
    }
    fn represent<RT>(&self) -> RT {
        return "<{}.{}(public_key={}, private_key=({}))>".format(
            self.module,
            type_(self).__name__,
            base58
                .b58encode(self.verifying_key.to_string())
                .decode("utf-8"),
            if self.signing_key != None {
                "hidden"
            } else {
                "not set"
            },
        );
    }
    fn public_key<RT>(&self) -> RT {
        return self.verifying_key.to_string();
    }
    fn private_key<RT>(&self) -> RT {
        return if self.signing_key != None {
            self.signing_key.to_string()
        } else {
            None
        };
    }
    fn sign<T0, T1, RT>(&self, message: T0, hash_f: T1) -> RT {
        // "
        // Signs a message with the existing private key and signature type.

        // The message is hashed before being signed, with the provided hash function. The default hash function used is
        // SHA-256.

        // Parameters
        // ----------
        // message: bytes
        //     The message to sign.
        // hash_f: function, optional
        //     The hash function used to compute the digest of the message before signing it.

        // Returns
        // -------
        // bytes
        //     The bytes of the signatures.

        // Raises
        // ------
        // AssertionError
        //     If the supplied message is not bytes, or if a private key has not been specified.
        // ";
        assert!(type_(message) == bytes);
        assert!(self.signing_key != None);
        return self.signing_key.sign_digest(hash_f(message).digest());
    }
    fn verify<T0, T1, T2, RT>(&self, message: T0, signature: T1, hash_f: T2) -> RT {
        // "
        // Verifies the signature of the given message

        // Parameters
        // ----------
        // message: bytes
        //     The (allegedly) signed message.
        // signature: bytes
        //     The signature to verify.
        // hash_f: function, optional
        //     The hash function used to compute the digest of the message.

        // Returns
        // -------
        // bool
        //     True if the signature is successfully verified, False otherwise.
        // ";
        use ecdsa::keys::BadSignatureError;
        assert!(type_(message) == bytes);
        assert!(type_(signature) == bytes);
        let try_dummy = {
            //unsupported
            return self
                .verifying_key
                .verify_digest(signature, hash_f(message).digest());
        };
        let except!(BadSignatureError) = {
            //unsupported
            return false;
        };
    }
    fn get_public_key_on_chain_repr<RT>(&self) -> RT {
        return (
            self.ON_CHAIN_PUB_KEY_NAME,
            base58.b58encode(self.public_key).decode(),
        );
    }
    fn _derive_signing_and_verifying_key<T0, T1>(&self, public_key: T0, private_key: T1) {
        if public_key == None && private_key == None {
            self.signing_key = ecdsa.SigningKey.generate(SECP256k1);
            self.verifying_key = self.signing_key.get_verifying_key();
            return;
        }
        if public_key != None && private_key != None {
            let try_dummy = {
                //unsupported
                self.signing_key = ecdsa.SigningKey.from_string(private_key, SECP256k1);
            };
            let except!((AssertionError, ValueError)) = {
                //unsupported
                raise!(ValueError(
                    "Invalid ECDSA private key. Must be a 32-byte secret exponent."
                )); //unsupported
            };
            self.verifying_key = self.signing_key.get_verifying_key();
            let non_matching_public_key_msg = "The provided public key does not match the one derived from the provided private key";
            assert!(self.verifying_key.to_string() == public_key);
            return;
        }
        if public_key != None {
            let try_dummy = {
                //unsupported
                self.signing_key = None;
                self.verifying_key = ecdsa.VerifyingKey.from_string(public_key, SECP256k1);
            };
            let except!((AssertionError, ValueError)) = {
                //unsupported
                raise!(ValueError(
                    "Invalid ECDSA public key. Must be a 64-byte encoded SECP256k1 curve point."
                )); //unsupported
            };
        } else {
            let try_dummy = {
                //unsupported
                self.signing_key = ecdsa.SigningKey.from_string(private_key, SECP256k1);
                self.verifying_key = self.signing_key.get_verifying_key();
            };
            let except!((AssertionError, ValueError)) = {
                //unsupported
                raise!(ValueError(
                    "Invalid ECDSA private key. Must be a 32-byte secret exponent."
                )); //unsupported
            };
        }
    }
}
