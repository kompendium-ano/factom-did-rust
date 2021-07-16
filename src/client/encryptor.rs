use std::*;
use std::collections::HashMap;

use base64::{urlsafe_b64decode};
use Crypto::Cipher::{AES};
use Crypto::Hash::{SHA256, HMAC};
use Crypto::Protocol::KDF::{PBKDF2};
let all = vec!["encrypt_keys", "decrypt_keys_from_str", "decrypt_keys_from_json_str", "decrypt_keys_from_json_file"];
fn encrypt_keys<T0, T1, T2, RT>(management_keys: T0, did_keys: T1, password: T2) -> RT {
"
    Encrypts keys with a password.

    Parameters
    ----------
    management_keys: ManagementKeyModel[]
        A list of management keys to be encrypted.
    did_keys: DidKeyModel[]
        A list of did keys to be encrypted.
    password: str
        A password to use for the encryption of the keys.

    Returns
    -------
    obj
        An object containing salt, initial vector, tag and encrypted data.
    ";
let management_keys_dict = DictComp /*unimplemented()*/;
let did_keys_dict = DictComp /*unimplemented()*/;
let keys_data = [("managementKeys", management_keys_dict), ("didKeys", did_keys_dict)].iter().cloned().collect::<HashMap<_,_>>();
let data = bytes(json.dumps(keys_data), "utf8");
let salt = os.urandom(32);
let iv = os.urandom(16);
let key = _gen_key(password, salt);
let cipher = AES::new(key, AES::MODE_GCM, iv);
let (ciphertext, tag) = cipher.encrypt_and_digest(data);
return [("salt", salt), ("iv", iv), ("data", (ciphertext + tag))].iter().cloned().collect::<HashMap<_,_>>();
}
fn decrypt_keys_from_str<T0, T1, T2, RT>(cipher_text_b64: T0, password: T1, encryption_algo: T2) -> RT {
"
    Decrypts keys from cipher text and password.

    Parameters
    ----------
    cipher_text_b64: str
        Base 64 encoded cipher text.
    password: str
        A password used for the encryption of the keys.
    encryption_algo: str
        The encryption algorithm used. Currently only 'AES-GCM' is supported

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the cipher text or the password used for the encryption is invalid.
    ";
let cipher_text_bin = urlsafe_b64decode(cipher_text_b64);
let (salt, cipher_text_bin) = (cipher_text_bin[..32], cipher_text_bin[32..]);
let (iv, cipher_text_bin) = (cipher_text_bin[..16], cipher_text_bin[16..]);
let ciphertext = cipher_text_bin[..-16];
let tag = cipher_text_bin[-16..];
return _decrypt_keys(salt, iv, ciphertext, tag, password, encryption_algo);
}
fn decrypt_keys_from_json_str<T0, T1, RT>(encrypted_keys_json_str: T0, password: T1) -> RT {
"
    Decrypts keys from JSON string and password. The JSON string must have a
    schema compatible with the one produced by
    DID.export_encrypted_keys_as_json():

    '{
        "encryptionAlgo": {
            "salt": ...,
            "iv": ...,
            "name": ...,
            "tagLength": ...,
        },
        "data": ... (encrypted private keys),
        "did": ...
    }'

    Parameters
    ----------
    encrypted_keys_json_str: str
        JSON string containing encrypted keys data.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the JSON or the password used for the encryption is invalid.
    ";
let try_dummy = { //unsupported
let encrypted_keys_json = json.loads(encrypted_keys_json_str);
};
let except!(json.decoder.JSONDecodeError) = { //unsupported
raise!(ValueError("Invalid JSON file.")); //unsupported
};
return _decrypt_keys_from_json(encrypted_keys_json, password);
}
fn decrypt_keys_from_json_file<T0, T1, RT>(file_path: T0, password: T1) -> RT {
"
    Decrypts keys from JSON file and password. The file must contain valid JSON
    with a schema compatible with the one produced by
    DID.export_encrypted_keys_as_json(). See decrypt_keys_from_json_str for
    details.

    Parameters
    ----------
    file_path: str
        Path to a file to read from.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the file or the password is invalid.
    ";
// with!(open(file_path, "r") as encrypted_file) //unsupported
{
let try_dummy = { //unsupported
let encrypted_keys_json = json.load(encrypted_file);
};
let except!(json.decoder.JSONDecodeError) = { //unsupported
raise!(ValueError("Invalid JSON file.")); //unsupported
};
}
return _decrypt_keys_from_json(encrypted_keys_json, password);
}
fn _decrypt_keys_from_json<T0, T1, RT>(encrypted_keys_json: T0, password: T1) -> RT {
let salt = urlsafe_b64decode(encrypted_keys_json["encryptionAlgo"]["salt"]);
let iv = urlsafe_b64decode(encrypted_keys_json["encryptionAlgo"]["iv"]);
let encrypted_data = urlsafe_b64decode(encrypted_keys_json["data"]);
let tag_length = i32::from(encrypted_keys_json["encryptionAlgo"]["tagLength"]);
let ciphertext = encrypted_data[..-i32::from((tag_length/8))];
let tag = encrypted_data[-i32::from((tag_length/8))..];
let encryption_algo = encrypted_keys_json["encryptionAlgo"]["name"];
return _decrypt_keys(salt, iv, ciphertext, tag, password, encryption_algo);
}
fn _decrypt_keys<T0, T1, T2, T3, T4, T5, RT>(salt: T0, iv: T1, ciphertext: T2, tag: T3, password: T4, encryption_algo: T5) -> RT {
let try_dummy = { //unsupported
let m = _decrypt(iv, ciphertext, tag, password, salt, encryption_algo);
return json.loads(m.decode("utf8"));
};
let except!(json.decoder.JSONDecodeError) = { //unsupported
raise!(ValueError("Invalid encrypted data or password.")); //unsupported
};
}
fn _hmac256<T0, T1, RT>(secret: T0, m: T1) -> RT {
return HMAC::new(secret, m, SHA256).digest();
}
fn _decrypt<T0, T1, T2, T3, T4, T5, RT>(iv: T0, ciphertext: T1, tag: T2, password: T3, salt: T4, encryption_algo: T5) -> RT {
if encryption_algo != "AES-GCM" {
raise!(NotImplementedError("Currently only AES-GCM is supported!")); //unsupported
}
let key = _gen_key(password, salt);
let decryptor = AES::new(key, AES::MODE_GCM, iv);
return decryptor.decrypt_and_verify(ciphertext, tag);
}
fn _gen_key<T0, T1, RT>(password: T0, salt: T1) -> RT {
return PBKDF2(password, salt, 32, 10000, _hmac256);
}