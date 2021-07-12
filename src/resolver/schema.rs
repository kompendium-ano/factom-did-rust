use std::collections::HashMap;
use std::*;

use factom_did::client::constants::ENTRY_SCHEMA_V100;
use jsonschema::validators::validator_for;
use os::path::{abspath, dirname, join};
fn _load_json_schema<T0, T1, RT>(filename: T0, version: T1) -> RT {
    "Loads the given schema file";
    let relative_path = join("factom_did", "resolver", "schemas", version, filename);
    let absolute_path = abspath(relative_path);
    let base_path = dirname(absolute_path);
    let base_uri = "file://{}/".format(base_path);
    // with!(open(absolute_path) as schema_file) //unsupported
    {
        return jsonref.loads(schema_file.read(), base_uri, true);
    }
}
fn get_schema_validator<T0, T1, RT>(schema_file: T0, version: T1) -> RT {
    "Instantiates the jsonschema.Validator instance for the given schema and version

    Parameters
    ----------
    schema_file: str
        The filename of the JSON schema
    version: str, optional
        The version of the schema

    Returns
    -------
    jsonschema.Validator
        The validator instance for the given schema and version
    ";
    let schema = _load_json_schema(schema_file, version);
    let cls = validator_for(schema);
    cls.check_schema(schema);
    return cls(schema);
}
