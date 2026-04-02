use open_passkey_core::base64url;
use open_passkey_core::{
    verify_authentication, verify_registration, AuthenticationInput, RegistrationInput,
};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[allow(dead_code)]
    description: String,
    input: serde_json::Value,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    success: bool,
    error: Option<String>,
    #[serde(rename = "credentialId")]
    credential_id: Option<String>,
    #[serde(rename = "publicKeyCose")]
    public_key_cose: Option<String>,
    #[serde(rename = "signCount")]
    sign_count: Option<u32>,
    #[serde(rename = "rpIdHash")]
    rp_id_hash: Option<String>,
}

#[test]
fn test_registration_vectors() {
    let data = fs::read_to_string("../../spec/vectors/registration.json")
        .expect("Failed to read registration.json");
    let file: VectorFile = serde_json::from_str(&data).expect("Failed to parse registration.json");

    for v in &file.vectors {
        let input = &v.input;
        let credential = &input["credential"];
        let response = &credential["response"];

        let reg_input = RegistrationInput {
            attestation_object: response["attestationObject"]
                .as_str()
                .unwrap()
                .to_string(),
            client_data_json: response["clientDataJSON"].as_str().unwrap().to_string(),
            expected_challenge: input["expectedChallenge"].as_str().unwrap().to_string(),
            expected_origin: input["expectedOrigin"].as_str().unwrap().to_string(),
            rp_id: input["rpId"].as_str().unwrap().to_string(),
            require_user_verification: false,
        };

        let result = verify_registration(reg_input);

        if v.expected.success {
            let res = result.unwrap_or_else(|e| {
                panic!("Vector '{}' expected success but got error: {}", v.name, e)
            });

            if let Some(expected_cred_id) = &v.expected.credential_id {
                let actual = base64url::encode(&res.credential_id);
                assert_eq!(
                    actual, *expected_cred_id,
                    "Vector '{}': credential ID mismatch",
                    v.name
                );
            }

            if let Some(expected_pk) = &v.expected.public_key_cose {
                let actual = base64url::encode(&res.public_key_cose);
                assert_eq!(
                    actual, *expected_pk,
                    "Vector '{}': public key COSE mismatch",
                    v.name
                );
            }

            if let Some(expected_sc) = v.expected.sign_count {
                assert_eq!(
                    res.sign_count, expected_sc,
                    "Vector '{}': sign count mismatch",
                    v.name
                );
            }

            if let Some(expected_hash) = &v.expected.rp_id_hash {
                let actual = base64url::encode(&res.rp_id_hash);
                assert_eq!(
                    actual, *expected_hash,
                    "Vector '{}': rpIdHash mismatch",
                    v.name
                );
            }
        } else {
            let err = result.unwrap_err();
            if let Some(expected_error) = &v.expected.error {
                assert_eq!(
                    err.code(),
                    expected_error.as_str(),
                    "Vector '{}': error code mismatch (got {})",
                    v.name,
                    err.code()
                );
            }
        }
    }
}

#[test]
fn test_authentication_vectors() {
    let data = fs::read_to_string("../../spec/vectors/authentication.json")
        .expect("Failed to read authentication.json");
    let file: VectorFile =
        serde_json::from_str(&data).expect("Failed to parse authentication.json");

    for v in &file.vectors {
        run_authentication_vector(v);
    }
}

#[test]
fn test_hybrid_authentication_vectors() {
    let data = fs::read_to_string("../../spec/vectors/hybrid_authentication.json")
        .expect("Failed to read hybrid_authentication.json");
    let file: VectorFile =
        serde_json::from_str(&data).expect("Failed to parse hybrid_authentication.json");

    for v in &file.vectors {
        run_authentication_vector(v);
    }
}

fn run_authentication_vector(v: &Vector) {
    let input = &v.input;
    let credential = &input["credential"];
    let response = &credential["response"];

    let auth_input = AuthenticationInput {
        authenticator_data: response["authenticatorData"].as_str().unwrap().to_string(),
        client_data_json: response["clientDataJSON"].as_str().unwrap().to_string(),
        signature: response["signature"].as_str().unwrap().to_string(),
        expected_challenge: input["expectedChallenge"].as_str().unwrap().to_string(),
        expected_origin: input["expectedOrigin"].as_str().unwrap().to_string(),
        rp_id: input["rpId"].as_str().unwrap().to_string(),
        stored_public_key_cose: input["storedPublicKeyCose"].as_str().unwrap().to_string(),
        stored_sign_count: input["storedSignCount"].as_u64().unwrap() as u32,
        require_user_verification: false,
    };

    let result = verify_authentication(auth_input);

    if v.expected.success {
        let res = result.unwrap_or_else(|e| {
            panic!("Vector '{}' expected success but got error: {}", v.name, e)
        });

        if let Some(expected_sc) = v.expected.sign_count {
            assert_eq!(
                res.sign_count, expected_sc,
                "Vector '{}': sign count mismatch",
                v.name
            );
        }
    } else {
        let err = result.unwrap_err();
        if let Some(expected_error) = &v.expected.error {
            assert_eq!(
                err.code(),
                expected_error.as_str(),
                "Vector '{}': error code mismatch (got {})",
                v.name,
                err.code()
            );
        }
    }
}
