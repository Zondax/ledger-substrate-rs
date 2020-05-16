/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
// Integration tests

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate ed25519_dalek;
extern crate hex;
extern crate ledger_kusama;
#[macro_use]
extern crate matches;
extern crate sha2;
#[macro_use]
extern crate serial_test;
use blake2b_simd::Params;

use ledger_kusama::{KusamaApp, LedgerAppError};

#[test]
#[serial]
fn version() {
    let app = KusamaApp::connect().unwrap();

    let resp = app.version();

    match resp {
        Ok(version) => {
            println!("mode  {}", version.mode);
            println!("major {}", version.major);
            println!("minor {}", version.minor);
            println!("patch {}", version.patch);

            // assert_eq!(version.major, 0x00);
            // assert!(version.minor >= 0x04);
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
        }
    }
}

#[test]
#[serial]
fn address() {
    let app = KusamaApp::connect().unwrap();
    let resp = app.address(0, 0, 5, false);

    match resp {
        Ok(addr) => {
            assert_eq!(addr.public_key.len(), 32);
            assert_eq!(
                hex::encode(addr.public_key),
                "d280b24dface41f31006e5a2783971fc5a66c862dd7d08f97603d2902b75e47a"
            );
            assert_eq!(addr.ss58, "HLKocKgeGjpXkGJU6VACtTYJK4ApTCfcGRw51E5jWntcsXv");

            println!("Public Key   {:?}", hex::encode(addr.public_key));
            println!("Address SS58 {:?}", addr.ss58);
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
            panic!()
        }
    }
}

#[test]
#[serial]
fn show_address() {
    let app = KusamaApp::connect().unwrap();
    let resp = app.address(0, 0, 5, true);

    match resp {
        Ok(addr) => {
            assert_eq!(addr.public_key.len(), 32);
            assert_eq!(
                hex::encode(addr.public_key),
                "d280b24dface41f31006e5a2783971fc5a66c862dd7d08f97603d2902b75e47a"
            );
            assert_eq!(addr.ss58, "HLKocKgeGjpXkGJU6VACtTYJK4ApTCfcGRw51E5jWntcsXv");

            println!("Public Key   {:?}", hex::encode(addr.public_key));
            println!("Address SS58 {:?}", addr.ss58);
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
            panic!()
        }
    }
}

#[test]
#[serial]
fn sign_empty() {
    let app = KusamaApp::connect().unwrap();

    let some_message0 = b"";

    let signature = app.sign(0, 0, 0, some_message0);
    assert!(signature.is_err());
    assert!(matches!(
        signature.err().unwrap(),
        LedgerAppError::InvalidEmptyMessage
    ));
}

#[test]
#[serial]
fn sign_verify() {
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;

    let app = KusamaApp::connect().unwrap();

    let txstr = "0000b30d1caed503000b63ce64c10c0526040000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
    let blob = hex::decode(txstr).unwrap();

    // First, get public key
    let addr = app.address(0, 0, 0, false).unwrap();
    let public_key = PublicKey::from_bytes(&addr.public_key).unwrap();

    match app.sign(0, 0, 0, &blob) {
        Ok(reply_signature) => {

            // we need to remove first byte (there is a new prepended byte)
            let signature = Signature::from_bytes(&reply_signature[1..]).unwrap();

            if blob.len() > 256 {
                // When the blob is > 256, the digest is signed
                let message_hashed = Params::new()
                    .hash_length(64)
                    .to_state()
                    .update(&blob)
                    .finalize();

                assert!(public_key.verify((&message_hashed).as_ref(), &signature).is_ok());
            } else {
                assert!(public_key.verify(&blob, &signature).is_ok());
            }
        }
        Err(e) => {
            println!("Err {:#?}", e);
            panic!();
        }
    }
}
