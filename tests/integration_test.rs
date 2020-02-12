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

            assert_eq!(version.major, 0x00);
            assert!(version.minor >= 0x04);
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
                "8d16d62802ca55326ec52bf76a8543b90e2aba5bcf6cd195c0d6fc1ef38fa1b3"
            );
            assert_eq!(addr.ss58, "FmK43tjzFGT9F68Sj9EvW6rwBQUAVuA9wNQaYxGLvfcCAxS");

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
    let app = KusamaApp::connect().unwrap();

    let txstr = "060904d503910133158139ae28a3dfaac5fe1560a5e9e05cc8010000fe06016e907605fb7ae9e09efc7237e57d31a32096a65d14f56524f37b909ef75390da7afac52b00d971bf76d6f513b138862eba20ed49cfd7580affaa9d3dba";
    let blob = hex::decode(txstr).unwrap();

    match app.sign(0, 0, 0, &blob) {
        Ok(sig) => {
            use ed25519_dalek::PublicKey;
            use ed25519_dalek::Signature;

            println!("{:#?}", sig.to_vec());

            // First, get public key
            let addr = app.address(0, 0, 0, false).unwrap();
            let public_key = PublicKey::from_bytes(&addr.public_key).unwrap();
            let signature = Signature::from_bytes(&sig).unwrap();

            // Verify signature
            assert!(public_key.verify(&blob, &signature).is_ok());
        }
        Err(e) => {
            println!("Err {:#?}", e);
            panic!();
        }
    }
}
