/*******************************************************************************
*   (c) 2018-2020 Zondax GmbH
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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate ed25519_dalek;
extern crate hex;
#[macro_use]
extern crate matches;
extern crate sha2;
#[macro_use]
extern crate serial_test;
extern crate ledger_substrate;

#[cfg(test)]
mod integration_tests {
    use blake2b_simd::Params;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;
    use futures_await_test::async_test;
    use ledger_substrate::{APDUTransport, new_kusama_app};
    use zx_bip44::BIP44Path;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[async_test]
    #[serial]
    async fn version() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let resp = app.get_version().await.unwrap();

        println!("mode  {}", resp.mode);
        println!("major {}", resp.major);
        println!("minor {}", resp.minor);
        println!("patch {}", resp.patch);
        println!("locked {}", resp.locked);

        assert!(resp.major > 0);
        assert!(resp.minor >= 1000);
    }

    #[async_test]
    #[serial]
    async fn address() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let resp = app.get_address(&path, false).await.unwrap();

        assert_eq!(resp.public_key.len(), 32);
        assert_eq!(
            hex::encode(resp.public_key),
            "8f1a396a3181a45b84f82e505400cb752922d6f11a2897e71c6d939c2e91fcab"
        );
        assert_eq!(resp.ss58, "Fox9yUWUbBeGzKymMB2rKyYBHoJ3tfTNjhZC77xrQE2aHsr");

        println!("Public Key   {:?}", hex::encode(resp.public_key));
        println!("Address SS58 {:?}", resp.ss58);
    }

    #[async_test]
    #[serial]
    async fn show_address() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/0").unwrap();
        let resp = app.get_address(&path, true).await.unwrap();

        assert_eq!(resp.public_key.len(), 32);
        assert_eq!(
            hex::encode(resp.public_key),
            "9aacddd17054070103ad37ee76610d1adaa7f8e0d02b76fb91391eec8a2470af"
        );
        assert_eq!(resp.ss58, "G58F7QUjgT273AaNScoXhpKVjCcnDvCcbyucDZiPEDmVD9d");

        println!("Public Key   {:?}", hex::encode(resp.public_key));
        println!("Address SS58 {:?}", resp.ss58);
    }

    #[async_test]
    #[serial]
    async fn sign_empty() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let some_message0 = b"";

        let response = app.sign(&path, some_message0).await;
        assert!(response.is_err());
        assert!(matches!(
            response.err().unwrap(),
            ledger_substrate::LedgerError::InvalidEmptyMessage
        ));
    }

    #[async_test]
    #[serial]
    async fn sign_verify() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let txstr = "0400f68ad810c8070fdacded5e85661439ab61010c2da28b645797d45d22a2af837800d503008ed73e0dd807000001000000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
        let blob = hex::decode(txstr).unwrap();

        // First, get public key
        let addr = app.get_address(&path, false).await.unwrap();
        let public_key = PublicKey::from_bytes(&addr.public_key).unwrap();

        let response = app.sign(&path, &blob).await.unwrap();

        // we need to remove first byte (there is a new prepended byte, defining the signature type)
        let signature = Signature::from_bytes(&response[1..]).unwrap();

        if blob.len() > 256 {
            // When the blob is > 256, the digest is signed
            let message_hashed = Params::new()
                .hash_length(64)
                .to_state()
                .update(&blob)
                .finalize();

            assert!(public_key
                .verify((&message_hashed).as_ref(), &signature)
                .is_ok());
        } else {
            assert!(public_key.verify(&blob, &signature).is_ok());
        }
    }
}
