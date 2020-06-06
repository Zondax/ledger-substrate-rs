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
extern crate ledger_kusama;

#[cfg(test)]
mod integration_tests {
    use blake2b_simd::Params;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;
    use futures_await_test::async_test;
    use ledger_kusama::APDUTransport;
    use ledger_kusama::KusamaApp;
    use ledger_kusama::LedgerError;
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
        let app = KusamaApp::new(transport);

        let resp = app.get_version().await.unwrap();

        println!("mode  {}", resp.mode);
        println!("major {}", resp.major);
        println!("minor {}", resp.minor);
        println!("patch {}", resp.patch);

        assert_eq!(resp.major, 0x00);
        assert!(resp.minor >= 0x04);
    }

    #[async_test]
    #[serial]
    async fn address() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = KusamaApp::new(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let resp = app.get_address(&path, false).await.unwrap();

        assert_eq!(resp.public_key.len(), 32);
        assert_eq!(
            hex::encode(resp.public_key),
            "d280b24dface41f31006e5a2783971fc5a66c862dd7d08f97603d2902b75e47a"
        );
        assert_eq!(resp.ss58, "HLKocKgeGjpXkGJU6VACtTYJK4ApTCfcGRw51E5jWntcsXv");

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
        let app = KusamaApp::new(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let resp = app.get_address(&path, true).await.unwrap();

        assert_eq!(resp.public_key.len(), 32);
        assert_eq!(
            hex::encode(resp.public_key),
            "d280b24dface41f31006e5a2783971fc5a66c862dd7d08f97603d2902b75e47a"
        );
        assert_eq!(resp.ss58, "HLKocKgeGjpXkGJU6VACtTYJK4ApTCfcGRw51E5jWntcsXv");

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
        let app = KusamaApp::new(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let some_message0 = b"";

        let response = app.sign(&path, some_message0).await;
        assert!(response.is_err());
        assert!(matches!(
            response.err().unwrap(),
            LedgerError::InvalidEmptyMessage
        ));
    }

    #[async_test]
    #[serial]
    async fn sign_verify() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = KusamaApp::new(transport);

        let path = BIP44Path::from_string("m/44'/434'/0/0/5").unwrap();
        let txstr = "0000b30d1caed503000b63ce64c10c0526040000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
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
