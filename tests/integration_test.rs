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
// #![deny(warnings, trivial_casts, trivial_numeric_casts)]
// #![deny(unused_import_braces, unused_qualifications)]
// #![deny(missing_docs)]

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
    use crate::ed25519_dalek::ed25519::signature::Signature;
    use crate::ed25519_dalek::Verifier;
    use blake2b_simd::Params;
    use ed25519_dalek::PublicKey;
    use env_logger::Env;
    use futures_await_test::async_test;
    use ledger_substrate::{new_kusama_app, APDUTransport, AppMode, SubstrateApp};
    use std::convert::TryInto;
    use zx_bip44::BIP44Path;

    fn init_logging() {
        let _ = env_logger::from_env(Env::default().default_filter_or("info"))
            .is_test(true)
            .try_init();
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

        let path = BIP44Path::from_string("m/44'/434'/0'/0'/5'").unwrap();
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
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0'/0'/5'").unwrap();
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
        let app = new_kusama_app(transport);

        let path = BIP44Path::from_string("m/44'/434'/0'/0'/5'").unwrap();
        let some_message0 = b"";

        let response = app.sign(&path, some_message0).await;
        assert!(response.is_err());
        assert!(matches!(
            response.err().unwrap(),
            ledger_substrate::LedgerAppError::InvalidEmptyMessage
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

        let app_version = app.get_version().await.unwrap();
        log::info!("Version: {:?}", app_version);
        if app_version.mode == AppMode::Ledgeracio as u8 {
            log::info!("This is a ledgeracio variant. Skip");
            // Bail out and pass the test
            return;
        }

        let path = BIP44Path::from_string("m/44'/434'/0'/0'/5'").unwrap();
        let txstr = "04009ae55222192347c60793232dd229197a5e6ad158b2b4fea7900458d1273ba4c933158139ae28a3dfaac5fe1560a5e9e05cd50391016d0fe607000002000000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
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

    static SOME_PK: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    static SOME_SK: &str = "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1560a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3";

    #[async_test]
    #[serial]
    async fn allowlist_create() {
        init_logging();

        // Now upload the allowlist
        let addresses = vec![
            "FQr6vFmm8zNFV9m4ZMxKzMdUVUbPtrhxxaVkAybHxsDYMCY",
            "HXAjzUP15goNbAkujFgnNcioHhUGMDMSRdfbSxi11GsCBV6",
        ];

        let sk = hex::decode(SOME_SK).unwrap();
        let esk = ed25519_dalek::ExpandedSecretKey::from_bytes(&sk).unwrap();
        let allowlist = SubstrateApp::generate_allowlist(0, addresses, esk).unwrap();

        assert_eq!(
            hex::encode(allowlist.digest),
            "42cd31e70afa9fc4cd0e72e0cfebf30f6294e048e9eb0b84d98c0afbcd40f804"
        );
    }

    #[async_test]
    #[serial]
    async fn allowlist_upload() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: ledger::TransportNativeHID::new().unwrap(),
        };
        let app = new_kusama_app(transport);

        let app_version = app.get_version().await.unwrap();
        log::info!("Version: {:?}", app_version);
        if app_version.mode != AppMode::Ledgeracio as u8 {
            log::info!("This is not a ledgeracio variant");
            // Bail out and pass the test
            return;
        }

        // We try to set the pubkey, it is possible that it was been set already, we ignore the error here:
        let some_pk: [u8; 32] = hex::decode(SOME_PK).unwrap().as_slice().try_into().unwrap();
        let _ = app.allowlist_set_pubkey(&some_pk).await;

        // Let's get the pubkey back to be sure it is fine
        let resp_get = app.allowlist_get_pubkey().await.unwrap();
        assert_eq!(resp_get.len(), 32);
        assert_eq!(hex::encode(resp_get), SOME_PK);

        // Now upload the allowlist
        let addresses = vec![
            "HRbm5tb7R2oz7WRNpNKUSz9gqDR1GZ6q6psh7TdXUwQLcpj",
            "Dn3g4pKTHbiRuxzr1S8N5swxz6hqUBFYfKXbWNcvWTW5YSP",
        ];
        let sk = hex::decode(SOME_SK).unwrap();
        let esk = ed25519_dalek::ExpandedSecretKey::from_bytes(&sk).unwrap();
        let allowlist = SubstrateApp::generate_allowlist(1, addresses, esk).unwrap();

        let _ = app.allowlist_upload(&allowlist.blob[..]).await.unwrap();

        let allowlist_digest = app.allowlist_get_hash().await.unwrap();
        assert_eq!(hex::encode(allowlist_digest), hex::encode(allowlist.digest));

        let path = BIP44Path::from_string("m/44'/434'/0'/0'/5'").unwrap();

        // Try a couple of stake nominations

        // THIS SHOULD BE ACCEPTED
        // "0 | Staking : Nominate",
        // "1 | Targets [1/4] : HRbm5tb7R2oz7WRNpNKUSz9gqDR1GZ6q6psh7Td",
        // "1 | Targets [2/4] : XUwQLcpj",
        // "1 | Targets [3/4] : Dn3g4pKTHbiRuxzr1S8N5swxz6hqUBFYfKXbWNc",
        // "1 | Targets [4/4] : vWTW5YSP",
        let nominate_tx = "060508d686a3466003504d58806608def3d98266bb2cad9a2ecfea32d342e9d4fdd2ae352dd837860c4194fee64ea26d07304ee16b14f6caf28a6852b2c50b3f66242fd5038d246d0fe607000002000000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
        let blob = hex::decode(nominate_tx).unwrap();

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

        // THIS SHOULD NOT BE ACCEPTED
        // "0 | Staking : Nominate",
        // "1 | Targets [1/2] : HFfvSuhgKycuYVk5YnxdDTmpDnjWsnT76nks8fr",
        // "1 | Targets [2/2] : yfSLaD96",
        let nominate_tx2 = "060504cef4313d2d72d949a1b35cd6ffd68bd6fcf5524dd0923fb94d23eaf69a01e888d503006d0fdc07000001000000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe";
        let blob2 = hex::decode(nominate_tx2).unwrap();

        // First, get public key
        let response2 = app.sign(&path, &blob2).await;
        assert!(response2.is_err());

        let err = response2.err().unwrap();
        log::info!("{:?}", err)
    }
}
