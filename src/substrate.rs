/*******************************************************************************
*   (c) 2020 Zondax GmbH
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
//! Support library for Kusama Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

use blake2b_simd::Params;
use ed25519_dalek::ExpandedSecretKey;
use ledger_transport::{APDUCommand, APDUErrorCodes, APDUTransport};
use ledger_zondax_generic::{
    map_apdu_error_description, AppInfo, ChunkPayloadType, DeviceInfo, LedgerAppError, Version,
};
use log::info;
use std::convert::TryInto;
use std::str;
use zx_bip44::BIP44Path;

const INS_GET_ADDR_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x02;

const INS_ALLOWLIST_GET_PUBKEY: u8 = 0x90;
const INS_ALLOWLIST_SET_PUBKEY: u8 = 0x91;
const INS_ALLOWLIST_GET_HASH: u8 = 0x92;
const INS_ALLOWLIST_UPLOAD: u8 = 0x93;

const PK_LEN: usize = 32;

/// Ledger App
pub struct SubstrateApp {
    pub(crate) apdu_transport: APDUTransport,
    pub(crate) cla: u8,
}

/// Ledger application mode
pub enum AppMode {
    /// Standard Mode - Normal App
    Standard = 0,
    /// Testing Mode - Only for testing purposes
    Testing = 1,
    /// Restricted Mode - Ledgeracio Variant
    Ledgeracio = 2,
}

type PublicKey = [u8; PK_LEN];

type AllowlistHash = [u8; 32];

pub struct Allowlist {
    pub blob: Vec<u8>,
    pub digest: [u8; 32],
}

/// Substrate address (includes pubkey and the corresponding ss58 address)
pub struct Address {
    /// Public Key
    pub public_key: PublicKey,
    /// Address (exposed as SS58)
    pub ss58: String,
}

type Signature = [u8; 65];

impl SubstrateApp {
    /// Connect to the Ledger App
    pub fn new(apdu_transport: APDUTransport, cla: u8) -> Self {
        SubstrateApp {
            apdu_transport,
            cla,
        }
    }

    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerAppError> {
        ledger_zondax_generic::get_version(self.cla, &self.apdu_transport).await
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerAppError> {
        ledger_zondax_generic::get_app_info(&self.apdu_transport).await
    }

    /// Retrieve the device info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerAppError> {
        ledger_zondax_generic::get_device_info(&self.apdu_transport).await
    }

    /// Retrieves the public key and address
    pub async fn get_address(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<Address, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla,
            ins: INS_GET_ADDR_ED25519,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        match self.apdu_transport.exchange(&command).await {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    info!("get_address: retcode={:X?}", response.retcode);
                    return Err(LedgerAppError::AppSpecific(
                        response.retcode,
                        map_apdu_error_description(response.retcode).to_string(),
                    ));
                }

                if response.data.len() < PK_LEN {
                    return Err(LedgerAppError::InvalidPK);
                }

                let mut address = Address {
                    public_key: [0; 32],
                    ss58: "".to_string(),
                };
                address.public_key.copy_from_slice(&response.data[..32]);
                address.ss58 = str::from_utf8(&response.data[32..])
                    .map_err(|_e| LedgerAppError::Utf8)?
                    .to_owned();

                Ok(address)
            }

            // FIXME: Improve
            Err(e) => Err(LedgerAppError::TransportError(e)),
        }
    }

    /// Sign a transaction. The returned `[u8; 65]` is a SCALE-encoded MultiSignature.
    pub async fn sign(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, LedgerAppError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla,
            ins: INS_SIGN_ED25519,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, message)
                .await?;

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 65 {
            return Err(LedgerAppError::InvalidSignature);
        }

        let mut sig: Signature = [0u8; 65];
        sig.copy_from_slice(&response.data[..65]);

        Ok(sig)
    }

    /// Retrieves the public key and address
    pub async fn allowlist_get_pubkey(&self) -> Result<PublicKey, LedgerAppError> {
        let command = APDUCommand {
            cla: self.cla,
            ins: INS_ALLOWLIST_GET_PUBKEY,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        match self.apdu_transport.exchange(&command).await {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    info!("allowlist_get_pubkey: retcode={:X?}", response.retcode);
                    return Err(LedgerAppError::AppSpecific(
                        response.retcode,
                        map_apdu_error_description(response.retcode).to_string(),
                    ));
                }

                if response.data.len() < PK_LEN {
                    return Err(LedgerAppError::InvalidPK);
                }

                let mut public_key = PublicKey::default();
                public_key.copy_from_slice(&response.data[..32]);

                Ok(public_key)
            }

            Err(e) => Err(LedgerAppError::TransportError(e)),
        }
    }

    /// Retrieves the public key and address
    pub async fn allowlist_set_pubkey(&self, pk: &PublicKey) -> Result<(), LedgerAppError> {
        let command = APDUCommand {
            cla: self.cla,
            ins: INS_ALLOWLIST_SET_PUBKEY,
            p1: 0x00,
            p2: 0x00,
            data: pk.to_vec(),
        };

        let answer = self.apdu_transport.exchange(&command).await;

        match answer {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    info!("allowlist_set_pubkey: retcode={:X?}", response.retcode);
                    return Err(LedgerAppError::AppSpecific(
                        response.retcode,
                        map_apdu_error_description(response.retcode).to_string(),
                    ));
                }

                Ok(())
            }

            Err(e) => Err(LedgerAppError::TransportError(e)),
        }
    }

    /// Generates a signed allow list based on
    /// https://github.com/Zondax/ledger-kusama/blob/master/docs/APDUSPEC.md#allow-list-structure
    pub fn generate_allowlist(
        nonce: u32,
        valid_addresses: Vec<&str>,
        esk: ExpandedSecretKey,
    ) -> Result<Allowlist, LedgerAppError> {
        // Prepare keys to sign
        let pk = ed25519_dalek::PublicKey::from(&esk);

        // The serialized allow list should look list:
        let nonce_bytes = nonce.to_le_bytes();

        let allowlist_len = valid_addresses.len();
        let allowlist_len_bytes = (allowlist_len as u32).to_le_bytes();

        let mut address_vec: Vec<u8> = vec![];
        address_vec.resize(64 * allowlist_len, 0);

        for i in 0..allowlist_len {
            let addr = valid_addresses[i];
            address_vec[i * 64..i * 64 + addr.len()].copy_from_slice(&addr.as_bytes());
        }

        let digest: [u8; 32] = Params::new()
            .hash_length(32)
            .to_state()
            .update(&nonce_bytes[..])
            .update(&allowlist_len_bytes[..])
            .update(&address_vec.as_slice())
            .finalize()
            .as_bytes()
            .try_into()
            .map_err(|_| LedgerAppError::Crypto)?;

        let signature = esk.sign(&digest, &pk);

        let allowlist_items = [
            &nonce_bytes,
            &allowlist_len_bytes,
            &signature.to_bytes()[..],
            &address_vec.as_slice(),
        ];

        let blob = allowlist_items.concat();

        Ok(Allowlist { blob, digest })
    }

    /// Retrieves the public key and address
    pub async fn allowlist_get_hash(&self) -> Result<AllowlistHash, LedgerAppError> {
        let command = APDUCommand {
            cla: self.cla,
            ins: INS_ALLOWLIST_GET_HASH,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        match self.apdu_transport.exchange(&command).await {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    info!("allowlist_get_hash: retcode={:X?}", response.retcode);
                    return Err(LedgerAppError::AppSpecific(
                        response.retcode,
                        map_apdu_error_description(response.retcode).to_string(),
                    ));
                }

                if response.data.len() < PK_LEN {
                    return Err(LedgerAppError::InvalidPK);
                }

                let mut hash = AllowlistHash::default();
                hash.copy_from_slice(&response.data[..32]);

                Ok(hash)
            }

            Err(e) => Err(LedgerAppError::TransportError(e)),
        }
    }

    /// Uploads an allow list to the device
    pub async fn allowlist_upload(&self, allowlist: &[u8]) -> Result<(), LedgerAppError> {
        let start_command = APDUCommand {
            cla: self.cla,
            ins: INS_ALLOWLIST_UPLOAD,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: vec![],
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, allowlist)
                .await?;

        if response.retcode != APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        Ok(())
    }
}
