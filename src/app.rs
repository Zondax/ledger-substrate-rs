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

use ledger_transport::{APDUCommand, APDUErrorCodes, APDUTransport};
use ledger_zondax_generic::{AppInfo, ChunkPayloadType, DeviceInfo, LedgerError, Version};
use std::str;
use zx_bip44::BIP44Path;

const CLA: u8 = 0x99;
const INS_GET_ADDR_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x02;

const PK_LEN: usize = 32;

/// Ledger App
pub struct KusamaApp {
    apdu_transport: APDUTransport,
}

type PublicKey = [u8; PK_LEN];

/// Kusama address (includes pubkey and the corresponding ss58 address)
#[allow(dead_code)]
pub struct Address {
    /// Public Key
    pub public_key: PublicKey,
    /// Address (exposed as SS58)
    pub ss58: String,
}

type Signature = [u8; 65];

impl KusamaApp {
    /// Connect to the Ledger App
    pub fn new(apdu_transport: APDUTransport) -> Self {
        KusamaApp { apdu_transport }
    }

    fn cla(&self) -> u8 {
        return CLA;
    }

    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerError> {
        ledger_zondax_generic::get_version(self.cla(), &self.apdu_transport).await
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerError> {
        ledger_zondax_generic::get_app_info(&self.apdu_transport).await
    }

    /// Retrieve the device info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerError> {
        ledger_zondax_generic::get_device_info(&self.apdu_transport).await
    }

    /// Retrieves the public key and address
    pub async fn get_address(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<Address, LedgerError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_ADDR_ED25519,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        match self.apdu_transport.exchange(&command).await {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() < PK_LEN {
                    return Err(LedgerError::InvalidPK);
                }

                let mut address = Address {
                    public_key: [0; 32],
                    ss58: "".to_string(),
                };
                address.public_key.copy_from_slice(&response.data[..32]);
                address.ss58 = str::from_utf8(&response.data[32..])
                    .map_err(|_e| LedgerError::Utf8)?
                    .to_owned();

                Ok(address)
            }

            // FIXME: Improve
            Err(e) => Err(LedgerError::TransportError(e)),
        }
    }

    /// Sign a transaction
    pub async fn sign(&self, path: &BIP44Path, message: &[u8]) -> Result<Signature, LedgerError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_SIGN_ED25519,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, message)
                .await?;

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 65 {
            return Err(LedgerError::InvalidSignature);
        }

        let mut sig: Signature = [0u8; 65];
        sig.copy_from_slice(&response.data[..65]);

        Ok(sig)
    }
}
