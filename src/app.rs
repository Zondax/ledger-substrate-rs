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

use crate::{APDUCommand, APDUErrorCodes, APDUTransport, TransportError};
use serde::{Deserialize, Serialize};

use crate::params::*;
use zx_bip44::BIP44Path;

use crate::errors::LedgerError;
use std::str;

/// Ledger App
pub struct LedgerApp {
    apdu_transport: APDUTransport,
}

type PublicKey = [u8; 32];

/// Kusama address (includes pubkey and the corresponding ss58 address)
#[allow(dead_code)]
pub struct Address {
    /// Public Key
    pub public_key: PublicKey,
    /// Address (exposed as SS58)
    pub ss58: String,
}

type Signature = [u8; 65];

#[derive(Clone, Debug, Deserialize, Serialize)]
/// App Version
pub struct Version {
    /// Application Mode
    #[serde(rename(serialize = "testMode"))]
    pub mode: u8,
    /// Version Major
    pub major: u16,
    /// Version Minor
    pub minor: u16,
    /// Version Patch
    pub patch: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// App Information
pub struct AppInfo {
    /// Name of the application
    #[serde(rename(serialize = "appName"))]
    pub app_name: String,
    /// App version
    #[serde(rename(serialize = "appVersion"))]
    pub app_version: String,
    /// Flag length
    #[serde(rename(serialize = "flagLen"))]
    pub flag_len: u8,
    /// Flag value
    #[serde(rename(serialize = "flagsValue"))]
    pub flags_value: u8,
    /// Flag Recovery
    #[serde(rename(serialize = "flagsRecovery"))]
    pub flag_recovery: bool,
    /// Flag Signed MCU code
    #[serde(rename(serialize = "flagsSignedMCUCode"))]
    pub flag_signed_mcu_code: bool,
    /// Flag Onboarded
    #[serde(rename(serialize = "flagsOnboarded"))]
    pub flag_onboarded: bool,
    /// Flag Pin Validated
    #[serde(rename(serialize = "flagsPINValidated"))]
    pub flag_pin_validated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// App Device Info
pub struct DeviceInfo {
    /// Target ID
    #[serde(rename(serialize = "targetId"))]
    pub target_id: [u8; 4],
    /// Secure Element Version
    #[serde(rename(serialize = "seVersion"))]
    pub se_version: String,
    /// Device Flag
    pub flag: Vec<u8>,
    /// MCU Version
    #[serde(rename(serialize = "mcuVersion"))]
    pub mcu_version: String,
}

impl LedgerApp {
    /// Connect to the Ledger App
    pub fn new(apdu_transport: APDUTransport) -> Self {
        LedgerApp { apdu_transport }
    }

    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerError> {
        let command = APDUCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
        };

        let response = self.apdu_transport.exchange(command).await?;
        if response.retcode != APDUErrorCodes::NoError as u16 {
            return Err(LedgerError::InvalidVersion);
        }

        if response.data.len() < 7 {
            return Err(LedgerError::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1] as u16 * 256 + response.data[2] as u16,
            minor: response.data[3] as u16 * 256 + response.data[4] as u16,
            patch: response.data[5] as u16 * 256 + response.data[6] as u16,
        };

        Ok(version)
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerError> {
        let command = APDUCommand {
            cla: CLA_APP_INFO,
            ins: INS_APP_INFO,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
        };

        let response = self.apdu_transport.exchange(command).await?;
        if response.retcode != APDUErrorCodes::NoError as u16 {
            return Err(LedgerError::TransportError(
                TransportError::APDUExchangeError,
            ));
        }

        if response.data[0] != 1 {
            return Err(LedgerError::InvalidFormatID);
        }

        let app_name_len: usize = response.data[1] as usize;
        let app_name_bytes = &response.data[2..app_name_len];

        let mut idx = 2 + app_name_len;
        let app_version_len: usize = response.data[idx] as usize;
        idx += 1;
        let app_version_bytes = &response.data[idx..idx + app_version_len];

        idx += app_version_len;

        let app_flags_len = response.data[idx];
        idx += 1;
        let flags_value = response.data[idx];

        let app_name = str::from_utf8(app_name_bytes).map_err(|_e| LedgerError::Utf8)?;
        let app_version = str::from_utf8(app_version_bytes).map_err(|_e| LedgerError::Utf8)?;

        let app_info = AppInfo {
            app_name: app_name.to_string(),
            app_version: app_version.to_string(),
            flag_len: app_flags_len,
            flags_value,
            flag_recovery: (flags_value & 1) != 0,
            flag_signed_mcu_code: (flags_value & 2) != 0,
            flag_onboarded: (flags_value & 4) != 0,
            flag_pin_validated: (flags_value & 128) != 0,
        };

        Ok(app_info)
    }

    /// Retrieve the app info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerError> {
        let command = APDUCommand {
            cla: CLA_DEVICE_INFO,
            ins: INS_DEVICE_INFO,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
        };

        let response = self.apdu_transport.exchange(command).await?;
        if response.retcode != APDUErrorCodes::NoError as u16 {
            return Err(LedgerError::TransportError(
                TransportError::APDUExchangeError,
            ));
        }

        let target_id_slice = &response.data[0..4];
        let mut idx = 4;
        let se_version_len: usize = response.data[idx] as usize;
        idx += 1;
        let se_version_bytes = &response.data[idx..idx + se_version_len];

        idx += se_version_len;

        let flags_len: usize = response.data[idx] as usize;
        idx += 1;
        let flag = &response.data[idx..idx + flags_len];
        idx += flags_len;

        let mcu_version_len: usize = response.data[idx] as usize;
        idx += 1;
        let mut tmp = &response.data[idx..idx + mcu_version_len];
        if tmp[mcu_version_len - 1] == 0 {
            tmp = &response.data[idx..idx + mcu_version_len - 1];
        }

        let mut target_id = [Default::default(); 4];
        target_id.copy_from_slice(target_id_slice);

        let se_version = str::from_utf8(se_version_bytes).map_err(|_e| LedgerError::Utf8)?;
        let mcu_version = str::from_utf8(tmp).map_err(|_e| LedgerError::Utf8)?;

        let device_info = DeviceInfo {
            target_id,
            se_version: se_version.to_string(),
            flag: flag.to_vec(),
            mcu_version: mcu_version.to_string(),
        };

        Ok(device_info)
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
            cla: CLA,
            ins: INS_GET_ADDR_ED25519,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        match self.apdu_transport.exchange(command).await {
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
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        match chunks.len() {
            0 => return Err(LedgerError::InvalidEmptyMessage),
            n if n > 255 => return Err(LedgerError::InvalidMessageSize),
            _ => (),
        }

        let command = APDUCommand {
            cla: CLA,
            ins: INS_SIGN_ED25519,
            p1: PayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let mut response = self.apdu_transport.exchange(command).await?;

        // Send message chunks
        let last_chunk_index = chunks.len() - 1;
        for (packet_idx, chunk) in chunks.enumerate() {
            let mut p1 = PayloadType::Add as u8;
            if packet_idx == last_chunk_index {
                p1 = PayloadType::Last as u8
            }

            let command = APDUCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1,
                p2: 0,
                data: chunk.to_vec(),
            };

            response = self.apdu_transport.exchange(command).await?;
        }

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
