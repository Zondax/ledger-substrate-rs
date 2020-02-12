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
#![doc(html_root_url = "https://docs.rs/ledger-kusama")]

mod params;

extern crate byteorder;
extern crate ledger;
#[macro_use]
extern crate quick_error;
#[cfg(test)]
extern crate hex;

use self::ledger::{ApduAnswer, ApduCommand};
use crate::params::{
    APDUErrors, PayloadType, CLA, INS_GET_ADDR_ED25519, INS_GET_VERSION, INS_SIGN_ED25519,
    USER_MESSAGE_CHUNK_SIZE,
};
use std::str;

quick_error! {
    /// Ledger App Error
    #[derive(Debug)]
    pub enum Error {
        /// Invalid version error
        InvalidVersion{
            description("This version is not supported")
        }
        /// The message cannot be empty
        InvalidEmptyMessage{
            description("message cannot be empty")
        }
        /// The size of the message to sign is invalid
        InvalidMessageSize{
            description("message size is invalid (too big)")
        }
        /// Public Key is invalid
        InvalidPK{
            description("received an invalid PK")
        }
        /// No signature has been returned
        NoSignature {
            description("received no signature back")
        }
        /// The signature is not valid
        InvalidSignature {
            description("received an invalid signature")
        }
        /// The derivation is invalid
        InvalidDerivationPath {
            description("invalid derivation path")
        }
        /// Device related errors
        Ledger ( err: ledger::Error ) {
            from()
            description("ledger error")
            display("Ledger error: {}", err)
            cause(err)
        }
    }
}

/// Kusama App
pub struct KusamaApp {
    app: ledger::LedgerApp,
}

unsafe impl Send for KusamaApp {}

type PublicKey = [u8; 32];
type Signature = [u8; 64];

/// Kusama address (includes pubkey and the corresponding ss58 address)
#[allow(dead_code)]
pub struct Address {
    /// Public Key
    pub public_key: PublicKey,
    /// Address (exposed as SS58)
    pub ss58: String,
}

/// App Version
#[allow(dead_code)]
pub struct Version {
    /// Application Mode
    pub mode: u8,
    /// Version Major
    pub major: u8,
    /// Version Minor
    pub minor: u8,
    /// Version Patch
    pub patch: u8,
}

fn serialize_bip44(account: u32, change: u32, address_index: u32) -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};
    let mut m = Vec::new();
    let harden = 0x8000_0000;
    m.write_u32::<LittleEndian>(harden | 0x2c).unwrap();
    m.write_u32::<LittleEndian>(harden | 0x162).unwrap();
    m.write_u32::<LittleEndian>(harden | account).unwrap();
    m.write_u32::<LittleEndian>(harden | change).unwrap();
    m.write_u32::<LittleEndian>(harden | address_index).unwrap();
    m
}

impl KusamaApp {
    /// Connect to the Ledger App
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(KusamaApp { app })
    }

    /// Retrieve the app version
    pub fn version(&self) -> Result<Version, Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;
        if response.retcode != APDUErrors::NoError as u16 {
            return Err(Error::InvalidVersion);
        }

        if response.data.len() < 4 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Ok(version)
    }

    /// Retrieves the public key and address
    pub fn address(
        &self,
        account: u32,
        change: u32,
        address_index: u32,
        require_confirmation: bool,
    ) -> Result<Address, Error> {
        let bip44path = serialize_bip44(account, change, address_index);
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_ADDR_ED25519,
            p1,
            p2: 0x00,
            length: 0,
            data: bip44path,
        };

        match self.app.exchange(command) {
            Ok(response) => {
                if response.retcode != 0x9000 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() < 32 {
                    return Err(Error::InvalidPK);
                }

                let mut address = Address {
                    public_key: [0; 32],
                    ss58: "".to_string(),
                };
                address.public_key.copy_from_slice(&response.data[..32]);
                address.ss58 = str::from_utf8(&response.data[32..]).unwrap().to_owned();
                Ok(address)
            }
            Err(err) => Err(Error::Ledger(err)),
        }
    }

    /// Sign a transaction
    pub fn sign(
        &self,
        account: u32,
        change: u32,
        address_index: u32,
        message: &[u8],
    ) -> Result<Signature, Error> {
        let bip44path = serialize_bip44(account, change, address_index);
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;
        let mut response: ApduAnswer;

        let _command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_ED25519,
            p1: PayloadType::Init as u8,
            p2: 0x00,
            length: bip44path.len() as u8,
            data: bip44path,
        };

        response = self.app.exchange(_command)?;

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let mut p1 = PayloadType::Add as u8;
            if packet_idx == (packet_count - 1) as usize {
                p1 = PayloadType::Last as u8
            }

            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1,
                p2: 0,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.is_empty() && response.retcode == 0x9000 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(&response.data[..64]);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize_bip44;

    #[test]
    fn bip44() {
        let path = serialize_bip44(0x1234, 0, 0x5678);
        assert_eq!(path.len(), 20);
        assert_eq!(
            hex::encode(path),
            "2c00008062010080341200800000008078560080"
        );
    }
}
