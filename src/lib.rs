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
//! Support library for Polkadot Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(
html_root_url = "https://docs.rs/ledger-polkadot/0.1.0"
)]

extern crate byteorder;
#[cfg(test)]
extern crate ed25519_dalek;
#[cfg(test)]
extern crate hex;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
extern crate ledger;
#[cfg(test)]
#[macro_use]
extern crate matches;
#[macro_use]
extern crate quick_error;
#[cfg(test)]
extern crate sha2;

use self::ledger::{ApduAnswer, ApduCommand};
use std::str;

const CLA: u8 = 0x99;
const INS_GET_VERSION: u8 = 0x00;
const INS_GET_ADDR_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x02;

const USER_MESSAGE_CHUNK_SIZE: usize = 250;

enum PayloadType {
    Init = 0x00,
    Add = 0x01,
    Last = 0x02
}

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
        /// The size fo the maessage to sign is invalid
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

/// Polkadot App
pub struct PolkadotApp {
    app: ledger::LedgerApp,
}

unsafe impl Send for PolkadotApp {}

type PublicKey = [u8; 32];
type Signature = [u8; 64];

/// Polkadot address (includes pubkey and the corresponding ss58 address)
#[allow(dead_code)]
pub struct Address {
    public_key: PublicKey,
    ss58: String,
}

/// Polkadot App Version
#[allow(dead_code)]
pub struct Version {
    mode: u8,
    major: u8,
    minor: u8,
    patch: u8,
}

fn serialize_bip44(account: u32, change: u32, address_index: u32) -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};
    let mut message = Vec::new();
    message.write_u32::<LittleEndian>(0x8000002c).unwrap();
    message.write_u32::<LittleEndian>(0x80000162).unwrap();
    message.write_u32::<LittleEndian>(0x80000000 | account).unwrap();
    message.write_u32::<LittleEndian>(0x80000000 | change).unwrap();
    message.write_u32::<LittleEndian>(0x80000000 | address_index).unwrap();
    message
}

impl PolkadotApp {
    /// Connect to the Ledger App
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(PolkadotApp { app })
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
        if response.retcode != 0x9000 {
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
    pub fn address(&self,
                   account: u32,
                   change: u32,
                   address_index: u32,
                   require_confirmation: bool) -> Result<Address, Error> {
        let bip44path = serialize_bip44(account, change, address_index);
        let mut p1: u8 = 0;
        if require_confirmation {
            p1 = 1;
        }

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

                let mut address = Address { public_key: [0; 32], ss58: "".to_string() };
                address.public_key.copy_from_slice(&response.data[..32]);
                address.ss58 = str::from_utf8(&response.data[32..]).unwrap().to_owned();
                Ok(address)
            }
            Err(err) => {
                return Err(Error::Ledger(err));
            }
        }
    }

    /// Sign a transaction
    pub fn sign(&self,
                account: u32,
                change: u32,
                address_index: u32,
                message: &[u8]) -> Result<Signature, Error> {
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
    use std::sync::Mutex;

    use crate::{Error, PolkadotApp};

    lazy_static! {
        static ref APP: Mutex<PolkadotApp> =
            Mutex::new(PolkadotApp::connect().unwrap());
    }

    #[test]
    fn version() {
        let app = APP.lock().unwrap();

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
    fn address() {
        let app = APP.lock().unwrap();
        let resp = app.address(0, 0, 5, false);

        match resp {
            Ok(addr) => {
                assert_eq!(addr.public_key.len(), 32);
                assert_eq!(hex::encode(addr.public_key),
                           "8d16d62802ca55326ec52bf76a8543b90e2aba5bcf6cd195c0d6fc1ef38fa1b3");
                assert_eq!(addr.ss58,
                           "FmK43tjzFGT9F68Sj9EvW6rwBQUAVuA9wNQaYxGLvfcCAxS");

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
    fn sign_empty() {
        let app = APP.lock().unwrap();

        let some_message0 = b"";

        let signature = app.sign(0, 0, 0, some_message0);
        assert!(signature.is_err());
        assert!(matches!(
            signature.err().unwrap(),
            Error::InvalidEmptyMessage
        ));
    }

    #[test]
    fn sign_verify() {
        let app = APP.lock().unwrap();

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
}

