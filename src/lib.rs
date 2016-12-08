#[cfg(feature = "with_pn532")]
extern crate pn532;
#[cfg(feature = "with_pn532")]
mod pn532_impl;

/// Typesafe numeric types related to Mifare tags.
pub mod numerics;

pub use numerics::{SectorNumber1K, SectorNumber4K, BlockOffset};

// Abbreviation
type SectorBlockOffset4K = numerics::SectorBlockOffset<numerics::Cap4K>;
type AbsoluteBlockOffset4K = numerics::AbsoluteBlockOffset<numerics::Cap4K>;

/// Represents NFC tag which could be Mifare tag.
pub trait NFCTag {
    /// Error type of transceive() method.
    type TransceiveError: ::std::error::Error;

    /// ID of tag. Must be 4 or 7 for valid Mifare tag.
    fn tag_id(&self) -> &[u8];

    /// This function will be used for communication with the tag.
    fn transceive(&mut self, data_to_tag: &[u8], data_from_tag: &mut [u8]) -> Result<usize, Self::TransceiveError>;
}

/// Type used for selecting authentication key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyOption {
    KeyA,
    KeyB,
}

/// Encapsulates Mifare tag.
pub struct MifareTag<T> {
    tag: T,
}

impl<T: NFCTag> MifareTag<T> {
    /// Checks whether tag_id has correct length and creates MifareTag.
    pub fn new(tag: T) -> Option<Self> {
        let id_len = tag.tag_id().len();
        if id_len == 4 || id_len == 7 {
            Some(MifareTag { tag: tag })
        } else {
            None
        }
    }

    /// Authenticates to sector using key.
    pub fn authenticate_sector<'s, SN: Into<SectorBlockOffset4K>>(&'s mut self, sector_number: SN, key_option: KeyOption, key: &[u8; 6]) -> Result<AuthenticatedSector<'s, T>, T::TransceiveError> {
        let sector_offset = sector_number.into();

        let cmd = match key_option {
            KeyOption::KeyA => 0x60,
            KeyOption::KeyB => 0x61,
        };

        let (auth_cmd_buf, len) = {
            let tag_id = self.tag.tag_id();
            let mut auth_cmd_buf = [cmd, sector_offset.into(), key[0], key[1], key[2], key[3], key[4], key[5], tag_id[0], tag_id[1], tag_id[2], tag_id[3], 0x00, 0x00, 0x00];
            if tag_id.len() == 7 {
                auth_cmd_buf[12] = tag_id[4];
                auth_cmd_buf[13] = tag_id[5];
                auth_cmd_buf[14] = tag_id[6];
            };
            (auth_cmd_buf, tag_id.len())
        };
        let auth_cmd = match len {
            4 => &auth_cmd_buf[0..12],
            7 => &auth_cmd_buf,
            _ => unreachable!(),
        };

        let mut resp = [0u8; 16];
        // Empty response on success
        try!(self.tag.transceive(auth_cmd, &mut resp));

        Ok(AuthenticatedSector { tag: self, sector_offset: sector_offset })
    }

    /// Returns id of underlying tag.
    pub fn tag_id(&self) -> &[u8] {
        self.tag.tag_id()
    }
}

/// Reference to authenticated sector.
/// When sector is authenticated, you can perform reading and writing.
pub struct AuthenticatedSector<'a, T: 'a> {
    tag: &'a mut MifareTag<T>,
    sector_offset: SectorBlockOffset4K,
}

impl<'a, T: 'a + NFCTag> AuthenticatedSector<'a, T> {
    /// Reads 16 bytes of data from given block
    ///
    /// Warning: This interface is temporary and will change!
    pub fn read_block(&mut self, offset: BlockOffset, buf: &mut [u8]) -> Result<(), T::TransceiveError> {
        let read_cmd = [0x30, (self.sector_offset + offset).into()];
        try!(self.tag.tag.transceive(&read_cmd, buf));
        Ok(())
    }

    fn write_block_raw(&mut self, offset: AbsoluteBlockOffset4K, data: &[u8; 16]) -> Result<(), T::TransceiveError> {
        let mut write_cmd = [0; 18];
        write_cmd[0] = 0xA0;
        write_cmd[1] = offset.into();
        write_cmd[2..].copy_from_slice(&*data);

        let mut resp = [0; 16];
        try!(self.tag.tag.transceive(&write_cmd, &mut resp));
        Ok(())
    }

    /// Writes 16 bytes of data to given block
    ///
    /// WARNING: NOT tested!!! Use at your own risk! By writing incorrect values, you may
    /// permanently damage the tag!
    /// This interface is temporary and will change!
    pub fn write_block(&mut self, offset: BlockOffset, data: &[u8; 16]) -> Result<(), T::TransceiveError> {
        let offset = self.sector_offset + offset;
        self.write_block_raw(offset, data)
    }

    /// Writes keys as well as access bits
    ///
    /// WARNING: NOT tested!!! Use at your own risk! By writing incorrect values, you may
    /// permanently damage the tag!
    /// This interface is temporary and will change!
    pub fn write_keys(&mut self, data: &[u8; 16]) -> Result<(), T::TransceiveError> {
        let offset = self.sector_offset.sector_trailer();
        self.write_block_raw(offset, data)
    }
}
