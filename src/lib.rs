
#[cfg(feature = "with_pn532")]
extern crate pn532;
#[cfg(feature = "with_pn532")]
mod pn532_impl;

/// Represents NFC tag which could be Mifare tag.
pub trait NFCTag {
    /// Error type of transceive() method.
    type TransceiveError: ::std::error::Error;

    /// ID of tag. Must be 4 or 7 for valid Mifare tag.
    fn tag_id(&self) -> &[u8];

    /// This function will be used for communication with the tag.
    fn transceive(&mut self, data_to_tag: &[u8], data_from_tag: &mut [u8]) -> Result<usize, Self::TransceiveError>;
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
    pub fn authenticate_sector<'s>(&'s mut self, sector_number: u8, key: &[u8; 6]) -> Result<AuthenticatedSector<'s, T>, T::TransceiveError> {
        let (auth_cmd_buf, len) = {
            let tag_id = self.tag.tag_id();
            let mut auth_cmd_buf = [0x60, sector_number * 4, key[0], key[1], key[2], key[3], key[4], key[5], tag_id[0], tag_id[1], tag_id[2], tag_id[3], 0x00, 0x00, 0x00];
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

        Ok(AuthenticatedSector { tag: self, sector_number: sector_number })
    }
}

/// Reference to authenticated sector.
/// When sector is authenticated, you can perform reading and writing.
pub struct AuthenticatedSector<'a, T: 'a> {
    tag: &'a mut MifareTag<T>,
    sector_number: u8,
}

impl<'a, T: 'a + NFCTag> AuthenticatedSector<'a, T> {
    pub fn read_block(&mut self, pos: u8, buf: &mut [u8]) -> Result<(), T::TransceiveError> {
        if pos > 3 {
            panic!("Position can't be bigger than 3! (Was {}.)", pos);
        }

        let read_cmd = [0x30, self.sector_number * 4 + pos];
        try!(self.tag.tag.transceive(&read_cmd, buf));
        Ok(())
    }
}