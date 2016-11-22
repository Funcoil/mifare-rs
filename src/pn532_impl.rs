use ::pn532::tags::{Tag, ISO14443A, TagResponse};
use ::pn532::bus::{WaitRead, BusWrite};
use ::pn532::PN532;
use ::pn532::error::CommError;
use ::NFCTag;

impl<'r, 'p, D: WaitRead + BusWrite> NFCTag for Tag<'p, ISO14443A<'r>, PN532<D>> where CommError<D::ReadError, D::WriteError>: ::std::error::Error, for<'r2> ISO14443A<'r>: TagResponse<'r2> {
    type TransceiveError = CommError<D::ReadError, D::WriteError>;

    fn tag_id(&self) -> &[u8] {
        self.id()
    }

    fn transceive(&mut self, data_to_tag: &[u8], data_from_tag: &mut [u8]) -> Result<usize, Self::TransceiveError> {
        (self as &mut Tag<ISO14443A, PN532<D>>).transceive(data_to_tag, data_from_tag)
    }
}
