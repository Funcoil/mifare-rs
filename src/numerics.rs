use ::std::marker::PhantomData;

/// Represents capacity of a tag
pub trait TagCapacity {
    fn bytes() -> u16;

    fn max_sectors() -> u8 {
        (Self::bytes() / 64) as u8
    }

    fn max_blocks() -> u8 {
        (Self::bytes() / 16) as u8
    }
}

/// Tag capacity of 1KiB.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cap1K;

impl TagCapacity for Cap1K {
    fn bytes() -> u16 {
        1024
    }
}

/// Tag capacity of 4KiB.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cap4K;

impl TagCapacity for Cap4K {
    fn bytes() -> u16 {
        4096
    }
}

/// Represents valid sector number within 1K Mifare tag.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct SectorNumber<Cap> (u8, PhantomData<Cap>);

impl<Cap: TagCapacity> SectorNumber<Cap> {
    /// Creates SectorNumber while checking for validity.
    pub fn new(sector_number: u8) -> Option<Self> {
        if sector_number < Cap::max_sectors() {
            Some(SectorNumber::raw(sector_number))
        } else {
            None
        }
    }

    // Shortcut internal method
    fn raw(val: u8) -> Self {
        SectorNumber(val, Default::default())
    }
}

impl<Cap: TagCapacity> From<SectorNumber<Cap>> for u8 {
    fn from(sector_number: SectorNumber<Cap>) -> Self {
        sector_number.0
    }
}

/// Abbreviation
pub type SectorNumber1K = SectorNumber<Cap1K>;

/// Abbreviation
pub type SectorNumber4K = SectorNumber<Cap4K>;

/// A tag with lower capacity can be safely treated as a tag with greater capacity.
impl From<SectorNumber1K> for SectorNumber4K {
    fn from(sector_number: SectorNumber1K) -> Self {
        SectorNumber::raw(sector_number.0)
    }
}

/// Offset within sector.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct BlockOffset (u8);

impl BlockOffset {
    /// Creates BlockOffset while checking for validity.
    pub fn new(block_offset: u8) -> Option<Self> {
        if block_offset < 3 {
            Some(BlockOffset(block_offset))
        } else {
            None
        }
    }
}

impl From<BlockOffset> for u8 {
    fn from(block_offset: BlockOffset) -> Self {
        block_offset.0
    }
}

/// Represents absolute Mifare tag address in blocks.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct AbsoluteBlockOffset<Cap> (u8, PhantomData<Cap>);

impl<Cap: TagCapacity> AbsoluteBlockOffset<Cap> {
    /// Creates AbsoluteBlockOffset while checking for validity.
    pub fn new(block_offset: u8) -> Option<Self> {
        if block_offset < Cap::max_blocks() {
            Some(AbsoluteBlockOffset::raw(block_offset))
        } else {
            None
        }
    }

    /// Returns the position of sector start.
    pub fn sector_offset(self) -> SectorBlockOffset<Cap> {
        SectorBlockOffset::raw(self.0 - self.0 % 4)
    }

    /// Returns offset from beginning of the sector.
    pub fn block_within_sector(self) -> BlockOffset {
        BlockOffset(self.0 % 4)
    }

    fn raw(val: u8) -> Self {
        AbsoluteBlockOffset(val, Default::default())
    }
}

impl<Cap: TagCapacity> From<AbsoluteBlockOffset<Cap>> for u8 {
    fn from(block_offset: AbsoluteBlockOffset<Cap>) -> Self {
        block_offset.0
    }
}

/// Represents sector as block offset.
///
/// Almost same as SectorNumber. The difference it that this one stores pre-calculated
/// offset to avoid re-calculating each time.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct SectorBlockOffset<Cap> (u8, PhantomData<Cap>);

impl<Cap: TagCapacity> SectorBlockOffset<Cap> {
    pub fn new(block_offset: u8) -> Option<Self> {
        if block_offset < Cap::max_blocks() && block_offset % 4 == 0 {
            Some(SectorBlockOffset::raw(block_offset))
        } else {
            None
        }
    }

    pub fn sector_trailer(self) -> AbsoluteBlockOffset<Cap> {
        AbsoluteBlockOffset::raw(self.0 + 3)
    }

    fn raw(val: u8) -> Self {
        SectorBlockOffset(val, Default::default())
    }
}

impl<Cap: TagCapacity> From<SectorBlockOffset<Cap>> for u8 {
    fn from(block_offset: SectorBlockOffset<Cap>) -> Self {
        block_offset.0
    }
}

impl<Cap: TagCapacity> From<SectorBlockOffset<Cap>> for SectorNumber<Cap> {
    fn from(block_offset: SectorBlockOffset<Cap>) -> Self {
        SectorNumber::raw(block_offset.0 / 4)
    }
}

impl<Cap: TagCapacity> ::std::ops::Add<BlockOffset> for SectorBlockOffset<Cap> {
    type Output = AbsoluteBlockOffset<Cap>;

    fn add(self, offset: BlockOffset) -> Self::Output {
        let lhs: u8 = self.into();
        let rhs: u8 = offset.into();
        AbsoluteBlockOffset::raw(lhs + rhs)
    }
}

impl<CapF, CapT> From<SectorNumber<CapF>> for SectorBlockOffset<CapT>
where CapF: TagCapacity,
      CapT: TagCapacity,
      SectorNumber<CapF>: Into<SectorNumber<CapT>> {

    fn from(sector_number: SectorNumber<CapF>) -> Self {
        sector_number.into().into()
    }
}
