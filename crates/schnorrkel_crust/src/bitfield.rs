use std::{convert::TryFrom, ops::BitOr};

use bitvec::{order::Lsb0, vec::BitVec};
use parity_scale_codec::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode, Hash, PartialEq, Eq)]
/// typedef for scale::BitVec
pub struct Bitfield<T>(BitVec<u8, bitvec::order::Lsb0>, std::marker::PhantomData<T>);

/// typedef for CoreBitfield
pub type CoreBitfield = Bitfield<u32>;

/// Index in CoreBitfield
pub struct BitIndex(pub usize);

/// Errors that can occur when creating and manipulating bitfields.
#[derive(Debug)]
pub enum BitfieldError {
    /// All bits are zero.
    NullAssignment,
}

/// Helper trait to convert primitives to `BitIndex`.
pub trait AsBitIndex {
    /// Returns the index of the corresponding bit in `Bitfield`.
    fn as_bit_index(&self) -> BitIndex;
}

impl AsBitIndex for u32 {
    fn as_bit_index(&self) -> BitIndex {
        BitIndex(*self as usize)
    }
}

impl AsBitIndex for usize {
    fn as_bit_index(&self) -> BitIndex {
        BitIndex(*self)
    }
}

impl<T> From<T> for Bitfield<T>
where
    T: AsBitIndex,
{
    fn from(value: T) -> Self {
        Self(
            {
                let mut bv = bitvec::bitvec![u8, Lsb0; 0; value.as_bit_index().0 + 1];
                bv.set(value.as_bit_index().0, true);
                bv
            },
            Default::default(),
        )
    }
}

impl<T> TryFrom<Vec<T>> for Bitfield<T>
where
    T: Into<Bitfield<T>>,
{
    type Error = BitfieldError;

    fn try_from(mut value: Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(BitfieldError::NullAssignment);
        }

        let initial_bitfield = value
            .pop()
            .expect("Just checked above it's not empty; qed")
            .into();

        Ok(Self(
            value
                .into_iter()
                .fold(initial_bitfield.0, |initial_bitfield, element| {
                    let mut bitfield: Bitfield<T> = element.into();
                    bitfield.0.resize(
                        std::cmp::max(initial_bitfield.len(), bitfield.0.len()),
                        false,
                    );
                    bitfield.0.bitor(initial_bitfield)
                }),
            Default::default(),
        ))
    }
}