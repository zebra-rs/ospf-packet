use std::net::Ipv4Addr;

use nom::error::ParseError;
use nom::number::complete::be_u32;
use nom::{Err, IResult, Needed};

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

// many0 which avoid passing empty input to the parser.
#[allow(dead_code)]
pub fn many0<'a, O, E: ParseError<&'a [u8]>>(
    parser: impl Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E> {
    move |input| {
        let mut res = Vec::new();
        let mut remaining = input;

        while !remaining.is_empty() {
            let (new_input, value) = parser(remaining)?;
            remaining = new_input;
            res.push(value);
        }

        Ok((remaining, res))
    }
}

// pub fn u8_3_u32(array: &[u8]) -> u32 {
//     if array.len() < 3 {
//         0
//     } else {
//         ((array[0] as u32) << 16) | ((array[1] as u32) << 8) | (array[2] as u32)
//     }
// }

// pub fn u32_u8_3(value: u32) -> [u8; 3] {
//     // Extract the three least significant bytes as big-endian
//     [
//         (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
//         (value >> 8) as u8,  // Middle byte
//         value as u8,         // Least significant byte
//     ]
// }
