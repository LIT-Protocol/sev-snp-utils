use std::io::Read;

use crate::error;
use crate::error::Result as Result;

pub (crate) fn read_exact_to_bin_vec(rdr: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    let mut vec = vec![0;len];
    rdr.read_exact(&mut vec)
        .map_err(error::map_io_err)?;

    Ok(vec)
}

pub (crate) fn fmt_bin_vec_to_hex(vec: &Vec<u8>) -> String {
    vec
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

pub (crate) fn fmt_bin_vec_to_decimal(vec: &Vec<u8>) -> String {
    vec
        .iter()
        .map(|b| format!("{:0>2}", b))
        .collect::<String>()
}

pub (crate) fn bin_vec_reverse_bytes(vec: &Vec<u8>) -> Vec<u8> {
    let mut res = vec.clone();
    res.reverse();
    res
}