//! Classic libpcap file reader/writer (offline analysis and synthetic fixtures).
//! Reads both byte orders and micro/nanosecond timestamps. Truncated records
//! return an error instead of silently accepting a partial capture.

use std::io::{self, Read, Write};

#[derive(Debug, Clone)]
pub struct Record {
    pub ts_us: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub link_type: u32,
    pub snaplen: u32,
    pub big_endian: bool,
    pub nanos: bool,
}

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    BadMagic(u32),
}
impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "io: {e}"),
            PcapError::BadMagic(m) => write!(f, "not a pcap file (magic {m:#x})"),
        }
    }
}
impl std::error::Error for PcapError {}
impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

pub struct PcapReader<R: Read> {
    inner: R,
    pub header: Header,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut inner: R) -> Result<Self, PcapError> {
        let mut h = [0u8; 24];
        inner.read_exact(&mut h)?;
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let (big_endian, nanos) = match magic {
            0xa1b2c3d4 => (false, false),
            0xd4c3b2a1 => (true, false),
            0xa1b23c4d => (false, true),
            0x4d3cb2a1 => (true, true),
            m => return Err(PcapError::BadMagic(m)),
        };
        let rd = |o: usize| {
            let b = [h[o], h[o + 1], h[o + 2], h[o + 3]];
            if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        let header = Header { link_type: rd(20), snaplen: rd(16), big_endian, nanos };
        Ok(Self { inner, header })
    }

    /// Returns Ok(None) only at a clean record boundary.
    pub fn next_record(&mut self) -> Result<Option<Record>, PcapError> {
        let mut rh = [0u8; 16];
        if !read_full(&mut self.inner, &mut rh)? {
            return Ok(None);
        }
        let rd = |o: usize| {
            let b = [rh[o], rh[o + 1], rh[o + 2], rh[o + 3]];
            if self.header.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        let (secs, frac, incl) = (rd(0) as u64, rd(4) as u64, rd(8) as usize);
        // Refuse absurd record sizes to avoid unbounded allocation on hostile input.
        if incl > 262_144 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized PCAP record").into());
        }
        let mut data = vec![0u8; incl];
        self.inner.read_exact(&mut data)?;
        let ts_us = secs * 1_000_000 + if self.header.nanos { frac / 1000 } else { frac };
        Ok(Some(Record { ts_us, data }))
    }
}

/// Fills header entirely; Ok(false) only if EOF precedes its first byte.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, PcapError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial PCAP record header")),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Write a little-endian, microsecond pcap file.
pub fn write_pcap<W: Write>(mut w: W, link_type: u32, records: &[Record]) -> io::Result<()> {
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&65535u32.to_le_bytes())?;
    w.write_all(&link_type.to_le_bytes())?;
    for r in records {
        w.write_all(&((r.ts_us / 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&((r.ts_us % 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&(r.data.len() as u32).to_le_bytes())?;
        w.write_all(&(r.data.len() as u32).to_le_bytes())?;
        w.write_all(&r.data)?;
    }
    Ok(())
}
