use crate::constants::{B64_DECODE_CHUNK, B64_ENCODE_CHUNK, READ_CHUNK, TEXT_CHUNK};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Streaming Base64-Writer: Nimmt beliebig große Datenströme entgegen und schreibt
/// sie in 48-KiB-Triplets als Base64 in den darunterliegenden Writer (O(1) RAM).
pub struct Base64EncoderWriter<'a, W: Write> {
    inner: &'a mut W,
    tail: [u8; 3],
    tail_len: usize,
}

impl<'a, W: Write> Base64EncoderWriter<'a, W> {
    pub fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            tail: [0u8; 3],
            tail_len: 0,
        }
    }

    pub fn finish(mut self) -> io::Result<()> {
        if self.tail_len > 0 {
            let encoded = BASE64.encode(&self.tail[..self.tail_len]);
            self.inner.write_all(encoded.as_bytes())?;
            self.tail_len = 0;
        }
        Ok(())
    }
}

impl<'a, W: Write> Write for Base64EncoderWriter<'a, W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let orig_len = buf.len();
        if orig_len == 0 {
            return Ok(0);
        }

        if self.tail_len > 0 {
            let need = 3 - self.tail_len;
            if buf.len() < need {
                self.tail[self.tail_len..self.tail_len + buf.len()].copy_from_slice(buf);
                self.tail_len += buf.len();
                return Ok(orig_len);
            }
            self.tail[self.tail_len..3].copy_from_slice(&buf[..need]);
            let encoded = BASE64.encode(&self.tail[..3]);
            self.inner.write_all(encoded.as_bytes())?;
            self.tail_len = 0;
            buf = &buf[need..];
        }

        while buf.len() >= 3 {
            let take = (buf.len().min(B64_ENCODE_CHUNK) / 3) * 3;
            let encoded = BASE64.encode(&buf[..take]);
            self.inner.write_all(encoded.as_bytes())?;
            buf = &buf[take..];
        }

        if !buf.is_empty() {
            self.tail[..buf.len()].copy_from_slice(buf);
            self.tail_len = buf.len();
        }

        Ok(orig_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streaming Base64-Reader: Dekodiert einen Base64-Slice blockweise in 64-KiB-Quanten,
/// ohne das gesamte Binär-Array im RAM allozieren zu müssen.
pub struct Base64SliceReader<'a> {
    src: &'a [u8],
    src_pos: usize,
    b64_buf: Vec<u8>,
    decoded_buf: Vec<u8>,
    decoded_pos: usize,
    done: bool,
}

impl<'a> Base64SliceReader<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            src_pos: 0,
            b64_buf: Vec::with_capacity(B64_DECODE_CHUNK),
            decoded_buf: Vec::new(),
            decoded_pos: 0,
            done: false,
        }
    }
}

impl<'a> Read for Base64SliceReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if self.decoded_pos < self.decoded_buf.len() {
                let avail = self.decoded_buf.len() - self.decoded_pos;
                let take = avail.min(out.len());
                out[..take].copy_from_slice(
                    &self.decoded_buf[self.decoded_pos..self.decoded_pos + take],
                );
                self.decoded_pos += take;
                return Ok(take);
            }

            if self.done {
                return Ok(0);
            }

            self.b64_buf.clear();
            while self.src_pos < self.src.len() && self.b64_buf.len() < B64_DECODE_CHUNK {
                let b = self.src[self.src_pos];
                self.src_pos += 1;
                if !b.is_ascii_whitespace() {
                    self.b64_buf.push(b);
                }
            }

            if self.b64_buf.is_empty() {
                self.done = true;
                return Ok(0);
            }

            self.decoded_buf = BASE64.decode(&self.b64_buf).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Base64-Fehler: {}", e),
                )
            })?;
            self.decoded_pos = 0;
        }
    }
}

/// Liest die Datei in 1-MiB-Blöcken für den SHA-256-Hash und prüft gleichzeitig über die
/// gesamte Dateilänge, ob es sich um valides, nullbyte-freies UTF-8 handelt.
pub fn analyze_file(full_path: &Path) -> io::Result<(String, u64, bool)> {
    let mut f = File::open(full_path)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut is_valid_text = true;
    let mut utf8_buf = vec![0u8; READ_CHUNK + 4];
    let mut leftover = 0usize;

    loop {
        let n = f.read(&mut utf8_buf[leftover..leftover + READ_CHUNK])?;
        if n == 0 {
            if leftover > 0 {
                is_valid_text = false;
            }
            break;
        }

        let new_bytes = &utf8_buf[leftover..leftover + n];
        hasher.update(new_bytes);
        size += n as u64;

        if is_valid_text {
            if new_bytes.contains(&0) {
                is_valid_text = false;
                leftover = 0;
            } else {
                let total = leftover + n;
                match std::str::from_utf8(&utf8_buf[..total]) {
                    Ok(_) => {
                        leftover = 0;
                    }
                    Err(e) => {
                        if e.error_len().is_none() {
                            let valid_up_to = e.valid_up_to();
                            leftover = total - valid_up_to;
                            utf8_buf.copy_within(valid_up_to..total, 0);
                        } else {
                            is_valid_text = false;
                            leftover = 0;
                        }
                    }
                }
            }
        }
    }

    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();

    Ok((digest, size, is_valid_text))
}

pub enum StreamTextError {
    Io(io::Error),
    InvalidUtf8,
}

pub fn stream_text_into_json<W: Write>(
    f_out: &mut W,
    full_path: &Path,
) -> Result<(String, u64), StreamTextError> {
    f_out.write_all(b"\"").map_err(StreamTextError::Io)?;
    let mut fs = File::open(full_path).map_err(StreamTextError::Io)?;
    let mut buf = vec![0u8; TEXT_CHUNK + 4];
    let mut leftover = 0usize;
    let mut hasher = Sha256::new();
    let mut total_read = 0u64;

    loop {
        let n = fs
        .read(&mut buf[leftover..leftover + TEXT_CHUNK])
        .map_err(StreamTextError::Io)?;
        if n > 0 {
            hasher.update(&buf[leftover..leftover + n]);
            total_read += n as u64;
        }
        let total = leftover + n;
        if total == 0 {
            break;
        }

        let valid_str = match std::str::from_utf8(&buf[..total]) {
            Ok(s) => {
                leftover = 0;
                s
            }
            Err(e) => {
                if e.error_len().is_none() && n > 0 {
                    let valid_up_to = e.valid_up_to();
                    leftover = total - valid_up_to;
                    let s = std::str::from_utf8(&buf[..valid_up_to]).unwrap();
                    let esc = serde_json::to_string(s).unwrap();
                    f_out
                    .write_all(&esc.as_bytes()[1..esc.len() - 1])
                    .map_err(StreamTextError::Io)?;
                    buf.copy_within(valid_up_to..total, 0);
                    continue;
                } else {
                    return Err(StreamTextError::InvalidUtf8);
                }
            }
        };

        let esc = serde_json::to_string(valid_str).unwrap();
        f_out
        .write_all(&esc.as_bytes()[1..esc.len() - 1])
        .map_err(StreamTextError::Io)?;
    }

    f_out.write_all(b"\"").map_err(StreamTextError::Io)?;
    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
    Ok((digest, total_read))
}

/// Echtes O(1)-RAM-Streaming für Binärdateien (sowohl mit Zstd als auch mit reinem Base64).
pub fn stream_binary_into_json<W: Write>(
    f_out: &mut W,
    full_path: &Path,
    compress_with_zstd: bool,
) -> io::Result<(String, u64)> {
    f_out.write_all(b"\"")?;
    let mut fs = File::open(full_path)?;
    let mut hasher = Sha256::new();
    let mut total_read = 0u64;
    let mut buf = vec![0u8; READ_CHUNK];

    if compress_with_zstd {
        let b64_writer = Base64EncoderWriter::new(f_out);
        let mut zstd_enc = zstd::Encoder::new(b64_writer, 3)?;
        loop {
            let n = fs.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_read += n as u64;
            zstd_enc.write_all(&buf[..n])?;
        }
        let b64_writer = zstd_enc.finish()?;
        b64_writer.finish()?;
    } else {
        let mut b64_writer = Base64EncoderWriter::new(f_out);
        loop {
            let n = fs.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_read += n as u64;
            b64_writer.write_all(&buf[..n])?;
        }
        b64_writer.finish()?;
    }

    f_out.write_all(b"\"")?;
    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
    Ok((digest, total_read))
}
