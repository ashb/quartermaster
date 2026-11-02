use std::{ffi::OsString, io, path::Path};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LIMIT: usize = 64 * 1024;

pub(super) async fn run(args: &[OsString], socket: &Path) -> io::Result<u8> {
    let args: Vec<&str> = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .ok_or_else(|| io::Error::other("Restic arguments must be UTF-8"))
        })
        .collect::<io::Result<_>>()?;
    let request = serde_json::to_vec(&serde_json::json!({
        "arguments": args,
        "workingDirectory": std::env::current_dir()?,
    }))?;
    if request.len() > LIMIT {
        return Err(io::Error::other("Restic request is too large"));
    }
    let mut stream = tokio::net::UnixStream::connect(socket).await?;
    stream.write_u32(request.len() as u32).await?;
    stream.write_all(&request).await?;
    let mut signals = super::Signals::new()?;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    tokio::select! {
        result = relay(&mut stream, &mut stdout, &mut stderr) => result,
        signal = signals.next() => Ok(128 + signal as u8),
    }
}

async fn relay(
    reader: &mut (impl AsyncRead + Unpin),
    stdout: &mut (impl AsyncWrite + Unpin),
    stderr: &mut (impl AsyncWrite + Unpin),
) -> io::Result<u8> {
    loop {
        let kind = reader.read_u8().await?;
        let size = reader.read_u32().await? as usize;
        if size > LIMIT {
            return Err(io::Error::other("invalid Quartermaster output frame"));
        }
        let mut bytes = vec![0; size];
        reader.read_exact(&mut bytes).await?;
        match kind {
            1 => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            2 => {
                stderr.write_all(&bytes).await?;
                stderr.flush().await?;
            }
            3 if bytes.len() == 1 => return Ok(bytes[0]),
            4 => {
                return Err(io::Error::other(
                    String::from_utf8(bytes).map_err(io::Error::other)?,
                ));
            }
            _ => return Err(io::Error::other("invalid Quartermaster output frame")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, data: &[u8]) -> Vec<u8> {
        [
            vec![kind],
            (data.len() as u32).to_be_bytes().to_vec(),
            data.to_vec(),
        ]
        .concat()
    }

    #[tokio::test]
    async fn relays_each_output_stream_and_preserves_nonzero_status() {
        let data = [frame(1, b"snapshot"), frame(2, b"warning"), frame(3, &[7])].concat();
        let (mut stdout, mut stderr) = (vec![], vec![]);
        assert_eq!(
            relay(&mut data.as_slice(), &mut stdout, &mut stderr)
                .await
                .unwrap(),
            7
        );
        assert_eq!(stdout, b"snapshot");
        assert_eq!(stderr, b"warning");
    }

    #[tokio::test]
    async fn rejects_truncation_unknown_frames_oversize_and_missing_status() {
        for data in [
            vec![],
            frame(9, b""),
            frame(3, b""),
            vec![1, 0, 2, 0, 0],
            vec![1, 0, 0, 0, 1],
        ] {
            assert!(
                relay(&mut data.as_slice(), &mut vec![], &mut vec![])
                    .await
                    .is_err()
            );
        }
        let data = frame(4, b"Unlock the vault first");
        assert_eq!(
            relay(&mut data.as_slice(), &mut vec![], &mut vec![])
                .await
                .unwrap_err()
                .to_string(),
            "Unlock the vault first"
        );
    }
}
