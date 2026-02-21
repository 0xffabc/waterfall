use std::time::Duration;

use tokio::net::TcpStream;

use tokio::io::AsyncWriteExt;

use anyhow::{anyhow, Result};

use crate::client_hook;
use crate::core::{blockmarker, parse_args};

pub async fn pipe_sockets(socket: TcpStream, stream: TcpStream) -> Result<()> {
    let mut socket_open = true;
    let mut stream_open = true;

    let config = parse_args();

    let socket: std::net::TcpStream = socket.into_std()?;
    let stream: std::net::TcpStream = stream.into_std()?;

    socket.set_nodelay(true)?;
    stream.set_nodelay(true)?;

    socket.set_nonblocking(true)?;
    stream.set_nonblocking(true)?;

    let mut socket = TcpStream::from_std(socket)?;
    let mut stream = TcpStream::from_std(stream)?;

    let mut buffer1: Vec<u8> = vec![0u8; config.socket_options.so_send_size];
    let mut buffer2: Vec<u8> = vec![0u8; config.socket_options.so_recv_size];

    let mut transferred = 0;
    let mut last_transmission = std::time::Instant::now();

    loop {
        if !socket_open || !stream_open {
            break;
        }

        if last_transmission.elapsed() > Duration::from_secs(3)
            && transferred < 33 * 1024
            && transferred > 1024
        {
            blockmarker::add_marker(stream.peer_addr()?).await;

            stream.shutdown().await?;
            socket.shutdown().await?;

            return Err(anyhow!("16-32kb block detected"));
        }

        tokio::select! {
            readable = socket.readable(), if socket_open => {
                readable?;

                match socket.try_read(&mut buffer1) {
                    Ok(0) => {
                        socket_open = false;

                        if stream_open {
                            stream.shutdown().await?;
                        }
                    }

                    Ok(n) => {
                        let data = &buffer1[..n];

                        let transformed = client_hook(&mut stream, data).await?;

                        stream.write_all(&transformed).await?;
                    }

                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { }

                    Err(e) => return Err(e.into())
                }
            }
            readable1 = stream.readable(), if stream_open => {
                readable1?;

                match stream.try_read(&mut buffer2) {
                    Ok(0) => {
                        stream_open = false;

                        if socket_open {
                            socket.shutdown().await?;
                        }
                    }

                    Ok(n) => {
                        let data = &buffer2[..n];

                        socket.write_all(data).await?;

                        transferred += n;

                        last_transmission = std::time::Instant::now();
                    }

                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { }

                    Err(e) => return Err(e.into())
                }
            }
        }
    }

    Ok(())
}
