use std::cell::UnsafeCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

macro_rules! into_split_half {
    ($stream:expr) => {{
        let arc = Arc::new(UnsafeCell::new($stream));

        (Arc::clone(&arc), arc)
    }};
}

macro_rules! pipe_fromto {
    ($from:expr, $to:expr, $hook:expr) => {
        thread::spawn(move || {
            let mut buffer = [0; 65535];

            let (arc_from_read, _) = into_split_half!($from);
            let (_, arc_to_write) = into_split_half!($to);

            let arc_from_read = &mut *arc_from_read.get();
            let arc_to_write = &mut *arc_to_write.get();

            let socket = arc_to_write.try_clone().unwrap();

            loop {
                match arc_from_read.read(&mut buffer) {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }

                        let processed = ($hook)(&socket, &buffer[..n]);

                        if let Err(_) = arc_to_write.write_all(&processed) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    };
    ($from:expr, $to:expr) => {
        thread::spawn(move || {
            let mut buffer = [0; 65535];

            let (arc_from_read, _) = into_split_half!($from);
            let (_, arc_to_write) = into_split_half!($to);

            let arc_from_read = &mut *arc_from_read.get();
            let arc_to_write = &mut *arc_to_write.get();

            loop {
                match arc_from_read.read(&mut buffer) {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }

                        if let Err(_) = arc_to_write.write_all(&buffer[..n]) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    };
}

pub fn pipe_sockets(
    socket: TcpStream,
    stream: TcpStream,
    hook: impl Fn(&TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static,
) {
    socket.set_nodelay(true).unwrap();
    stream.set_nodelay(true).unwrap();

    let socket1 = socket.try_clone().unwrap();
    let stream1 = stream.try_clone().unwrap();

    unsafe {
        pipe_fromto!(socket1, stream1, hook);
        pipe_fromto!(stream, socket);
    }
}
