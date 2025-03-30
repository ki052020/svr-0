use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

use sha1::{Sha1, Digest};
use base64::{Engine, engine::general_purpose};

mod ws;
use ws::*;
mod c_fn;
use c_fn::*;
mod dbg;
use dbg::*;

#[cfg(test)]
mod tests {
	#[test]
	fn test_1() {
		let a = 10u8;
		println!("test -> {a:02x}");
	}
}

// -------------------------------------------------------------
#[tokio::main]
async fn main() -> std::io::Result<()> {
	let listener = TcpListener::bind("0.0.0.0:80").await?;
	println!("--- Listening port -> 80");

//	TEST_WebSocket_Accept_Key();
	
	loop {
		// fn accept(&self) -> io::Result<(TcpStream, SocketAddr)>
		let (stream, addr)
			= match listener.accept().await {
				Ok(x) => x,
				Err(err) => {
					println!("{err:?}");
					continue;
				}
			};
		
		// マルチスレッドで実行する場合
//		tokio::spawn(async move { process_client(stream, addr).await; });
		
		// 現在は、１回のみの accept を受け付けている
		process_client(stream, addr).await;
		
		break;
	}
	
	Ok(())
}

#[allow(dead_code)]
#[allow(non_snake_case)]
fn TEST_WebSocket_Accept_Key()
{
	println!("--- Test Websocket accept key");
	let test_key = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	println!("   test_key -> {test_key}");
	let mut hasher = Sha1::new();
	hasher.update(test_key.as_bytes());
	let result: [u8; 20] = hasher.finalize().into();
	
	let engine = general_purpose::STANDARD;
	let encoded_string = engine.encode(&result);
	println!("   accept key -> {encoded_string}");
}

// -------------------------------------------------------------
async fn process_client(mut stream: TcpStream, addr: SocketAddr) {
	println!("+++ accept addr -> {}", addr);
	
	let mut ws_channel
		= match WsChannel::new(&mut stream).await {
			Ok(ws_channel) => ws_channel,
			Err(str) => {
				println!("!!! process_client() -> {str}");
				return;
			}
		};
	
	let (buf_decoded, b_fin): (&[u8], bool)
		= match ws_channel.read_async().await {
			Ok(x) => x,
			Err(err_msg) => {
				println!("!!! failed to ws_handshake.connect() -> {err_msg}");
				return;
			}
		};

	let str_recvd = unsafe {
		String::from_utf8_unchecked(buf_decoded.to_vec())
	};

	println!("&&& str_recvd -> {str_recvd}");
	println!("&&& (buf_decoded.len(), b_fin) -> ({}, {b_fin})", buf_decoded.len());
}

