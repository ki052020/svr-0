use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

mod ws;
use ws::*;
mod c_fn;
use c_fn::*;
mod dbg;
use dbg::*;

// -------------------------------------------------------------
#[tokio::main]
async fn main() -> std::io::Result<()> {
	let listener = TcpListener::bind("0.0.0.0:80").await?;
	println!("--- Listening port -> 80");
	
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

// -------------------------------------------------------------
async fn process_client(mut stream: TcpStream, addr: SocketAddr) {
	println!("+++ accept addr -> {}", addr);

	let mut ws_channel
		= match WsChannel::new(&mut stream).await {
			Ok(ws_channel) => ws_channel,
			Err(str) => {
				println!("!!! failed to WsChannel::new() -> {str}");
				return;
			}
		};
	
	if TEST_read_async(&mut ws_channel).await == false { return; }
	match ws_channel.send_text("えお").await {
		Ok(()) => {},
		Err(string) => {
			println!("!!! failed to WsChannel::TEST_read_async() -> {}", &string);
			return;
		}
	}
	
	if TEST_read_async(&mut ws_channel).await == false { return; }
	match ws_channel.send_text("さしすせそ").await {
		Ok(()) => {},
		Err(string) => {
			println!("!!! failed to WsChannel::TEST_read_async() -> {}", &string);
			return;
		}
	}
}

// -------------------------------------------------------------
#[allow(non_snake_case)]
async fn TEST_read_async<'a>(ws_channel: &mut WsChannel<'a>) -> bool {
	let (buf_decoded, b_close)
		= match ws_channel.read_async().await {
			Ok(x) => x,
			Err(err_msg) => {
				println!("!!! failed to ws_channel.read_async() -> {err_msg}");
				return false;
			}
		};
		
	let str_recvd = unsafe {
		String::from_utf8_unchecked(buf_decoded.to_vec())
	};

	println!("&&& str_recvd -> {str_recvd}");
	println!("    (buf_decoded.len(), b_close) -> ({}, {b_close})", buf_decoded.len());
	true
}

