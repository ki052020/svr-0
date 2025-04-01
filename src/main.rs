use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

mod ws;
use ws::*;
mod c_fn;
use c_fn::*;
mod dbg;
use dbg::*;

// -------------------------------------------------------------
#[cfg(test)]
mod test1 {
	#[derive(Debug)]
	struct S<'a> {
		ref_val: &'a mut i32,
	}
	
	impl<'a> S<'a> {
		fn new(ref_val: &'a mut i32) -> Self {
			S {
				ref_val,
			}
		}
	}
	
	#[allow(dead_code)]
	fn f<'a>(s: &'a mut S<'a>) {
		*s.ref_val += 1;
	}

	fn g1<'a>(s: &'a mut S) {
		*s.ref_val += 1;
	}

	fn g2<'a>(s: &mut S<'a>) {
		*s.ref_val += 1;
	}
	
	fn g3(s: &mut S) {
		*s.ref_val += 1;
	}

	fn g4<'a, 'b>(s: &'a mut S<'b>) {
		*s.ref_val += 1;
	}
	
	fn g5<'a, 'b>(s: &'a mut S<'b>) where 'b: 'a {
		*s.ref_val += 1;
	}

	#[allow(dead_code)]
	fn g6<'a, 'b>(s: &'a mut S<'b>) where 'a: 'b {
		*s.ref_val += 1;
	}

	#[test]
	fn test_1() {
		let mut val: i32 = 0;
		let mut s = S::new(&mut val);
		
//		f(&mut s);
		g1(&mut s);
		g2(&mut s);
		g3(&mut s);
		g4(&mut s);
		g5(&mut s);
//		g6(&mut s);
	
		println!("{s:?}");
	}
}

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
async fn TEST_read_async(ws_channel: &mut WsChannel<'_>) -> bool {
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

