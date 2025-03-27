use std::net::SocketAddr;
//use std::io::{self, Write};

use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use sha1::{Sha1, Digest};
use base64::{Engine, engine::general_purpose};

mod ws_key;
use ws_key::*;
mod c_fn;
use c_fn::*;

// 各クライアントに割り当てる tcp バッファ
const BYTES_READ_BUF_CLIENT: usize = 8 * 1024;

#[tokio::main]
async fn main() -> std::io::Result<()> {
	let listener = TcpListener::bind("0.0.0.0:80").await?;
	println!("Listening port -> 80");

//	TEST_WebSocket_Accept_Key();
	
	loop {
		// fn accept(&self) -> io::Result<(TcpStream, SocketAddr)>
		let (stream, addr) = listener.accept().await?;
		
		// マルチスレッドで実行する場合
	//	tokio::spawn(async move { process_client(stream, addr).await; });
		
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
	println!("accept addr -> {}", addr);
	
	let (reader, _writer) = stream.split();
	let mut buf_reader = BufReader::new(reader);
	let mut array_buf_read = [0u8; BYTES_READ_BUF_CLIENT];
	
	let bytes_read = {
		let mut slice_buf_read = &mut array_buf_read[..];
		buf_reader.read_buf(&mut slice_buf_read).await.unwrap()
	};

//#[cfg(any())]
{
	println!("--- DBG_show_http_req()");
	let _bytes_consumed = DBG_show_http_req(&array_buf_read[0..bytes_read]);
}
#[cfg(any())]
{
	println!("--- check_GET_req()");
	if check_GET_req(&array_buf_read[0..bytes_read])
		{ println!("   GET -> OK"); }
	else
		{ println!("!!! GET -> NG..."); }
}

	let mut wskey = WSKey::default();
	if let Err(err_msg) = wskey.get_accept_key(&array_buf_read) {
		println!("!!! failed to get Sec-Websocket-Key -> {err_msg}");
		return;  // この async リソースは破棄される
	}
	
	wskey.DBG_show_accept_key();
}

// -------------------------------------------------------------
#[allow(dead_code)]
#[allow(non_snake_case)]
fn check_GET_req(buf: &[u8]) -> bool {
	const U32_STR_GET: u32 = C_to_u32str("GET ");
	if buf.len() < 4 { return false; };
	
	unsafe {
		let ptr: *const u32 = buf.as_ptr() as *const u32;
		if ptr.read_unaligned() == U32_STR_GET
			{ true }
		else
			{ false }
	}
}

// -------------------------------------------------------------
// 戻り値: 処理した byte 数（\r\n を含む）
#[allow(dead_code)]
#[allow(non_snake_case)]
fn DBG_show_http_req(buf: &[u8]) -> usize
{
	let buf_len: usize = buf.len();
	let mut pos: usize = 0;
	
	loop {
		if buf_len == pos { return pos; }
		
		let (str, bytes_consumed) = DBG_get_http_req_line(&buf[pos..buf_len]);
		if str == None { return pos; }
		
		println!("{}", str.unwrap());
		pos += bytes_consumed + 2;
	}
}

// -------------------------------------------------------------
// 戻り値： usize -> \r\n を除く文字数
#[allow(non_snake_case)]
fn DBG_get_http_req_line(buf: &[u8]) -> (Option<String>, usize)
{
	unsafe {
		let len_buf: usize = buf.len() as usize;
		let ptr_head = buf.as_ptr();
		let mut ptr = ptr_head;
		let ptr_tmnt = ptr_head.add(len_buf);
		loop {
			if ptr == ptr_tmnt { return (None, 0); }
				
			if *ptr == 0x0d { break; }
			ptr = ptr.add(1);
		}
		
		let len_line: usize = ptr.offset_from(ptr_head) as usize;
		if len_line == 0 { return (Some(String::new()), 0); }

		let substr = buf[0..len_line.min(len_buf).try_into().unwrap()].to_vec();
		(Some(String::from_utf8_unchecked(substr)), len_line)
	}
}
