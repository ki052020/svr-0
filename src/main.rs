use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use std::io;

// 各クライアントに割り当てる tcp バッファ
const BYTES_READ_BUF_CLIENT: usize = 16 * 1024;

#[tokio::main]
async fn main() -> io::Result<()> {
	let listener = TcpListener::bind("0.0.0.0:80").await?;
	println!("Listening port -> 80");

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

// -------------------------------------------------------------
async fn process_client(mut stream: TcpStream, addr: SocketAddr) {
	println!("accept addr -> {}", addr);
	
	let (reader, _writer) = stream.split();
	let mut buf_reader = BufReader::new(reader);
	let mut array_buf_read = [0u8; BYTES_READ_BUF_CLIENT];
	
	
	println!("--- text recieved:");
	let bytes_read = {
		let mut slice_buf_read = &mut array_buf_read[..];
		buf_reader.read_buf(&mut slice_buf_read).await.unwrap()
	};
	println!("bytes_read -> {bytes_read}");
	
	println!("--- _dbg_show_http_req()");
	let bytes_consumed = _dbg_show_http_req(&array_buf_read[0..bytes_read]);
	
	if bytes_read == bytes_consumed {
		println!("--- gotten complete req");
	} else {
		println!("--- ?? NOT gotten complete req");
	}
}

// -------------------------------------------------------------
fn _dbg_show_http_req(buf: &[u8]) -> usize
{
	let buf_len: usize = buf.len();
	let mut pos: usize = 0;
	
	loop {
		if buf_len == pos { return pos; }
		
		let (str, bytes_consumed) = _dbg_get_http_req_line(&buf[pos..buf_len]);
		if str == None { return pos; }
		
		println!("{}", str.unwrap());
		pos += bytes_consumed + 2;
	}
}

// -------------------------------------------------------------
// 戻り値： usize -> \r\n を除く文字数
fn _dbg_get_http_req_line(buf: &[u8]) -> (Option<String>, usize)
{
	unsafe {
		let len_buf: usize = buf.len().try_into().unwrap();
		let ptr_head = buf.as_ptr();
		let mut ptr = ptr_head;
		let ptr_tmnt = ptr_head.add(len_buf);
		loop {
			if ptr == ptr_tmnt { return (None, 0); }
				
			if *ptr == 0x0d { break; }
			ptr = ptr.add(1);
		}
		
		let len_line: usize = ptr.offset_from(ptr_head).try_into().unwrap();
		if len_line == 0 { return (Some(String::new()), 0); }

		let substr = buf[0..len_line.min(len_buf).try_into().unwrap()].to_vec();
		(Some(String::from_utf8_unchecked(substr)), len_line)
	}
}
