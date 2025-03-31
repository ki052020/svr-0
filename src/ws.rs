use super::{C_to_u32str, C_to_u64str, DBG_show_http_req};
use sha1::{Sha1, Digest};
use base64::{Engine, engine::general_purpose};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};

////////////////////////////////////////////////////////////////
// 各クライアントに割り当てる tcp バッファ
const BYTES_READ_BUF_CLIENT: usize = 8 * 1024;
const BYTES_WRITE_BUF_CLIENT: usize = 8 * 1024;


////////////////////////////////////////////////////////////////
// WsKey
struct WsKey {
	accept_key: [u8; 28],
}

impl WsKey {
	fn new(buf: &[u8]) -> Result<Self, &'static str> {
		let len_buf: usize = buf.len() as usize;
		if len_buf < 8 { return Err("!!! buf.len() < 8"); }
		
		unsafe {
			let ptr = buf.as_ptr();
			let ptr_tmnt = ptr.add(len_buf);
			
			let mut ptr = match Self::srch_Sec_WebSocket_Key(ptr, ptr_tmnt) {
				Some(x) => x,
				None => { return Err("!!! not found -> Sec_WebSocket_Key"); }
			};

			// Sec-WebSocket-Key: の読み取り
			loop {
				if *ptr != 0x20 { break; }
				ptr = ptr.add(1);
				if ptr == ptr_tmnt { return Err("!!! not found -> Sec_WebSocket_Key"); }
			}
			
			let mut ary_key = [0u8; 60];
			{
				let dst = ary_key.as_mut_ptr() as *mut u64;
				let src = ptr as *mut u64;
				for i in 0..3 {
					dst.add(i).write_unaligned(src.add(i).read_unaligned());
				}
				
				dst.add(3).write_unaligned(C_to_u64str("258EAFA5"));
				dst.add(4).write_unaligned(C_to_u64str("-E914-47"));
				dst.add(5).write_unaligned(C_to_u64str("DA-95CA-"));
				dst.add(6).write_unaligned(C_to_u64str("C5AB0DC8"));
				
				let dst = dst.add(7) as *mut u32;
				dst.write_unaligned(C_to_u32str("5B11"));
			}
			
			let mut hasher = Sha1::new();
			hasher.update(ary_key);
			
			// 20 bytes のコピーが発生するが、これはなくせるはず？？
			let sha1_result: [u8; 20] = hasher.finalize().into();
			
			let mut accept_key = [0u8; 28];		
			let engine: general_purpose::GeneralPurpose = general_purpose::STANDARD;
			match engine.internal_encode(&sha1_result, &mut accept_key) {
				27 => accept_key[27] = b'=',
				x => panic!("x -> {x}"),
			}
			Ok(WsKey { accept_key })
		}
	}
	
	// -------------------------------------------------------------
	#[allow(non_snake_case)]
	fn srch_Sec_WebSocket_Key(ptr_head: *const u8, ptr_tmnt: *const u8) -> Option<*const u8> {
		const SEC_WEBS: u64 = C_to_u64str("Sec-WebS");
		const KET_KEY: u64 = C_to_u64str("ket-Key:");
		
		unsafe {
			let mut ptr = ptr_head;
			
			loop {
				// "Sec-WebS" を検出する
				loop {
					if (ptr.add(8)) >= ptr_tmnt { return None; }
					if (ptr as *const u64).read_unaligned() == SEC_WEBS { break; }
					
					ptr = ptr.add(8);  // key 部分の文字列は読み飛ばす
					loop {
						if *ptr == 0x0a { break; }
						ptr = ptr.add(1);
						if ptr == ptr_tmnt { return None; }
					}
					ptr = ptr.add(1);
				}
				
				// "ket-Key:" を検出する
				// Sec-WebS oc ket-Key:
				if (ptr.add(18)) >= ptr_tmnt { return None; }
				ptr = ptr.add(10);
				if (ptr as *const u64).read_unaligned() == KET_KEY
					{ return Some(ptr.add(8)); }
				
				// ここに来た場合、Sec-WebSocket-Extensions: であったと考えられる
				// ２５文字読み飛ばしても良いが、未知の Key があった場合も考えて読み飛ばしはしない
				loop {
					if *ptr == 0x0a { break; }
					ptr = ptr.add(1);
					if ptr == ptr_tmnt { return None; }
				}
				ptr = ptr.add(1);
			}
		}
	}

	// -------------------------------------------------------------
	#[allow(dead_code)]
	#[allow(non_snake_case)]
	fn DBG_show_accept_key(&self) {
		let dbg_str = String::from_utf8(self.accept_key.to_vec()).unwrap();
		println!("&&& accept key -> {dbg_str}");
	}
}


////////////////////////////////////////////////////////////////
// WsHandshake
const RESP_STR: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
const NUM_RESP_STR: usize = RESP_STR.len();

/*
const _RESP_STR: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
*/

struct WsHandshake {	
	resp: [u8; NUM_RESP_STR + 32],
}

impl WsHandshake {
	fn new(ws_key: WsKey) -> Self {
		let mut resp = [0u8; NUM_RESP_STR + 32];
		unsafe {
			let ptr = resp.as_mut_ptr();

			std::intrinsics::copy_nonoverlapping(
				RESP_STR.as_ptr(), ptr, NUM_RESP_STR);

			std::intrinsics::copy_nonoverlapping(
				ws_key.accept_key.as_ptr(), ptr.add(NUM_RESP_STR), 28);

			let ptr = ptr.add(NUM_RESP_STR + 28) as *mut u32;
			ptr.write_unaligned(C_to_u32str("\r\n\r\n"));
		}
		WsHandshake{ resp }
	}

	// -------------------------------------------------------------
	async fn connect(&self, writer: &mut WriteHalf<'_>) -> Result<(), String>
	{
		match writer.write(&self.resp).await {
			Ok(bytes) => {
				if bytes != NUM_RESP_STR + 32
					{ return Err(String::from("!!! bytes != NUM_RESP_STR + 32")); };
				Ok(())
			},
			Err(err) => { return Err(err.to_string()); },
		}
	}

	// -------------------------------------------------------------
	#[allow(dead_code)]
	#[allow(non_snake_case)]
	fn DBG_show_resp(&self) {
		DBG_show_http_req(&self.resp);
	}
}


////////////////////////////////////////////////////////////////
// WsChannel
pub struct WsChannel<'a> {
	reader: ReadHalf<'a>,
	writer: WriteHalf<'a>,
	
	buf_read: [u8; BYTES_READ_BUF_CLIENT],
	// +10 -> ヘッダの最大バイト数
	buf_write: [u8; BYTES_WRITE_BUF_CLIENT + 10],

	idx_read_next: usize,
	idx_read_tmnt: usize,
}

impl<'a> WsChannel<'a> {
	pub async fn new(stream: &'a mut TcpStream) -> Result<Self, String> {
		let (mut reader, mut writer) = stream.split();
		
		let mut buf_read = [0u8; BYTES_READ_BUF_CLIENT];
		
		let bytes_read = match reader.read(&mut buf_read).await {
			Ok(bytes) => bytes,
			Err(err) => { return Err(err.to_string()); }
		};
		
		let ws_key: WsKey
			= match WsKey::new(&buf_read[0..bytes_read]) {
				Ok(ws_key) => ws_key,
				Err(err_str) => return Err(err_str.to_string())
			};
	
		let ws_handshake = WsHandshake::new(ws_key);

		if let Err(err_string) = ws_handshake.connect(&mut writer).await {
			return Err(err_string);
		}

		Ok(WsChannel {
			reader,
			writer,
			
			buf_read,
			buf_write: [0u8; BYTES_WRITE_BUF_CLIENT + 10],
			
			idx_read_next: 0,
			idx_read_tmnt: 0,
		})
	}

	// -------------------------------------------------------------
	pub async fn read_async(&mut self) -> Result<(&[u8], bool), String> {
//	pub async fn read_async<'a>(&'a mut self) -> Result<(&'a [u8], bool), String> {  <- case 1
//	pub async fn read_async<'b>(&'b mut self) -> Result<(&'b [u8], bool), String> {  <- case 2
		let (idx_next, idx_tmnt) = {
			if self.idx_read_next == 0 {
				match self.reader.read(&mut self.buf_read[..]).await {
					Ok(bytes) => (0, bytes),
					Err(err) => { return Err(err.to_string()); }
				}
			} else {
				(self.idx_read_next, self.idx_read_tmnt)
			}
		};
//		println!("&&& (idx_next, idx_tmnt) -> ({idx_next}, {idx_tmnt})");
		
		let mut ret_b_close = false;
		let (idx_payload_start, idx_payload_tmnt) = unsafe {
			let ptr_top = self.buf_read.as_ptr();
			let ptr = ptr_top.add(idx_next);
			{
				// FIN と Close のチェック。FIN == 0 の場合はエラーとする
				let byte_1st = *ptr;
				if (byte_1st & 0x80) == 0
					{ return Err("!!! FIN == 0".to_string()); }
					
				// opcode のチェック
				if (byte_1st & 0x0f) == 8  // Close のみをチェックしている
					{ ret_b_close = true; }
			}
				
			// MASK のチェック
			let byte_2nd: u8 = *ptr.add(1);
			if (byte_2nd & 0x80) == 0
				{ return Err("!!! MASK bit is 0.".to_string()); }
				
			let (idx_payload_start, mut bytes_payload, ptr): (usize, usize, *const u8) = {
				let len: usize = (byte_2nd & 0x7f) as usize;
				if len <= 125 {
					(idx_next + 2 + 4, len, ptr.add(2))
				} else if len == 126 {
					let ptr_u16 = ptr.add(2) as *const u16;
					(idx_next + 2 + 2 + 4, *ptr_u16 as usize, ptr.add(4))
				} else {
					let ptr_u64 = ptr.add(2) as *const u64;
					(idx_next + 2 + 8 + 4, *ptr_u64 as usize, ptr.add(8))
				}
			};
//			println!("&&& bytes_payload -> {bytes_payload}");
						
			// xor_mask -> little endian であることに注意
			let xor_mask: u64 = (ptr as *const u32).read_unaligned() as u64;
			let xor_mask = (xor_mask << 32) + xor_mask;
			
			let mut ptr_u64 = ptr.add(4) as *mut u64;
			loop {
				if bytes_payload < 8 { break; }
				ptr_u64.write_unaligned(ptr_u64.read_unaligned() ^ xor_mask);
				ptr_u64 = ptr_u64.add(1);
				bytes_payload -= 8;
			}
			
			let mut xor_mask = xor_mask as u32;
			let mut ptr: *mut u8
				= if bytes_payload < 4 {
					ptr_u64 as *mut u8
				} else {
					let ptr_u32 = ptr_u64 as *mut u32;
					ptr_u32.write_unaligned(ptr_u32.read_unaligned() ^ xor_mask);
					bytes_payload -= 4;
					ptr_u32.add(1) as *mut u8
				};
			
			while bytes_payload > 0 {
				*ptr = *ptr ^ (xor_mask as u8);
				ptr = ptr.add(1);
				xor_mask >>= 8;
				bytes_payload -= 1;
			}
			
			// ptr は、tmnt の位置を指している
			let idx_payload_tmnt = ptr.offset_from(ptr_top);
			if idx_payload_tmnt < 0
				{ return Err("!!! idx_payload_tmnt < 0".to_string()); }
			(idx_payload_start, idx_payload_tmnt as usize)
		};
		
		if idx_tmnt == idx_payload_tmnt {
			self.idx_read_next = 0;
		} else {
			self.idx_read_next = idx_payload_tmnt;
			self.idx_read_tmnt = idx_tmnt;
		};
				
		Ok((&self.buf_read[idx_payload_start..idx_payload_tmnt], ret_b_close))
	}

	// -------------------------------------------------------------
	pub async fn send_text(&mut self, msg: &str) -> Result<(), String> {
		let msg_len: usize = msg.len();
		if msg_len > BYTES_WRITE_BUF_CLIENT
			{ return Err("!!! msg.len() > BYTES_WRITE_BUF_CLIENT".to_string()); };
		
		let idx_start: usize = unsafe {
			let ptr = self.buf_write.as_mut_ptr().add(10);
			std::intrinsics::copy_nonoverlapping(msg.as_ptr(), ptr, msg_len);
			
			// FIN = 1, opcode = テキストフレーム -> 先頭１byte は 0x81
			if msg_len <= 125 {
				*ptr.sub(2) = 0x81;
				*ptr.sub(1) = msg_len as u8;
				10 - 2
			} else if msg_len <= 0xffff {
				*ptr.sub(4) = 0x81;
				*ptr.sub(3) = 126;
				*(ptr.sub(2) as *mut u16) = msg_len as u16;
				10 - 4
			} else {
				*ptr.sub(10) = 0x81;
				*ptr.add(9) = 127;
				*(ptr.add(8) as *mut u64) = msg_len as u64;
				0
			}
		};
		
		match self.writer.write(&self.buf_write[idx_start..(msg_len + 10)]).await {
			Ok(_) => Ok(()),
			Err(err) => Err(err.to_string())
		}
	}
}
