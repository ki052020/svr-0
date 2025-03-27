use super::{C_to_u32str, C_to_u64str};
use sha1::{Sha1, Digest};
use base64::{Engine, engine::general_purpose};

pub struct WSKey {
	accept_key: [u8; 28],
}

impl Default for WSKey {
	fn default() -> Self {
		WSKey {
			accept_key: [0u8; 28],
		}
	}
}

impl WSKey {
	pub fn get_accept_key(&mut self, buf: &[u8]) -> Result<(), &str> {
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
			
			let engine: general_purpose::GeneralPurpose = general_purpose::STANDARD;
			match engine.internal_encode(&sha1_result, &mut self.accept_key) {
				27 => self.accept_key[27] = b'=',
				x => panic!("x -> {x}"),
			}			
			Ok(())
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
	pub fn DBG_show_accept_key(&self) {
		let dbg_str = String::from_utf8(self.accept_key.to_vec()).unwrap();
		println!("&&& accept key -> {dbg_str}");
	}
}

