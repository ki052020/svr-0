use super::{C_to_u32str, C_to_u64str};

pub struct WSKey {
	_sec_key: [u8; 60],
}

impl Default for WSKey {
	fn default() -> Self {
		WSKey {
			_sec_key: [0u8; 60],
		}
	}
}

impl WSKey {
	pub fn get_accept_key(buf: &[u8]) -> Option<[u8; 60]> {
		let len_buf: usize = buf.len() as usize;
		if len_buf < 8 { return None; }
		
		unsafe {
			let ptr = buf.as_ptr();
			let ptr_tmnt = ptr.add(len_buf);
			
			let mut ptr = match Self::srch_Sec_WebSocket_Key(ptr, ptr_tmnt) {
				Some(x) => x,
				None => { return None; }
			};

			// Sec-WebSocket-Key: の読み取り
			loop {
				if *ptr != 0x20 { break; }
				ptr = ptr.add(1);
				if ptr == ptr_tmnt { return None; }
			}
			let mut ret_ary = [0u8; 60];
			{
				let dst = ret_ary.as_mut_ptr() as *mut u64;
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
			
			let v = ret_ary.to_vec();
			let str = String::from_utf8_unchecked(v);
			println!("+++ found -> 'Sec-WebSocket-Key:' -> {str}");
			
			Some(ret_ary)
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
}

// gLMxVY3NvVtc9pFCWDRqng==


