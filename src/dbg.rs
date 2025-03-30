use super::C_to_u32str;

// -------------------------------------------------------------
#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn check_GET_req(buf: &[u8]) -> bool {
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
pub fn DBG_show_http_req(buf: &[u8]) -> usize
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

// -------------------------------------------------------------
#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn DBG_show_u8s(vals: &[u8]) {
	let len = vals.len();
	let mut idx = 0;
	loop {		
		for _i in 0..8 {
			if idx == len { return; }
			
			print!("{:02x} ", vals[idx]);
			idx += 1;
		}
		println!("");
	}
}

