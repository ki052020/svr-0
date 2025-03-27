
// -------------------------------------------------------------
// C_to_u32str
#[allow(dead_code)]
#[allow(non_snake_case)]
pub const fn C_to_u32str(str: &str) -> u32 {
	if str.len() != 4
		{ panic!("!!! str.len() != 4"); };

	let ary: &[u8] = str.as_bytes();
	// const fn の内部では for を利用できない
	let mut ret_val: u32 = 0;
	let mut idx = 3;
	loop {
		ret_val = (ret_val << 8) + ary[idx] as u32;
		if idx == 0 { return ret_val; }
		idx -= 1;
	}	
}

// -------------------------------------------------------------
// C_to_u64str
#[allow(dead_code)]
#[allow(non_snake_case)]
pub const fn C_to_u64str(str: &str) -> u64 {
	if str.len() != 8
		{ panic!("!!! str.len() != 8"); };

	let ary: &[u8] = str.as_bytes();
	// const fn の内部では for を利用できない
	let mut ret_val: u64 = 0;
	let mut idx = 7;
	loop {
		ret_val = (ret_val << 8) + ary[idx] as u64;
		if idx == 0 { return ret_val; }
		idx -= 1;
	}	
}
