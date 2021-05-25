use http_req::request;
use http_req::{request::{Request, Method}, uri::Uri};
use std::ffi::{CString, CStr};
use std::os::raw::{c_int, c_char};
use encoding_rs::GBK;
use base64::{encode, decode};
use rand::prelude::*;
use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;
use serde_json::{Value, Map};

pub struct HttpResult {
    content: Option<String>,
    status_code: Option<u16>,
    reason: Option<String>,
    error: Option<String>
}

#[no_mangle]
pub unsafe extern fn rsa_public_encrypt(pubkey: *const c_char, data: *const c_char) -> *mut c_char{
    match _rsa_public_encrypt(CStr::from_ptr(pubkey), CStr::from_ptr(data)){
        Ok(encrypted) => {
            let encrypted = CString::new(encrypted).unwrap();
            encrypted.into_raw()
        },
        Err(err) => {
            println!("RSA加密失败! {:?}", err);
            0 as *mut c_char
        }
    }
}

#[no_mangle]
pub unsafe extern fn aes_random_key128() -> *mut c_char {
    let key = _aes_random_key128();
    let c_str_key = CString::new(key).unwrap();
    c_str_key.into_raw()
}

#[no_mangle]
pub extern fn free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            eprintln!("String ptr is null!");
            return
        }
        CString::from_raw(s)
    };
}

#[no_mangle]
pub extern fn http_result_content(ptr: *mut HttpResult, charset: *const c_char) -> *mut c_char {
    let result = unsafe {
        if ptr.is_null() {
            eprintln!("HttpResult ptr is null!");
            return 0 as *mut c_char;
        }
        &mut *ptr
    };
    if let Some(err) = &result.error{
        eprintln!("HttpResult has error: {:?}", err);
        0 as *mut c_char
    }else{
        let content = result.content.clone().unwrap();
        let content = get_string_of_charset(&content, charset);
        CString::new(content).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern fn http_result_success(ptr: *mut HttpResult) -> c_int {
    let result = unsafe {
        if ptr.is_null() {
            eprintln!("HttpResult ptr is null!");
            return 0;
        }
        &mut *ptr
    };
    match &result.error{
        Some(_err) => 0,
        _ => 1
    }
}

#[no_mangle]
pub extern fn http_result_status_info(ptr: *mut HttpResult) -> *mut c_char {
    let result = unsafe {
        if ptr.is_null() {
            eprintln!("HttpResult ptr is null!");
            return 0 as *mut c_char;
        }
        &mut *ptr
    };
    if let Some(err) = &result.error{
        eprintln!("HttpResult has error: {:?}", err);
        0 as *mut c_char
    }else{
        let reason = result.reason.clone().unwrap();
        let status_code = result.status_code.clone().unwrap();
        CString::new(format!("{} {}", status_code, reason)).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern fn http_result_error_info(ptr: *mut HttpResult, charset: *const c_char) -> *mut c_char {
    let result = unsafe {
        if ptr.is_null() {
            eprintln!("HttpResult ptr is null!");
            return 0 as *mut c_char;
        }
        &mut *ptr
    };
    if let Some(err) = &result.error{
        let d = get_string_of_charset(&err, charset);
        CString::new(d).unwrap().into_raw()
    }else{
        eprintln!("HttpResult error is empty!");
        0 as *mut c_char
    }
}

#[no_mangle]
pub extern fn http_result_free(ptr: *mut HttpResult) {
    if ptr.is_null() {
        eprintln!("HttpResult ptr is null!");
        return
    }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
pub extern fn printval(l: *const c_char, r: *const c_char) {
    let l = unsafe{ CStr::from_ptr(l) };
    let r = unsafe{ CStr::from_ptr(r) };
    println!("{} {}", l.to_str().unwrap_or(""), r.to_str().unwrap_or(""));
}

#[no_mangle]
pub unsafe extern fn aes_encrypt(data: *const c_char, key: *const c_char) -> *mut c_char {
    match _aes_encrypt(CStr::from_ptr(data), CStr::from_ptr(key)){
        Ok(data) => {
            CString::new(data).unwrap().into_raw()
        },
        Err(err) => {
            println!("加密失败! {:?}", err);
            0 as *mut c_char
        }
    }
}

#[no_mangle]
pub unsafe extern fn aes_decrypt(data: *const c_char, key: *const c_char) -> *mut c_char {
    match _aes_decrypt(CStr::from_ptr(data), CStr::from_ptr(key)){
        Ok(data) => {
            CString::new(data).unwrap().into_raw()
        },
        Err(err) => {
            println!("解密失败! {:?}", err);
            0 as *mut c_char
        }
    }
}
// c++和rust互相传参
// http://jakegoulding.com/rust-ffi-omnibus/objects/

#[no_mangle]
pub unsafe extern fn http_get(url: *const c_char) -> *mut HttpResult {
    let result =
    match _http_get(CStr::from_ptr(url)){
        Ok(result) => {
            result
        }
        Err(err) => {
            eprintln!("请求失败:{:?}", err);
            HttpResult{
                content: None,
                status_code: None,
                reason: None,
                error: Some(format!("{:?}", err))
            }
        }
    };
    Box::into_raw(Box::new(result))
}

#[no_mangle]
pub unsafe extern fn http_post(url: *const c_char, data:*const c_char) -> *mut HttpResult {
    let result = match _http_post(CStr::from_ptr(url), CStr::from_ptr(data)){
        Ok(result) => {
            result
        }
        Err(err) => {
            eprintln!("请求失败:{:?}", err);
            HttpResult{
                content: None,
                status_code: None,
                reason: None,
                error: Some(format!("{:?}", err))
            }
        }
    };
    Box::into_raw(Box::new(result))
}

#[no_mangle]
pub unsafe extern fn http_post_json(url: *const c_char, datas: *const *const c_char, len: c_int) -> *mut HttpResult {
    let json = map_to_json(datas, len);
    if let Err(err) = json{
        eprintln!("JSON组合失败:{:?}", err);
        return Box::into_raw(Box::new(HttpResult{
            content: None,
            status_code: None,
            reason: None,
            error: Some(format!("{:?}", err))
        }));
    }
    let result = match _http_post_json(CStr::from_ptr(url), &json.unwrap()){
        Ok(result) => {
            result
        }
        Err(err) => {
            eprintln!("请求失败:{:?}", err);
            HttpResult{
                content: None,
                status_code: None,
                reason: None,
                error: Some(format!("{:?}", err))
            }
        }
    };
    Box::into_raw(Box::new(result))
}

fn get_string_of_charset(content:&str, charset: *const c_char) -> Vec<u8>{
    if let Ok(charset) = unsafe{ CStr::from_ptr(charset) }.to_str(){
        if charset.to_lowercase() == "gbk"{
            let (gbkdata, _e, _r) = GBK.encode(&content);
            gbkdata.to_vec()
        }else{
            content.as_bytes().to_vec()
        }
    }else{
        content.as_bytes().to_vec()
    }
}

fn map_to_json(values: *const *const c_char, len: c_int) -> Result<String, String>{
    let values = unsafe { std::slice::from_raw_parts(values, len as usize) };
	let mut map = Map::new();
	for pair in values.chunks(2) {
		if pair.len() != 2{
			return Err(format!("错误的数据对: {:?}", pair));
		}
		let key = unsafe{ CStr::from_ptr(pair[0]) };
		let value = unsafe{ CStr::from_ptr(pair[1]) };
		if let Ok(key) = key.to_str(){
			if let Ok(value) = value.to_str(){
				map.insert(key.to_string(), Value::String(value.to_string()));
			}
		}
	}
    let json = Value::Object(map);
    Ok(json.to_string())
}

fn _rsa_public_encrypt(pubkey:&CStr, data:&CStr) -> Result<String, Box<dyn std::error::Error>>{
    let pk = pubkey.to_str()?;
    let pk = pk.replace("-----BEGIN PUBLIC KEY-----", "");
    let pk = pk.replace("-----END PUBLIC KEY-----", "");
    let pk = pk.replace("\r\n", "");
    let pk = pk.replace("\r", "");
    let pk = pk.replace("\n", "");

    let data = data.to_str()?;

    let pk = base64::decode(&pk)?;
    let enc = rsa_public_encrypt_pkcs1::encrypt(&pk, data.as_bytes())?;
    Ok(base64::encode(&enc))
}

fn _aes_random_key128() -> String{
    let key = &mut [0u8; 16];
    rand::thread_rng().fill_bytes(key);
    encode(key)
}

fn _aes_encrypt(data:&CStr, key:&CStr) -> Result<String, Box<dyn std::error::Error>>{
    let data = data.to_str()?;
    let key = key.to_str()?;
    let key = decode(key)?;
    
    let cipher = Aes128Ecb::new_var(&key, &[0u8; 16])?;

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 1024];
    // copy message to the buffer
    let pos = data.len();
    buffer[..pos].copy_from_slice(data.as_bytes());
    let ciphertext = cipher.encrypt(&mut buffer, pos)?;

    let encrypt_text = encode(ciphertext);
    
    Ok(encrypt_text)
}

fn _aes_decrypt(data:&CStr, key:&CStr) -> Result<String, Box<dyn std::error::Error>>{
    let data = data.to_str()?;
    let key = key.to_str()?;

    let key = decode(key)?;

    let cipher = Aes128Ecb::new_var(&key, &[0u8; 16]).unwrap();
    let mut buf = decode(&data)?;
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

    let decrypted_text = decrypted_ciphertext.to_vec();
    
    Ok(String::from_utf8(decrypted_text)?)
}

fn _http_post(url:&CStr, data:&CStr) -> Result<HttpResult, Box<dyn std::error::Error>>{
    let url = url.to_str()?;
    let data = data.to_str()?;
    http_post_string(url, data)
}

fn _http_post_json(url:&CStr, data:&str) -> Result<HttpResult, Box<dyn std::error::Error>>{
    let url = url.to_str()?;
    http_post_string(url, data)
}

fn http_post_string(url: &str, data: &str) -> Result<HttpResult, Box<dyn std::error::Error>>{
    let content_length = data.as_bytes().len();
    let mut writer = Vec::new();
    let uri: Uri = url.parse().unwrap();
    let res = Request::new(&uri)
        .header("Content-Type", "application/json")
        .header("accept", "*/*")
        .header("user-agent", "Rust/1.39.0")
        .header("content-length", &format!("{}", content_length))
        .method(Method::POST)
        .body(data.as_bytes())
        .send(&mut writer)?;
        let content = String::from_utf8(writer)?;
    Ok(HttpResult{
        content: Some(content),
        status_code: Some(u16::from(res.status_code())),
        reason: Some(res.reason().to_string()),
        error: None
    })
}

fn _http_get(url:&CStr) -> Result<HttpResult, Box<dyn std::error::Error>>{
    let url = url.to_str()?;
    let mut writer = Vec::new();
    let res = request::get(url, &mut writer)?;
    let content = String::from_utf8(writer)?;
    Ok(HttpResult{
        content: Some(content),
        status_code: Some(u16::from(res.status_code())),
        reason: Some(res.reason().to_string()),
        error: None
    })
}

#[test]
fn test() {

    let pkstr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCinIOX/ypQfRrz2vHHSJytO8Ow0p10iNwD/kzPGHhsyUUjAvLx5eHuUUhnFSFp1qiRI3ayEzz0thJwCNYszGWCEoC/ivB+2UZypN5DFCRLe7JiwKexEGFKrvRdMsOmN90YfuHgPjv0knCN06NX2X9RaUxM7P12zx6qQm9Umf689wIDAQAB";

    let bytes = decode(pkstr).unwrap();

    println!("{:?}", bytes);

    println!("长度={:?}", bytes.len());

    let message = "hello!";

    let r = rsa_public_encrypt_pkcs1::encrypt(&bytes, message.as_bytes()).unwrap();

    let s = encode(&r);
    println!("{:?}", s);
}
//cargo test -- --nocapture