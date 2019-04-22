extern crate winapi;

use std::thread;
use winapi::{
    ctypes::*,
    shared::minwindef::*,
    um::{
        consoleapi::*, libloaderapi::*, memoryapi::*, processthreadsapi::*, winnt::*, winsock2::*,
    },
};

#[link(name = "trampoline", kind = "static")]
extern "stdcall" {
    static mut send_addr: u32;
    fn send_trampoline(s: SOCKET, buf: *const c_char, len: c_int, flags: c_int) -> c_int;
}

extern "stdcall" fn send_hook(s: SOCKET, buf: *const c_char, len: c_int, flags: c_int) -> c_int {
    println!("send() called. Size of buffer: {}", len);
    unsafe { send_trampoline(s, buf, len, flags) }
}

unsafe fn hook(address: usize, callback: usize) {
    println!("Address is {}, while callback is {}", address, callback);
    let offset = callback.wrapping_sub(address).wrapping_sub(5);
    let mut tmp: u32 = 0;
    let op: c_uchar = 0xE9;

    VirtualProtect(
        address as LPVOID,
        5,
        PAGE_EXECUTE_READWRITE,
        &mut tmp,
    );
    WriteProcessMemory(
        GetCurrentProcess(),
        address as LPVOID,
        &op as *const _ as *const c_void,
        1,
        0 as *mut usize,
    );
    WriteProcessMemory(
        GetCurrentProcess(),
        (address + 1) as LPVOID,
        &offset as *const _ as *const c_void,
        4,
        0 as *mut usize,
    );
    VirtualProtect(address as LPVOID, 5, tmp, &mut tmp);
}

fn main() {
    unsafe {
        AllocConsole();
        let ws = GetModuleHandleA(b"WS2_32.dll\0".as_ptr() as *const i8);
        send_addr = GetProcAddress(ws, b"send\0".as_ptr() as *const i8) as u32;
        println!("Address of send(): {}", send_addr);
        hook(send_addr as usize, send_hook as usize);
    }
}

//Entrypoint
#[no_mangle]
extern "stdcall" fn DllMain(_dll: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        thread::spawn(main);
    }
    TRUE
}
