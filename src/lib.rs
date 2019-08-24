extern crate winapi;

use std::io::{Error, Result};
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

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
/// `lpNumberOfBytesWritten` is ignored
pub unsafe fn write_process_memory(
    proc_handle: HANDLE,
    address: LPVOID,
    buffer: &[u8],
) -> Result<()> {
    //use winapi::um::memoryapi::WriteProcessMemory;
    if WriteProcessMemory(
        proc_handle,
        address,
        buffer.as_ptr() as LPVOID,
        buffer.len(),
        std::ptr::null_mut(),
    ) != 0
    {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
/// In case of success, the value of the old page protection is returned
pub unsafe fn virtual_protect(address: LPVOID, size: usize, protection_flags: u32) -> Result<u32> {
    //use winapi::um::memoryapi::VirtualProtect;

    let mut old_protect: u32 = 0;
    if VirtualProtect(address, size, protection_flags, &mut old_protect) != 0 {
        Ok(old_protect)
    } else {
        Err(Error::last_os_error())
    }
}

unsafe fn hook(address: usize, callback: usize) -> Result<()> {
    println!("Address is {}, while callback is {}", address, callback);
    let offset = callback.wrapping_sub(address).wrapping_sub(5);
    let op = &[0xE9];

    let old = virtual_protect(address as LPVOID, 5, PAGE_EXECUTE_READWRITE)?;

    let handle = GetCurrentProcess();
    write_process_memory(handle, address as LPVOID, op)?;
    write_process_memory(handle, (address + 1) as LPVOID, &offset.to_le_bytes())?;

    virtual_protect(address as LPVOID, 5, old)?;
    Ok(())
}

fn main() -> Result<()> {
    unsafe {
        AllocConsole();
        let ws = GetModuleHandleA(b"WS2_32.dll\0".as_ptr() as *const i8);
        send_addr = GetProcAddress(ws, b"send\0".as_ptr() as *const i8) as u32;
        println!("Address of send(): {}", send_addr);
        hook(send_addr as usize, send_hook as usize)
    }
}

//Entrypoint
#[no_mangle]
extern "stdcall" fn DllMain(_dll: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        match main() {
            Ok(_) => TRUE,
            Err(_) => FALSE,
        }
    } else {
        TRUE
    }
}
