//! Platform layer for linking `std` into FPVM client programs.
//!
//! The client programs target `os = "zkvm"`, for which `std` delegates every platform service to a
//! small set of `sys_*` functions. This module implements them on top of the FPVM kernel
//! interface, so dependencies that require `std` can run inside the FPVM.
//!
//! Every service is deterministic, as fault proof execution must be: there is no entropy source,
//! clock, environment, or argument list. std's own randomness requests (`sys_rand`, which seeds
//! `HashMap`) are answered with zeroes; getrandom requests from dependencies fail.

extern crate std;

use alloc::{
    alloc::{Layout, alloc},
    boxed::Box,
    format,
    string::String,
};
use core::slice;

use crate::io;

const STDERR_FD: u32 = 2;

/// Installs a panic hook that reports the panic on stderr and exits with code 2, matching the
/// `#[panic_handler]` that `client_entry` installs for `no_std` builds.
///
/// Also installs an allocation error hook that exits the same way. Without it, std's default
/// handler aborts, which compiles to a MIPS `break` that the FPVM cannot prove; the `no_std` build
/// turns an allocation failure into a panic instead.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        io::print_err(&format!("Panic: {info}"));
        io::exit(2)
    }));
    std::alloc::set_alloc_error_hook(alloc_error);
}

/// Reports an allocation failure and exits with code 2. It must not allocate.
fn alloc_error(_layout: Layout) {
    io::print_err("Panic: memory allocation failed\n");
    io::exit(2)
}

/// Borrows `len` bytes at `ptr`, treating a zero length as empty regardless of `ptr`.
///
/// # Safety
/// For a non-zero `len`, `ptr` must be valid for reads of `len` bytes.
const unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 { &[] } else { unsafe { slice::from_raw_parts(ptr, len) } }
}

fn write(fd: u32, msg: &[u8]) {
    let msg = String::from_utf8_lossy(msg);
    if fd == STDERR_FD { io::print_err(&msg) } else { io::print(&msg) }
}

fn unsupported(name: &str) -> ! {
    io::print_err(&format!("{name} is not supported in the FPVM\n"));
    io::exit(3)
}

/// Fails every getrandom 0.2 request: fault proof execution has no entropy source, and a
/// dependency that needs real entropy must fail visibly rather than run on predictable bytes.
const fn unsupported_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
getrandom::register_custom_getrandom!(unsupported_getrandom);

#[unsafe(no_mangle)]
extern "C" fn sys_halt() {
    io::exit(0)
}

#[unsafe(no_mangle)]
const extern "C" fn sys_output(_output_id: u32, _output_value: u32) {}

#[unsafe(no_mangle)]
extern "C" fn sys_sha_compress(
    _out_state: *mut [u32; 8],
    _in_state: *const [u32; 8],
    _block1_ptr: *const [u32; 8],
    _block2_ptr: *const [u32; 8],
) {
    unsupported("sys_sha_compress")
}

#[unsafe(no_mangle)]
extern "C" fn sys_sha_buffer(
    _out_state: *mut [u32; 8],
    _in_state: *const [u32; 8],
    _buf: *const u8,
    _count: u32,
) {
    unsupported("sys_sha_buffer")
}

#[unsafe(no_mangle)]
extern "C" fn sys_rand(recv_buf: *mut u32, words: usize) {
    if words > 0 {
        // SAFETY: std passes a buffer of `words` writable words.
        unsafe { slice::from_raw_parts_mut(recv_buf, words) }.fill(0);
    }
}

#[unsafe(no_mangle)]
extern "C" fn sys_panic(msg_ptr: *const u8, len: usize) -> ! {
    // SAFETY: std passes a message of `len` readable bytes.
    write(STDERR_FD, unsafe { bytes(msg_ptr, len) });
    io::exit(2)
}

#[unsafe(no_mangle)]
extern "C" fn sys_log(msg_ptr: *const u8, len: usize) {
    // SAFETY: std passes a message of `len` readable bytes.
    write(STDERR_FD, unsafe { bytes(msg_ptr, len) });
}

#[unsafe(no_mangle)]
const extern "C" fn sys_cycle_count() -> usize {
    0
}

#[unsafe(no_mangle)]
const extern "C" fn sys_read(_fd: u32, _recv_buf: *mut u8, _nrequested: usize) -> usize {
    0
}

#[unsafe(no_mangle)]
extern "C" fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    // SAFETY: std passes a buffer of `nbytes` readable bytes.
    write(fd, unsafe { bytes(write_buf, nbytes) });
}

/// Reports every environment variable as unset.
#[unsafe(no_mangle)]
const extern "C" fn sys_getenv(
    _recv_buf: *mut u32,
    _words: usize,
    _varname: *const u8,
    _varname_len: usize,
) -> usize {
    usize::MAX
}

#[unsafe(no_mangle)]
const extern "C" fn sys_argc() -> usize {
    0
}

#[unsafe(no_mangle)]
const extern "C" fn sys_argv(_out_words: *mut u32, _out_nwords: usize, _arg_index: usize) -> usize {
    0
}

#[unsafe(no_mangle)]
extern "C" fn sys_alloc_words(nwords: usize) -> *mut u32 {
    let Some(nbytes) = nwords.checked_mul(4) else {
        unsupported("sys_alloc_words with an overflowing size")
    };
    sys_alloc_aligned(nbytes, 4).cast()
}

/// Backs `std::alloc::System`. Allocations go through the global allocator, which the client
/// program sets up with `alloc_heap!`.
#[unsafe(no_mangle)]
extern "C" fn sys_alloc_aligned(nbytes: usize, align: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(nbytes.max(1), align) else {
        unsupported("sys_alloc_aligned with an invalid layout")
    };
    // SAFETY: `layout` has a non-zero size.
    unsafe { alloc(layout) }
}
