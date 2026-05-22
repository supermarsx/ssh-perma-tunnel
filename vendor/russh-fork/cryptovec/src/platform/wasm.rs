// WASM does not support synchronization primitives
pub fn munlock(_ptr: *const u8, _len: usize) {
    // No-op
}

pub fn mlock(_ptr: *const u8, _len: usize) -> i32 {
    0
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    let byte_value = value as u8; // Extract the least significant byte directly
    // SAFETY: pristine from upstream russh-cryptovec@0.7.3. See upstream source for invariants.
    unsafe {
        std::ptr::write_bytes(ptr, byte_value, size);
    }
}

pub fn memcpy(dest: *mut u32, src: *const u8, size: usize) {
    // SAFETY: pristine from upstream russh-cryptovec@0.7.3. See upstream source for invariants.
    unsafe {
        // Convert dest to *mut u8 for byte-wise copying
        let dest_bytes = dest as *mut u8;

        // Use std::ptr::copy_nonoverlapping to copy the data
        std::ptr::copy_nonoverlapping(src, dest_bytes, size);
    }
}
