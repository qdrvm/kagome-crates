pub unsafe fn from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    let data = if data.is_null() {
        core::ptr::NonNull::dangling().as_ptr()
    } else {
        data
    };
    core::slice::from_raw_parts(data, len)
}

pub unsafe fn from_raw_parts_mut<'a, T>(data: *mut T, len: usize) -> &'a mut [T] {
    let data = if data.is_null() {
        core::ptr::NonNull::dangling().as_ptr()
    } else {
        data
    };
    core::slice::from_raw_parts_mut(data, len)
}
