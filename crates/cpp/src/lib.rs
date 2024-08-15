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

pub trait Opaque: Sized {
    type Type;
    fn null() -> *mut Self {
        std::ptr::null_mut()
    }
    fn leak(value: Self::Type) -> *mut Self {
        Box::leak(Box::new(value)) as *mut _ as *mut _
    }
    fn drop(ptr: *mut Self) {
        unsafe { drop(Box::from_raw(ptr)) }
    }
    fn arg(ptr: *mut Self) -> &'static mut Self::Type {
        unsafe { &mut *(ptr as *mut _) }
    }
}
