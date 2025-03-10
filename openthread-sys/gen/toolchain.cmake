# It is only necessary to have a toolchain file so that we can pass `CMAKE_TOOLCHAIN_FILE` and
# thus suppress the target parsing pogo happening in `cmake-rs` here:
# https://github.com/rust-lang/cmake-rs/blob/fd56c5a6b4ecda8815c863eb5b12d7b3f0391197/src/lib.rs#L459

set(CMAKE_SYSTEM_NAME Generic)
