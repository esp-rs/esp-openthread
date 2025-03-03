use core::{ffi::c_void, net::{Ipv6Addr, SocketAddrV6}, task::Waker};

use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal, waitqueue::WakerRegistration};
use openthread_sys::{otError_OT_ERROR_NO_BUFS, otMessage, otMessageInfo, otUdpOpen, otUdpSocket};

use crate::{OpenThread, OtContext, OtError};

pub struct UdpSocket<'a> {
    ot: OpenThread<'a>,
    slot: usize,
}

impl<'a> UdpSocket<'a> {
    pub fn new(ot: OpenThread<'a>) -> Result<Self, OtError> {
        let mut ot = ot.activate();
        let state = ot.state();

        let slot = state
            .udp_sockets_data
            .iter()
            .position(|socket| !socket.taken)
            .ok_or(otError_OT_ERROR_NO_BUFS)?;

        let socket_data = &mut state.udp_sockets_data[slot];
        // TODO socket_data.socket = UdpSocketData::new();
        socket_data.taken = true;

        unsafe {
            otUdpOpen(state.data.instance, &mut socket_data.socket, Some(Self::plat_c_udp_receive), slot as *mut c_void);
        }

        todo!()
    }

    pub async fn wait_recv_available(&self) -> Result<(), OtError> {
        loop {
            {
                let mut ot = self.ot.activate();
                let state = ot.state();
        
                if state.udp_sockets_data[self.slot].rx_peer.is_some() {
                    return Ok(());
                }
            }

            self.ot.0.udp_sockets_signals[self.slot].rx.wait().await;
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6), OtError> {
        loop {
            {
                let mut ot = self.ot.activate();
                let state = ot.state();
        
                let socket_data = &mut state.udp_sockets_data[self.slot];

                if let Some(src_addr) = socket_data.rx_peer.take() {
                    let len = socket_data.rx_data.len().min(buf.len());
                    buf[..len].copy_from_slice(&socket_data.rx_data[..len]);

                    return Ok((len, src_addr));
                }
            }

            self.ot.0.udp_sockets_signals[self.slot].rx.wait().await;
        }
    }

    pub async fn send(&self, data: &[u8], dst: SocketAddrV6) -> Result<usize, OtError> {
        todo!()
    }

    extern "C" fn plat_c_udp_receive(slot: *mut c_void, msg: *mut otMessage, msg_info: *const otMessageInfo) {
        let slot: usize = slot as usize;

        let mut ot = OtContext::callback(core::ptr::null_mut());
        let state = ot.state();

        todo!()
    }
}

pub(crate) struct UdpSocketSignals {
    rx: Signal<NoopRawMutex, ()>,
}

impl UdpSocketSignals {
    pub(crate) const fn new() -> Self {
        Self {
            rx: Signal::new(),
        }
    }
}

pub(crate) struct UdpSocketData {
    socket: otUdpSocket,
    taken: bool,
    rx_data: heapless::Vec<u8, 1280>, // TODO
    rx_peer: Option<SocketAddrV6>,
}

impl UdpSocketData {
    pub(crate) const fn new() -> Self {
        todo!()
    }
}

// /// Creates a new UDP socket
// pub fn get_udp_socket<'s, const BUFFER_SIZE: usize>(
//     &'s self,
// ) -> Result<UdpSocket<'s, 'a, BUFFER_SIZE>, Error>
// where
//     'a: 's,
// {
//     let ot_socket = otUdpSocket {
//         mSockName: otSockAddr {
//             mAddress: otIp6Address {
//                 mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
//             },
//             mPort: 0,
//         },
//         mPeerName: otSockAddr {
//             mAddress: otIp6Address {
//                 mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
//             },
//             mPort: 0,
//         },
//         mHandler: Some(udp_receive_handler),
//         mContext: core::ptr::null_mut(),
//         mHandle: core::ptr::null_mut(),
//         mNext: core::ptr::null_mut(),
//     };

//     Ok(UdpSocket {
//         ot_socket,
//         ot: self,
//         receive_len: 0,
//         receive_from: [0u8; 16],
//         receive_port: 0,
//         max: BUFFER_SIZE,
//         _pinned: PhantomPinned::default(),
//         receive_buffer: [0u8; BUFFER_SIZE],
//     })
// }

// pub fn get_eui(&self, out: &mut [u8]) {
//     unsafe { otPlatRadioGetIeeeEui64(self.instance, out.as_mut_ptr()) }
// }
