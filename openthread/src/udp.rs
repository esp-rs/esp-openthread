use core::cell::RefCell;
use core::ffi::c_void;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::net::{Ipv6Addr, SocketAddrV6};

use log::info;
use openthread_sys::otUdpClose;

use crate::signal::Signal;
use crate::sys::{
    otError_OT_ERROR_NO_BUFS, otIp6Address, otIp6Address__bindgen_ty_1, otMessage,
    otMessageGetLength, otMessageInfo, otMessageRead, otNetifIdentifier_OT_NETIF_THREAD,
    otSockAddr, otUdpBind, otUdpConnect, otUdpOpen, otUdpSocket,
};
use crate::{ot, OpenThread, OtContext, OtError};

pub struct OtUdpResources<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> {
    sockets: MaybeUninit<[UdpSocketCtx; UDP_SOCKETS]>,
    buffers: MaybeUninit<[[u8; UDP_RX_SZ]; UDP_SOCKETS]>,
    state: MaybeUninit<RefCell<OtUdpState<'static>>>,
}

impl<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> OtUdpResources<UDP_SOCKETS, UDP_RX_SZ> {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_SOCKET: UdpSocketCtx = UdpSocketCtx::new();
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_BUFFERS: [u8; UDP_RX_SZ] = [0; UDP_RX_SZ];

    /// Create a new `OtResources` instance.
    pub const fn new() -> Self {
        Self {
            sockets: MaybeUninit::uninit(),
            buffers: MaybeUninit::uninit(),
            state: MaybeUninit::uninit(),
        }
    }

    /// Initialize the resouces, as they start their life as `MaybeUninit` so as to avoid mem-moves.
    ///
    /// Returns:
    /// - A mutable reference to an `OtState` value that represents the initialized OpenThread state.
    // TODO: Need to manually drop/reset the signals in OtSignals
    pub(crate) fn init(&mut self) -> &mut RefCell<OtUdpState<'static>> {
        self.sockets.write([Self::INIT_SOCKET; UDP_SOCKETS]);
        self.buffers.write([Self::INIT_BUFFERS; UDP_SOCKETS]);

        let buffers: &mut [[u8; UDP_RX_SZ]; UDP_SOCKETS] =
            unsafe { self.buffers.assume_init_mut() };

        self.state.write(RefCell::new(unsafe {
            core::mem::transmute(OtUdpState {
                sockets: self.sockets.assume_init_mut(),
                buffers: core::slice::from_raw_parts_mut(
                    buffers.as_mut_ptr() as *mut _,
                    UDP_RX_SZ * UDP_SOCKETS,
                ),
                buf_len: UDP_RX_SZ,
            })
        }));

        info!("OpenThread UDP resources initialized");

        unsafe { self.state.assume_init_mut() }
    }
}

impl<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> Default
    for OtUdpResources<UDP_SOCKETS, UDP_RX_SZ>
{
    fn default() -> Self {
        Self::new()
    }
}

/// The state of the OpenThread stack, from Rust POV.
pub(crate) struct OtUdpState<'a> {
    sockets: &'a mut [UdpSocketCtx],
    buffers: &'a mut [u8],
    buf_len: usize,
}

pub struct UdpSocket<'a> {
    ot: OpenThread<'a>,
    slot: usize,
}

impl<'a> UdpSocket<'a> {
    pub fn bind(ot: OpenThread<'a>, local: &SocketAddrV6) -> Result<Self, OtError> {
        let this = Self::new(ot)?;

        {
            let mut ot = this.ot.activate();
            let state = ot.state();

            unsafe {
                otUdpBind(
                    state.ot.instance,
                    &mut state.udp.as_mut().unwrap().sockets[this.slot].ot_socket,
                    &to_ot_addr(local),
                    otNetifIdentifier_OT_NETIF_THREAD,
                );
            }
        }

        Ok(this)
    }

    pub fn connect(ot: OpenThread<'a>, remote: &SocketAddrV6) -> Result<Self, OtError> {
        let this = Self::new(ot)?;

        {
            let mut ot = this.ot.activate();
            let state = ot.state();

            unsafe {
                otUdpConnect(
                    state.ot.instance,
                    &mut state.udp().sockets[this.slot].ot_socket,
                    &to_ot_addr(remote),
                );
            }
        }

        Ok(this)
    }

    fn new(ot: OpenThread<'a>) -> Result<Self, OtError> {
        let mut active_ot = ot.activate();
        let state = active_ot.state();
        let instance = state.ot.instance;
        let udp = state.udp();

        let slot = udp
            .sockets
            .iter()
            .position(|socket| !socket.taken)
            .ok_or(otError_OT_ERROR_NO_BUFS)?;

        let socket = &mut udp.sockets[slot];
        // TODO socket.socket = UdpSocketData::new();
        socket.taken = true;

        unsafe {
            otUdpOpen(
                instance,
                &mut socket.ot_socket,
                Some(Self::plat_c_udp_receive),
                slot as *mut c_void,
            );
        }

        Ok(Self { ot, slot })
    }

    pub async fn wait_recv_available(&self) -> Result<(), OtError> {
        poll_fn(move |cx| {
            self.ot.activate().state().udp().sockets[self.slot]
                .rx_peer
                .poll_wait_triggered(cx)
        })
        .await;

        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6), OtError> {
        if buf.is_empty() {
            return Ok((0, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)));
        }

        let (len, src_addr) = poll_fn(move |cx| {
            self.ot.activate().state().udp().sockets[self.slot]
                .rx_peer
                .poll_wait(cx)
        })
        .await;

        let mut ot = self.ot.activate();
        let udp = ot.state().udp();

        let offset = self.slot * udp.buf_len;
        let data = &mut udp.buffers[offset..offset + len];

        let len = len.min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);

        Ok((len, src_addr))
    }

    pub async fn send(&self, data: &[u8], dst: &SocketAddrV6) -> Result<usize, OtError> {
        todo!()
    }

    extern "C" fn plat_c_udp_receive(
        slot: *mut c_void,
        msg: *mut otMessage,
        msg_info: *const otMessageInfo,
    ) {
        let slot: usize = slot as usize;

        let mut ot = OtContext::callback(core::ptr::null_mut());
        let udp = ot.state().udp();

        let socket = &mut udp.sockets[slot];
        if socket.rx_peer.signaled() {
            return;
        }

        let msg = unsafe { &*msg };
        let msg_info = unsafe { &*msg_info };
        let msg_len = unsafe { otMessageGetLength(msg) as usize };

        let buf_len = udp.buf_len;
        if msg_len <= buf_len {
            let offset = slot * buf_len;
            let buf = &mut udp.buffers[offset..offset + buf_len];

            unsafe {
                otMessageRead(
                    msg,
                    0,
                    buf.as_mut_ptr() as *mut _,
                    buf_len.min(msg_len) as _,
                );
            };

            socket.rx_peer.signal((
                msg_len,
                SocketAddrV6::new(
                    unsafe { msg_info.mPeerAddr.mFields.m8 }.into(),
                    msg_info.mPeerPort,
                    0,
                    0,
                ),
            ));
        }
    }
}

impl Drop for UdpSocket<'_> {
    fn drop(&mut self) {
        let mut ot = self.ot.activate();
        let instance = ot.state().ot.instance;
        let udp = ot.state().udp();

        ot!(unsafe { otUdpClose(instance, &mut udp.sockets[self.slot].ot_socket,) }).unwrap();

        udp.sockets[self.slot].taken = false;
    }
}

fn to_sock_addr(addr: &otIp6Address, port: u16, netif: u32) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::from(unsafe { addr.mFields.m8 }), port, 0, netif)
}

fn to_ot_addr(addr: &SocketAddrV6) -> otSockAddr {
    otSockAddr {
        mAddress: otIp6Address {
            mFields: otIp6Address__bindgen_ty_1 {
                m8: addr.ip().octets(),
            },
        },
        mPort: addr.port(),
    }
}

pub(crate) struct UdpSocketCtx {
    taken: bool,
    ot_socket: otUdpSocket,
    rx_peer: Signal<(usize, SocketAddrV6)>,
}

impl UdpSocketCtx {
    pub(crate) const fn new() -> Self {
        Self {
            taken: false,
            ot_socket: otUdpSocket {
                mSockName: otSockAddr {
                    mAddress: otIp6Address {
                        mFields: otIp6Address__bindgen_ty_1 { m8: [0; 16] },
                    },
                    mPort: 0,
                },
                mPeerName: otSockAddr {
                    mAddress: otIp6Address {
                        mFields: otIp6Address__bindgen_ty_1 { m8: [0; 16] },
                    },
                    mPort: 0,
                },
                mHandler: None,
                mContext: core::ptr::null_mut(),
                mHandle: core::ptr::null_mut(),
                mNext: core::ptr::null_mut(),
            },
            rx_peer: Signal::new(),
        }
    }
}
