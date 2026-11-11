//! The XDP program, as eBPF instructions built in Rust.
//!
//! In C it is one line:
//!
//! ```c
//! return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
//! ```
//!
//! `bpf_redirect_map` hands the frame to the AF_XDP socket in the map slot
//! for its receive queue. The low two bits of its `flags` argument are the
//! action when that slot holds no socket (`bpf-helpers(7)`), so a frame on
//! a queue without a socket is dropped. It never reaches the kernel's
//! network stack.
//!
//! Encodings follow the eBPF instruction set, RFC 9669. Instructions are
//! in host byte order, as the kernel reads them, and the register byte
//! puts the destination in its low nibble, which is the little-endian
//! layout of `struct bpf_insn`.

#[cfg(not(target_endian = "little"))]
compile_error!("the XDP program encoding is written for little-endian hosts");

use std::os::fd::{AsRawFd, BorrowedFd};

/// `XDP_DROP` from `enum xdp_action`.
pub const XDP_DROP: i32 = 1;

/// The XDP context the kernel passes in `r1` (`struct xdp_md`).
#[repr(C)]
#[allow(dead_code, reason = "mirrors the kernel layout; only offsets are read")]
pub(crate) struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

/// An eBPF register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
}

/// A kernel helper the program calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Helper {
    /// `bpf_redirect_map`, `FN(redirect_map, 51)` in `uapi/linux/bpf.h`.
    RedirectMap = 51,
}

/// One eBPF instruction, laid out as `struct bpf_insn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

// Instruction classes, sizes, modes and operations (RFC 9669, section 3).
const CLASS_LD: u8 = 0x00;
const CLASS_LDX: u8 = 0x01;
const CLASS_JMP: u8 = 0x05;
const CLASS_ALU64: u8 = 0x07;
const SIZE_W: u8 = 0x00;
const SIZE_DW: u8 = 0x18;
const MODE_IMM: u8 = 0x00;
const MODE_MEM: u8 = 0x60;
const SOURCE_K: u8 = 0x00;
const OP_MOV: u8 = 0xb0;
const OP_CALL: u8 = 0x80;
const OP_EXIT: u8 = 0x90;
/// `BPF_PSEUDO_MAP_FD`: the 64-bit immediate is a map file descriptor.
const PSEUDO_MAP_FD: u8 = 1;

impl Insn {
    const fn new(code: u8, dst: Reg, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst as u8) | (src << 4),
            off,
            imm,
        }
    }

    /// `dst = *(u32 *)(src + off)`.
    pub const fn load_u32(dst: Reg, src: Reg, off: i16) -> Self {
        Self::new(CLASS_LDX | MODE_MEM | SIZE_W, dst, src as u8, off, 0)
    }

    /// `dst = map`, the two-slot 64-bit immediate load the kernel resolves
    /// from a map file descriptor.
    pub fn load_map(dst: Reg, map: BorrowedFd<'_>) -> [Self; 2] {
        [
            Self::new(
                CLASS_LD | MODE_IMM | SIZE_DW,
                dst,
                PSEUDO_MAP_FD,
                0,
                map.as_raw_fd(),
            ),
            Self::new(0, Reg::R0, 0, 0, 0),
        ]
    }

    /// `dst = imm`, sign-extended to 64 bits.
    pub const fn mov64_imm(dst: Reg, imm: i32) -> Self {
        Self::new(CLASS_ALU64 | OP_MOV | SOURCE_K, dst, 0, 0, imm)
    }

    /// Calls a kernel helper. Arguments are in `r1` to `r5`, the result
    /// lands in `r0`, and `r1` to `r5` are clobbered.
    pub const fn call(helper: Helper) -> Self {
        Self::new(CLASS_JMP | OP_CALL, Reg::R0, 0, 0, helper as i32)
    }

    /// Returns `r0`.
    pub const fn exit() -> Self {
        Self::new(CLASS_JMP | OP_EXIT, Reg::R0, 0, 0, 0)
    }
}

/// Byte offset of `rx_queue_index` in the XDP context.
pub(crate) const RX_QUEUE_INDEX: i16 = std::mem::offset_of!(XdpMd, rx_queue_index) as i16;

/// The program: every frame to the socket for its receive queue in `map`,
/// or dropped when that slot is empty.
pub fn redirect_to_sockets(map: BorrowedFd<'_>) -> [Insn; 6] {
    let [map_low, map_high] = Insn::load_map(Reg::R1, map);
    [
        // r2 = ctx->rx_queue_index, read before r1 is reused.
        Insn::load_u32(Reg::R2, Reg::R1, RX_QUEUE_INDEX),
        // r1 = &xsks
        map_low,
        map_high,
        // r3 = XDP_DROP, the action when the slot has no socket.
        Insn::mov64_imm(Reg::R3, XDP_DROP),
        // r0 = bpf_redirect_map(r1, r2, r3)
        Insn::call(Helper::RedirectMap),
        Insn::exit(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// Any open descriptor stands in for the map: encoding only reads its number.
    fn map() -> std::fs::File {
        std::fs::File::open("/dev/null").unwrap()
    }

    fn fields(insn: Insn) -> (u8, u8, u8, i16, i32) {
        (
            insn.code,
            insn.regs & 0x0f,
            insn.regs >> 4,
            insn.off,
            insn.imm,
        )
    }

    #[test]
    fn instructions_follow_the_rfc_9669_encoding() {
        // Opcodes from RFC 9669, appendix A, and the 64-bit immediate
        // load's src_reg value for a map fd from section 5.4.
        assert_eq!(
            fields(Insn::load_u32(Reg::R2, Reg::R1, 16)),
            (0x61, 2, 1, 16, 0)
        );
        assert_eq!(fields(Insn::mov64_imm(Reg::R3, 1)), (0xb7, 3, 0, 0, 1));
        assert_eq!(fields(Insn::call(Helper::RedirectMap)), (0x85, 0, 0, 0, 51));
        assert_eq!(fields(Insn::exit()), (0x95, 0, 0, 0, 0));
        let file = map();
        let [low, high] = Insn::load_map(Reg::R1, file.as_fd());
        assert_eq!(fields(low), (0x18, 1, 1, 0, file.as_raw_fd()));
        assert_eq!(fields(high), (0, 0, 0, 0, 0));
        assert_eq!(std::mem::size_of::<Insn>(), 8);
    }

    #[test]
    fn context_offset_is_the_receive_queue_index() {
        // struct xdp_md: data, data_end, data_meta, ingress_ifindex,
        // rx_queue_index, egress_ifindex, all __u32.
        assert_eq!(RX_QUEUE_INDEX, 16);
        assert_eq!(std::mem::size_of::<XdpMd>(), 24);
    }

    /// What the verifier knows about a register at one point.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Value {
        Uninit,
        Context,
        Stack,
        Map,
        Scalar(Option<i64>),
    }

    /// Walks the straight-line program as the verifier does for these
    /// instruction kinds, and returns the helper calls with their
    /// argument states. Panics on anything the verifier would reject.
    fn verify(program: &[Insn]) -> Vec<(i32, [Value; 3])> {
        let mut regs = [Value::Uninit; 11];
        regs[1] = Value::Context;
        regs[10] = Value::Stack;
        let mut calls = Vec::new();
        let mut index = 0;
        while index < program.len() {
            let insn = program[index];
            let (dst, src) = ((insn.regs & 0x0f) as usize, (insn.regs >> 4) as usize);
            match insn.code {
                0x61 => {
                    assert_eq!(regs[src], Value::Context, "load from the context only");
                    let off = insn.off as usize;
                    assert!(off.is_multiple_of(4) && off + 4 <= std::mem::size_of::<XdpMd>());
                    assert_ne!(dst, 10, "the frame pointer is read-only");
                    regs[dst] = Value::Scalar(None);
                }
                0x18 => {
                    assert_eq!(src, PSEUDO_MAP_FD as usize);
                    let next = program.get(index + 1).expect("a second slot");
                    assert_eq!(fields(*next), (0, 0, 0, 0, 0));
                    regs[dst] = Value::Map;
                    index += 1;
                }
                0xb7 => regs[dst] = Value::Scalar(Some(insn.imm as i64)),
                0x85 => {
                    calls.push((insn.imm, [regs[1], regs[2], regs[3]]));
                    for reg in &mut regs[1..=5] {
                        *reg = Value::Uninit;
                    }
                    regs[0] = Value::Scalar(None);
                }
                0x95 => {
                    assert!(matches!(regs[0], Value::Scalar(_)), "r0 set before exit");
                    assert_eq!(index, program.len() - 1, "exit ends the program");
                    return calls;
                }
                code => panic!("unexpected opcode {code:#x}"),
            }
            index += 1;
        }
        panic!("the program falls off its end");
    }

    #[test]
    fn program_redirects_by_queue_and_drops_without_a_socket() {
        let file = map();
        let calls = verify(&redirect_to_sockets(file.as_fd()));
        let [(helper, [map, key, flags])] = calls.as_slice() else {
            panic!("one helper call, got {calls:?}");
        };
        assert_eq!(*helper, Helper::RedirectMap as i32);
        assert_eq!(*map, Value::Map);
        assert_eq!(
            *key,
            Value::Scalar(None),
            "the key is read from the context"
        );
        let Value::Scalar(Some(flags)) = *flags else {
            panic!("flags must be a known constant");
        };
        assert_eq!(flags & 0b11, XDP_DROP as i64, "the fallback action");
        assert_eq!(flags & !0b11, 0, "no other flag bits");
    }
}
