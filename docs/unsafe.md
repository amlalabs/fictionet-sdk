# Unsafe code audit

Locations below refer to the starting tree, commit `6201666f3`, so removed sites
remain identifiable. New boundaries are named explicitly. Every unsafe block,
unsafe function, unsafe implementation and foreign block in workspace Rust
sources was inspected, including tests, benchmarks, build scripts and
feature-gated guest code. Target directories were excluded. An entry listing
several locations applies its verdict to each listed site.

The word `unsafe` in protocol descriptions, CSP strings and the code generator's
keyword table does not introduce Rust unsafe code. `extern crate` declarations
in verification modules are imports, not foreign blocks. Dependencies in Cargo's
cache are outside this inventory. Vendored crates are included.

## Policy

Pure crates forbid unsafe code through their Cargo lint configuration, covering
build scripts, examples and tests as well as their libraries: codegen and its
golden/layout fixtures, extras, both example worlds, smoltcp, the search app and
the nuclear world. Rustls already forbids it and is unchanged. Core and host
libraries, CLI, demo kit, search world, honeypot and xtask reject unsafe by default
in their crate roots, with commented exceptions at host or memory boundaries.
The guest-only xtask binary necessarily contains privileged setup calls.
Crates retaining unsafe deny `unsafe_op_in_unsafe_fn` and
`clippy::undocumented_unsafe_blocks`. The core library applies the latter in its
manifest so integration tests and benchmarks are covered too.

Unsafe does not mean runtime I/O is acceptable in protocol processing. The
existing core crate includes optional/runtime-facing listener, relay, clocks
and random-source boundaries; these are separate from protocol parsing. Its
TCP backing store also uses Linux anonymous mappings to reclaim empty queues.
Removing those facilities or changing their allocation behavior is outside a
behavior-preserving audit.

## Command line crate

The CLI has no unsafe functions or implementations. Its one C-ABI function is a
signal handler, not a foreign declaration. Raw descriptor arguments to read,
write and poll do not by themselves create Rust memory unsafety: the kernel
validates them. Ownership conversions, buffer validity and syscall-specific
argument sizes are the critical obligations.

| Original site | Verdict and invariant |
| --- | --- |
| `cli/src/blocked.rs:114`, `cli/src/blocked.rs:122` | Keep: socket creation takes only scalars; failure is checked, and the fresh descriptor is closed exactly once before connection probing. There is no std API for creating an unconnected TCP socket for this capability probe. |
| `cli/src/linux.rs:14` | Keep in the Linux boundary: the namespace file stays open for setns; no retained pointers. The only caller enters before spawning threads. |
| `cli/src/linux.rs:36`, `cli/src/linux.rs:45` | Remove: OpenOptions with O_NONBLOCK and safe OwnedFd conversion supplies the same open mode and close-on-exec ownership. |
| `cli/src/linux.rs:81` | Keep: mknod receives a static terminated path and scalar mode/device. No std character-device creation API. |
| `cli/src/linux.rs:105`, `cli/src/tap/device.rs:73` | Wrap: one `linux::set_tun_interface` accepts a complete mutable 40-byte request and borrowed owner. Both callers initialize the name and flag bytes. Linux copies ifreq bytes; it does not dereference a Rust reference to a misaligned typed object. |
| `cli/src/linux.rs:112` | Keep: TUNGETIFF writes within the same initialized ifreq buffer. Only invoked when the kernel omitted a name. |
| `cli/src/linux.rs:127` | Keep: CString owns a terminated name throughout if_nametoindex. Invalid embedded NUL currently panics before FFI, not memory unsafety. |
| `cli/src/tun.rs:261`, `cli/src/tap.rs:302`, `cli/src/tap/qemu.rs:235` | Wrap in `linux::poll`: slice length determines nfds; the kernel can only update those initialized entries. Timeout and errno handling are unchanged at callers. |
| `cli/src/tun.rs:273` | Wrap in `linux::write`: the packet slice remains readable for its length. The caller still treats write failure as a dropped packet. |
| `cli/src/tun.rs:292`, `cli/src/tap.rs:399`, `cli/src/tap.rs:432` | Wrap in `linux::read`: unique initialized destination slice, matching pointer and length. Callers inspect negative results before converting to lengths. |
| `cli/src/tap.rs:216` | Wrap in `linux::write_packet`: two iovecs borrow live header/payload slices; writev only reads them and returns before either borrow expires. File ownership remains in Port. |
| `cli/src/tap/device.rs:212`, `cli/src/tap/device.rs:216` | Keep: abstract device lock requires seqpacket, absent from std UnixStream. Socket success is checked before one ownership conversion. |
| `cli/src/tap/device.rs:219`, `cli/src/tap/device.rs:227` | Keep: zero is valid sockaddr_un storage; the abstract name is bounded by a decimal u32 index and fits sun_path. bind receives precisely its initialized prefix. |
| `cli/src/tap/qemu.rs:78` | Remove: File::try_lock provides the existing nonblocking exclusive flock, retaining the file as OwnedFd after success. WouldBlock keeps its diagnostic. |
| `cli/src/tap/qemu.rs:132`, `cli/src/tap/qemu.rs:142` | Keep: nonblocking close-on-exec socket with explicit backlog and permissions; creation failure is checked before ownership. |
| `cli/src/tap/qemu.rs:153`, `cli/src/tap/qemu.rs:154`, `cli/src/tap/qemu.rs:156` | Keep: umask is scalar, address() bounds and terminates the address, bind borrows it synchronously. The old mask is restored before inspecting the result. Startup is single threaded; using this routine after spawning threads would violate its permissions assumption, though not Rust memory safety. |
| `cli/src/tap/qemu.rs:182` | Keep: listen takes a live owned socket and scalar backlog. Std's fixed backlog would alter behavior. |
| `cli/src/tap/qemu.rs:247`, `cli/src/tap/qemu.rs:267` | Keep: accept4 requests no peer-address output, sets CLOEXEC/NONBLOCK atomically, checks all errors before taking unique ownership. |
| `cli/src/tap/qemu.rs:281` | Keep: outbox pending bytes stay borrowed during send; NOSIGNAL/DONTWAIT retain the required error behavior. |
| `cli/src/netlink.rs:462`, `cli/src/netlink.rs:472` | Keep in Netlink: socket failure checked before unique ownership; std has no route-netlink socket API. |
| `cli/src/netlink.rs:474`, `cli/src/netlink.rs:476` | Keep: zero-valid sockaddr_nl, correct family and exact struct size; bind does not retain the pointer. |
| `cli/src/netlink.rs:491`, `cli/src/netlink.rs:493` | Keep: zero-valid kernel address and borrowed serialized message are readable for exactly the lengths passed to sendto. |
| `cli/src/netlink.rs:513` | Keep: recv writes within the exclusive buffer; only nonnegative lengths index it. |
| `cli/src/lifecycle.rs:116` | Keep C ABI: handler signature matches signal; it cannot unwind and terminates with _exit. |
| `cli/src/lifecycle.rs:121` | Keep: OnceLock::get is nonblocking and only exposes a fully initialized, immutable, permanently retained CString. unlink is async-signal-safe. |
| `cli/src/lifecycle.rs:129` | Keep: lstat fills a complete local stat; its result gates field use. Published inode/path data remain immutable and atomic flags need no lock. lstat/unlink are signal-safe. The inode comparison is best-effort path cleanup, not protection against a hostile rename between calls. |
| `cli/src/lifecycle.rs:142` | Keep separate signal path: socket/sendto/close are async-signal-safe, the published message never changes or reallocates, and sockaddr_nl is initialized with exact length. Ordinary allocating Netlink methods must not be called here. |
| `cli/src/lifecycle.rs:164`, `cli/src/lifecycle.rs:168` | Keep: _exit does not run destructors; signal installs a correctly typed handler. Corrected the old comment claiming the handler only called _exit. |
| `cli/src/proxy/link.rs:64` | Keep: AsyncFd owns OwnedFd with a stable descriptor until deregistration. The pinned Tokio version deprecates its nominally safe `new` as unsound, so explicit register is appropriate. |
| `cli/src/proxy/link.rs:254` | Keep test fixture: two-int writable array, socketpair success asserted before either ownership conversion, each descriptor owned once. |
| `cli/benches/services.rs:38`, `cli/benches/services.rs:49` | Keep: same checked socketpair invariant, CLOEXEC prevents leaked endpoints into subprocesses. Std stream pairs change packet boundaries. |
| `cli/tests/it/tap_bin.rs:516`, `cli/tests/it/tap_bin.rs:529` | Keep fixture: socket/accept success checked before ownership; bounded address, exact bind length and null accept outputs. |
| `cli/tests/it/proxy.rs:495` | Keep: linger is an initialized struct with the exact SO_LINGER size, and the live socket remains owned. This deliberately injects connection reset. |
| `cli/tests/it/proxy.rs:1317` | Keep: checked fresh socket, bounded address, correct bind size and backlog. |
| `cli/tests/it/proxy.rs:1330` | Real ownership-contract bug, fixed: accept4 could return -1 and was immediately passed to OwnedFd::from_raw_fd. Check success first, then convert once. The oversized-handshake test exercises the helper's successful path; deliberately executing the old invalid ownership conversion is not a safe regression test. |
| `cli/tests/it/attach_bin.rs:122` | Keep: pre_exec closure only uses signal/setrlimit and last_os_error, with initialized scalar/struct arguments; no allocation or locks after fork. Resource limits apply to its child only. |

## Demo kit

| Original site | Verdict and invariant |
| --- | --- |
| `demos/kit/src/kit/vm/mod.rs:194` | Keep in own_child: pre_exec closure contains only scalar prctl/setpgid/getppid/_exit calls and errno conversion. Captures are plain values; parent-death race is checked before exec. |
| `demos/kit/src/kit/vm/mod.rs:229` | Keep: geteuid has no pointer or Rust storage effects. Moved into a named local with a direct safety comment. |
| `demos/kit/src/kit/vm/mod.rs:242` | Keep: inheritance hook only calls fcntl and errno conversion after fork. The Ownership file stays live through spawn at both callers; dropping it prematurely can invalidate the intended lock inheritance, not create a Rust reference violation. |
| `demos/kit/src/kit/vm/mod.rs:260`, `demos/kit/src/kit/vm/mod.rs:265` | Keep: terminated static memfd name, checked result, one owning conversion. Std cannot request an anonymous sealable executable. |
| `demos/kit/src/kit/vm/mod.rs:269` | Remove: File::write_all writes the embedded executable through a safe owned File, then safe conversion returns the descriptor. |
| `demos/kit/src/kit/vm/mod.rs:283` | Keep: scalar F_ADD_SEALS on the owned file after writes finish; no retained pointers. |
| `demos/kit/src/kit/shot.rs:339`, `xtask/src/capture/render.rs:279` | Wrap once in `kit::shot::devtools_pipe`: pre_exec duplicates both source descriptors above four before overwriting three/four. fcntl/dup2 are async-signal-safe, captures are scalars, and callers keep source owners through spawn. Xt tool now uses the same hook through as_std_mut. |
| `demos/kit/src/kit/shot.rs:425` | Keep: DevTools owns the pipe outside this raw-descriptor reader and keeps it alive; chunk is exclusively writable for its length. |
| `demos/kit/src/kit/shot.rs:450`, `demos/kit/src/kit/shot.rs:454` | Remove: std::io::pipe and safe ownership conversions preserve close-on-exec pipe endpoints. |
| `demos/kit/src/kit/shot.rs:464` | Keep: write loop borrows live command bytes including the terminator; the owner remains alive, and every positive result advances within the supplied length. |
| `demos/kit/src/kit/shot.rs:488` | Keep: one initialized pollfd with exact count one and bounded timeout; result is inspected before reading. |

## Search world and honeypot

| Original site | Verdict and invariant |
| --- | --- |
| `demos/search/world/src/pages/copied/reference.rs:54`, `demos/search/world/src/pages/copied/reference.rs:57`, `xtask/src/web.rs:23`, `xtask/src/web.rs:26` | Wrap once in `fictionet_host::filesystem::available_space`, behind the filesystem feature. CString is terminated; MaybeUninit provides aligned full-size output; assume_init happens only after statvfs succeeds. Std has no capacity query. |
| `demos/search/world/src/pages/copied/git.rs:167` | Keep: kill takes scalar process-group id; backend is launched in its own group and the child owner waits after termination. No pointer invariants. |
| `demos/search/world/src/pages/copied/git.rs:179` | Keep: fcntl uses F_SETFL with scalar O_NONBLOCK on owned stdin/stdout pipes. These fresh pipes have no other mutable status flags to preserve. |
| `demos/search/world/src/pages/copied/git.rs:206` | Keep in Backend::exchange: poll count matches its three-element mutable array; each active descriptor's owner remains live and disabled entries use -1. |
| `demos/honeypot/src/deploy.rs:320`, `demos/honeypot/src/deploy.rs:359` | Wrap once in `effective_uid`: geteuid takes no pointers or mutable Rust storage. The state directory and secret-file permission checks remain unchanged. |
| `demos/honeypot/src/evidence.rs:1366`, `demos/honeypot/src/evidence.rs:1378` | Keep test-only: initialized rlimit output/input, getrlimit success checked before reuse, valid SIG_IGN sentinel. Test runs in a dedicated child so its limits and signal disposition cannot affect other tests. Restored limit precedes recovery writes. |

## Development tooling and guest entry point

Guest code is inventoried by inspection and compilation only. No XDP, AF_XDP,
VFIO device opening, raw guest exercise, VM launch or privileged network setup
was run on this host.

| Original site | Verdict and invariant |
| --- | --- |
| `xtask/src/ssh_connect.rs:57`, `xtask/src/ssh_connect.rs:239` | Keep: AsyncFd takes the OwnedFd/File by value; the number remains stable through deregistration. Caller sets nonblocking first. stdin is duplicated, so ownership is independent even though status flags share its open-file description. |
| `xtask/src/rawnic_world.rs:242`, `xtask/src/rawnic_world.rs:247` | Keep guest-only: inotify_init1 takes scalar flags, checks failure, transfers one fresh descriptor into File. |
| `xtask/src/rawnic_world.rs:249` | Keep: static terminated watch path and open inotify descriptor; no retained Rust pointer. |
| `xtask/src/rawnic_world.rs:304` | Keep: scalar kill on the still-unreaped child after try_wait; preserves graceful SIGTERM rather than changing to Child::kill's SIGKILL. |
| `xtask/src/rawnic_world.rs:368` | Keep private ioctl wrapper: all call sites pass the complete initialized 40-byte ifreq and use only TUNSETIFF, SIOCSIFMTU, SIOCGIFFLAGS or SIOCSIFFLAGS, whose payloads fit it. Not a public arbitrary-ioctl API. |
| `xtask/src/rawnic_world.rs:376` | Keep: CStr guarantees termination for if_nametoindex. |
| `xtask/src/rawnic_world.rs:394`, `xtask/src/rawnic_world.rs:405` | Keep: AF_PACKET datagram socket requires FFI; success checked before File takes unique ownership. |
| `xtask/src/rawnic_world.rs:407`, `xtask/src/rawnic_world.rs:412` | Keep: zero-valid sockaddr_ll, initialized family/protocol/index, correct struct length for bind. |
| `xtask/src/rawnic_world.rs:424` | Keep: setsockopt borrows one initialized integer with its exact size. |
| `xtask/src/rawnic_world.rs:440` | Keep: expected packet and sockaddr_ll remain readable at exact lengths through sendto. |
| `xtask/src/rawnic_world.rs:454` | Keep: AsyncFd owns a nonblocking File and cannot change its descriptor during registration. |
| `xtask/src/rawnic_world.rs:506`, `xtask/src/rawnic_world.rs:543` | Keep: TUNSETPERSIST takes an integer, not a pointer; correct owned guest-only device and scalar values one/zero. |
| `xtask/src/egress.rs:326` | Keep: zero-valid libc ifreq then initialized terminated interface name and address union member. |
| `xtask/src/egress.rs:340` | Remove: construct sockaddr's port/address bytes directly instead of transmuting sockaddr_in. The four IPv4 octets occupy data bytes two through five, after the zero port. |
| `xtask/src/egress.rs:342` | Keep: only SIOCSIFADDR and SIOCSIFNETMASK are passed, with initialized complete request and live control socket. |
| `xtask/src/bin/rawnic-guest.rs:15` | Keep in private mount helper: terminated source/target/type strings, null optional data, zero flags. Only proc, sysfs and devtmpfs calls. |
| `xtask/src/bin/rawnic-guest.rs:53` | Keep: init_module receives readable owned image bytes with exact length and terminated empty parameters. Called only after PID/QEMU/command-line gating. |
| `xtask/src/bin/rawnic-guest.rs:69` | Keep: zero is a valid ifreq representation and supplies termination after the loopback name. |
| `xtask/src/bin/rawnic-guest.rs:73`, `xtask/src/bin/rawnic-guest.rs:76`, `xtask/src/bin/rawnic-guest.rs:79` | Keep: get-flags writes the complete request, success gates reading its union member, and set-flags receives initialized flags on a live socket. |
| `xtask/src/bin/rawnic-guest.rs:145` | Keep guest-only: ioperm gates the x86 output instruction; register-only asm does not touch Rust memory. Explicit marked guest exits through its configured test port. Never exercised by this audit. |
| `xtask/src/bin/rawnic-guest.rs:152` | Keep guest-only: reboot takes a scalar command and no pointers, guarded by successful guest identification. |

## Root tests and shared benchmark support

| Original site | Verdict and invariant |
| --- | --- |
| `tests/support/bench/http.rs:36` | Keep in cpu_us: full aligned rusage output, getrusage success asserted before assume_init. No portable std CPU-time query. |
| `tests/it/common/alloc.rs:59` | Keep GlobalAlloc implementation: accepted allocations use System, rejected allocations return null, deallocation always uses the original pointer/layout. Constant TLS cells and saturating arithmetic do not allocate, recurse or unwind. |
| `tests/it/common/alloc.rs:60`, `tests/it/common/alloc.rs:65` | Keep unsafe allocation entry and call: caller's nonzero valid Layout forwarded unchanged to System; null stays a valid failure result. |
| `tests/it/common/alloc.rs:78`, `tests/it/common/alloc.rs:80` | Keep unsafe deallocation entry and call: caller's live allocation and matching layout forwarded unchanged; accounting cannot invalidate storage. |
| `tests/it/common/alloc.rs:83`, `tests/it/common/alloc.rs:88` | Keep unsafe reallocation entry and call: caller supplies valid original allocation/layout and nonzero representable new size. Refusal leaves the original allocation alive. |
| `tests/it/fd_limit.rs:45`, `tests/it/fd_limit.rs:107` | Keep: initialized full rlimit output. Added an assertion for the previously unchecked first getrlimit, preventing an invalid test setup after syscall failure. |
| `tests/it/fd_limit.rs:50`, `tests/it/fd_limit.rs:114` | Keep: initialized limits within the saved hard limit, isolated subprocesses, no retained pointers. |
| `tests/it/fd_limit.rs:65`, `tests/it/fd_limit.rs:118` | Keep: restore the initialized saved limit. The previously unchecked restoration now asserts success. |
| `tests/it/fd_limit.rs:174` | Keep: live owned socket, scalar SHUT_WR, no pointer arguments. Deliberately exercises half-close. |
| `tests/host/tun_linux.rs:38` | Keep test-only: packet slice remains readable and Arc keeps its TUN descriptor owned during write. |
| `tests/host/tun_linux.rs:49`, `tests/host/tun_linux.rs:55` | Remove: OpenOptions and safe OwnedFd conversion replace raw open and unchecked ownership coupling. |
| `tests/host/tun_linux.rs:60` | Keep test-only: full initialized ifreq buffer, fixed TUNSETIFF command and live owner. Slice copy checks the name fits storage before FFI. |
| `tests/host/tun_linux.rs:71` | Keep test-only: exclusive buffer, exact length, Arc keeps reader fd alive, nonpositive results end the thread before indexing. Privileged test was not executed. |

## Core runtime and transport

| Original site | Verdict and invariant |
| --- | --- |
| `src/sys.rs:26` | Keep in sys: getrandom receives the exact live mutable slice, retries EINTR and advances only by the returned byte count. Browser getrandom::fill is already safe. A native getrandom dependency could replace this, but is not currently a direct native dependency. |
| `src/listen.rs:173`, `src/listen.rs:174` | Keep in listener: epoll_create1/eventfd results pass cvt before OwnedFd consumes each fresh descriptor; failure paths retain RAII ownership. |
| `src/listen.rs:217` | Keep: epoll_ctl gets a complete initialized event whose lifetime covers the call; its token is an integer, not a borrowed pointer. |
| `src/listen.rs:223` | Keep: accept4 supplies null address/length outputs, checks failure before OwnedFd, and atomically requests close-on-exec/nonblocking flags. |
| `src/listen.rs:240`, `src/listen.rs:258` | Keep: bind uses validated unix::address storage and its bounded length; listen takes only scalar arguments. |
| `src/listen.rs:292` | Keep: eventfd write reads one live u64; Shared retains the owning descriptor until users finish. |
| `src/listen.rs:444` | Keep: epoll_wait gets initialized output entries with their exact count and only its returned prefix is inspected. |
| `src/listen.rs:461` | Keep: eventfd read gets an exclusive eight-byte buffer; the owner outlives the helper thread. |
| `src/relay/unix.rs:24` | Keep: setsockopt borrows an initialized timeval with its exact size. Current callers use SO_RCVTIMEO/SO_SNDTIMEO; this public helper accepts an option integer, but the kernel bounds any read by the supplied length. |
| `src/relay/unix.rs:40` | Keep: zero is valid sockaddr_un storage; checked path copying bounds its length and preserves NUL termination. |
| `src/relay/unix.rs:82` | Keep: setsockopt borrows one initialized integer with its exact size; neither fallback retains the pointer. |
| `src/relay/unix.rs:105`, `src/relay/unix.rs:106` | Keep: socket creation error checked before adopting the new descriptor once. |
| `src/relay/unix.rs:115` | Keep: connect borrows the validated exact sockaddr length for the call. |
| `src/relay/unix.rs:129`, `src/relay/unix.rs:135` | Keep: integer-only fcntl preserves existing flags except the requested nonblocking bit. |
| `src/relay/unix.rs:168`, `src/relay/unix.rs:177` | Keep: zero-valid msghdr is populated with initialized iovecs borrowing live message slices for sendmsg. No pointers are retained or mutable input exposed to the kernel. |
| `src/relay/unix.rs:197` | Keep: recv receives an exclusive slice pointer and exact capacity; nonnegative result is bounded by that capacity. |
| `src/relay/unix.rs:211` | Keep: shutdown takes scalar arguments, neither transfers ownership nor touches Rust memory. |
| `src/timer.rs:212` | Keep foreign block: wasm-bindgen import for JavaScript setTimeout, not a handwritten native ABI call. Thread-local Closure remains alive for all callbacks during the module lifetime. |
| `src/cx/timer.rs:206`, `src/cx/timer.rs:208`, `src/cx/timer.rs:209` | Keep test-only clone callback and blocks: raw data points to a live Arc Gate; cloning increments its count before borrowing Gate. Custom RawWaker intercepts cloning to enforce the race window; Wake cannot replace this side effect. |
| `src/cx/timer.rs:216`, `src/cx/timer.rs:217`, `src/cx/timer.rs:218` | Keep test-only wake callback and blocks: wake_by_ref borrows the still-owned count, then release consumes it exactly once. |
| `src/cx/timer.rs:220`, `src/cx/timer.rs:222` | Keep test-only borrowed wake callback and block: caller retains a strong count; Gate contains thread-safe synchronization. |
| `src/cx/timer.rs:226`, `src/cx/timer.rs:228` | Keep test-only release callback and block: each raw Waker owns one count transferred from Arc or added by clone. |
| `src/cx/timer.rs:247` | Keep test-only construction: each initial raw Arc transfers one count into the matching vtable. A timeout panic can leak a count but cannot double release it. Unsafe permission is scoped to this regression test. |

## TCP backing store

| Original site | Verdict and invariant |
| --- | --- |
| `src/stdlib/network/tcp/engine.rs:545` | Keep Send: Pages owns its mapping, is not Sync, and moves with its owning layer. Socket accesses are serialized. |
| `src/stdlib/network/tcp/engine.rs:554` | Keep, harden constructor: fresh private writable anonymous mapping; check MAP_FAILED. Added checked multiplication, nonzero/isize bounds, and rejection/unmapping of a successful null address before creating slices. Public buffer options already clamp sizes, so no public oversized-allocation exploit was found. |
| `src/stdlib/network/tcp/engine.rs:571` | Keep: MADV_NOHUGEPAGE covers the live owned allocation and prevents neighboring queues sharing reclamation costs. |
| `src/stdlib/network/tcp/engine.rs:585`, `src/stdlib/network/tcp/engine.rs:589`, `src/stdlib/network/tcp/engine.rs:663` | Keep private lending contract: exactly one pair of initialized, nonoverlapping u8 slices is handed to exactly one socket. Explicitly document that halves must be called only once. All current callers comply. Socket storage is declared before pages for destruction order, removal removes the socket first, and compaction moves sockets without unmapping. |
| `src/stdlib/network/tcp/engine.rs:606`, `src/stdlib/network/tcp/engine.rs:610`, `src/stdlib/network/tcp/engine.rs:832` | Keep with the limitation below: release_quiet requires empty receive/send queues and no out-of-order assembler data. Every current call passes these checks before MADV_DONTNEED. |
| `src/stdlib/network/tcp/engine.rs:619` | Keep test-only: mincore output has initialized space for one byte per page; accounting assumes 4096-byte pages on the tested Linux host. |
| `src/stdlib/network/tcp/engine.rs:629` | Keep: munmap owns precisely the original mapping, after its borrowed socket buffers have been removed or dropped. |
| `src/stdlib/network/tcp/engine.rs:645`, `src/stdlib/network/tcp/engine.rs:650` | Keep unreachable wasm compatibility signatures: Pages is uninhabited on wasm, so these functions cannot execute an unsafe memory operation. They preserve the shared host call contract without adding another conditional path. |

The mmap lifetime remains manually enforced by a private tuple return rather
than encoded structurally. MADV_DONTNEED changes bytes through the original mmap
address while long-lived mutable slices exist inside smoltcp. Empty-buffer
checks establish logical data lifetime, but strict alias/provenance treatment
of this OS reclamation is an unresolved model question, not a demonstrated bug
or a proof of soundness. A stronger design would obtain reclamation pointers
from current exclusive buffer borrows. No Miri validation is claimed.

## Host crate

| Original site | Verdict and invariant |
| --- | --- |
| `host/src/tun.rs:110` | Keep: AsyncFd owns its O_NONBLOCK File with an unchanging descriptor until deregistration. The pinned Tokio's deprecated safe new is not an appropriate replacement. |
| `host/src/tun.rs:174` | Keep private wrapper: all callers select matching TUN/interface commands with a complete initialized ifreq byte buffer; no arbitrary external request enters it. Kernel byte copies do not create misaligned Rust references. |
| `host/src/virtio.rs:91` | Keep private VFIO wrapper: callers pass scalar constants for API/extension/IOMMU/reset, initialized repr(C) structures for status/info/region/map/unmap, a live descriptor pointer for set-container, or a terminated CString for device lookup. Request/payload pairing remains a manual private invariant. |
| `host/src/virtio.rs:151` | Keep and harden: mmap failure checked; a successful null address is now unmapped before returning an error. |
| `host/src/virtio.rs:173`, `host/src/virtio.rs:185` | Unsound safe abstraction, fixed: generic T: Copy permits invalid bool/reference bit patterns, and offset addition could overflow. Replace with integer-width read/write methods, checked bounds and actual pointer alignment. Current callers previously used only unsigned integers; no invalid-type production call was found. Preserve volatile register access widths. |
| `host/src/virtio.rs:197` | Keep: Mapping uniquely owns the original mapping and unmaps it once. |
| `host/src/virtio.rs:291` | Keep Send, not Sync: mappings/descriptors have no thread affinity; mutable queue API serializes driver accesses. Hardware concurrency is governed by volatile integer access, descriptor ownership and fences. This is a QEMU-gated x86 driver, not a proof against arbitrary malicious hardware. |
| `host/src/virtio.rs:356` | Keep: device-fd ioctl success checked before File adopts unique ownership. |
| `host/src/tests.rs:137` | Keep test-only: scalar listen changes the backlog on a live TcpListener. Scoped unsafe exception for the unanswered fixture. |

The new `host/src/filesystem.rs` owns the two statvfs unsafe operations formerly
in the search world and xtask. It passes terminated path storage and aligned
writable output, checks success, then reads initialized fields. No generic
foreign-call framework, added dependency or runtime registry is needed.

## Vendored and remaining sources

`rustls/src/lib.rs:300` already has `#![forbid(unsafe_code, unused_must_use)]`.
There are no unsafe blocks, unsafe functions, unsafe implementations or native
foreign blocks in this fork. Mentions in `client/client_conn.rs:560`,
`client/builder.rs:88`, `manual/features.rs:75` and crate prose describe dangerous
certificate-verifier configuration, not Rust memory unsafety. No vendor code
was changed.

Smoltcp contains no unsafe sites. Verification Rust files only import
`extern crate alloc`; no unsafe operations or foreign blocks were found.
Codegen's keyword strings include `unsafe` and `extern` without emitting an
unsafe construct. The excluded fuzz package contains no unsafe Rust site;
workspace lint policy does not automatically apply to that separate workspace.

## Replacement boundary locations

These locations are in the audited final source rather than the starting tree.
They identify new unsafe blocks separately from the removed or moved sites above.

| Current site | Verdict and invariant |
| --- | --- |
| `cli/src/linux.rs:130` | Wrap: set_tun_interface owns the one TUNSETIFF call; borrowed descriptor and full mutable ifreq buffer. |
| `cli/src/linux.rs:141` | Wrap: poll derives its count from the mutable initialized slice. |
| `cli/src/linux.rs:147`, `cli/src/linux.rs:153` | Wrap: read/write derive pointers and lengths from exclusive/shared byte slices and preserve syscall results. |
| `cli/src/linux.rs:164` | Wrap: write_packet constructs two live iovecs and performs one writev. |
| `host/src/filesystem.rs:11`, `host/src/filesystem.rs:15` | Wrap: checked statvfs success precedes initialization assertion on aligned output storage. |
| `host/src/virtio.rs:148`, `host/src/virtio.rs:155`, `host/src/virtio.rs:210` | Keep corrected typed boundary: unsigned integer-only volatile access after checked range and actual pointer alignment. Macro expansions provide reads/writes for u8/u16/u32; only a write is needed for u64. |
| `host/src/virtio.rs:185`, `src/stdlib/network/tcp/engine.rs:577` | Keep defensive cleanup: successful null mappings are unmapped rather than leaking or constructing invalid Rust slices. |
| `demos/honeypot/src/deploy.rs:307` | Wrap: effective_uid owns the scalar-only geteuid call formerly repeated in permission checks. |

## Validation

All Cargo commands used the requested `systemd-run --user --scope -q
--slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0` scope with
`CARGO_BUILD_JOBS=8` and
`CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-unsafe`.
After a build exhausted disk space, `cargo clean -p fictionet` removed only
this audit target's disposable core build artifacts. Subsequent builds used
`CARGO_INCREMENTAL=0`. No source or unrelated target directory was removed.

Passed checks:

- `cargo check --workspace --all-targets --all-features`, covering every changed
  crate, build script, test and benchmark target, including guest code without
  executing it.
- `cargo clippy --workspace --all-targets --all-features`, with the new unsafe
  lint policies enabled. Core/host libraries also passed Clippy with warnings
  denied.
- `cargo check -p fictionet --lib --target wasm32-unknown-unknown`, confirming
  that the existing wasm-bindgen timer import works with the new policy.
- `cargo fmt --all -- --check`.
- `cargo doc --workspace --all-features --no-deps`.
- `cargo bench -p fictionet-cli --bench services --no-run --profile test`.
  This compiled the benchmark; no performance result is claimed.

Only selected tests ran, 24 unique tests in total:

- Three core library tests: `mappings_reject_lengths_that_cannot_form_slices`,
  `quiet_connections_give_their_buffer_pages_back`, and
  `a_lab_clock_never_moves_back_for_a_deadline_set_from_another_thread`.
- Eight host `virtio::tests`: anonymous memory, queue ownership and parser tests
  only. The new fixed-width test checks value preservation, alignment, bounds
  and overflowing aligned offsets. It does not open VFIO or any device.
- Five CLI `tap_bin::` tests using ordinary Unix sockets and a fake QEMU peer.
- CLI `proxy::an_oversized_answer_to_hello_is_an_error_not_a_refusal`.
- Three demo-kit process tests and the Chromium canvas/condition-timeout test,
  exercising the shared descriptor hook and standard pipes.
- Honeypot `deploy::tests::state_persists_identity_key_and_prevents_concurrent_use`.
- Two root `fd_limit::` tests, isolated in child processes.

The new mapping-length test would fail on the old unchecked multiplication for
oversized lengths. The private invalid-type MMIO defect was established by
source/type-contract review, not by executing an invalid bool/reference value.
Likewise, no test intentionally constructs an invalid OwnedFd to reproduce the
old accept failure. Tests of the corrected boundaries supplement the audit;
they do not prove all unsafe invariants or hardware behavior.

No full test suite, Kani, TLA+, Lean, XDP, AF_XDP, VFIO workload or privileged
TUN test was run. Vendored rustls was documented without code changes. Changes
are committed on the audit branch; nothing was merged or pushed.
