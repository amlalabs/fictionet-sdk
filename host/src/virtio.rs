//! Polling raw Ethernet over a modern virtio network device assigned to VFIO.
//!
//! This driver is restricted to an explicitly opted-in QEMU guest. The guest
//! administrator must bind the intended device to vfio-pci before opening it.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, fence};

// Linux VFIO UAPI request numbers and flags.
const VFIO_TYPE: libc::c_ulong = (b';' as libc::c_ulong) << 8;
const VFIO_GET_API_VERSION: libc::c_ulong = VFIO_TYPE | 100;
const VFIO_CHECK_EXTENSION: libc::c_ulong = VFIO_TYPE | 101;
const VFIO_SET_IOMMU: libc::c_ulong = VFIO_TYPE | 102;
const VFIO_GROUP_GET_STATUS: libc::c_ulong = VFIO_TYPE | 103;
const VFIO_GROUP_SET_CONTAINER: libc::c_ulong = VFIO_TYPE | 104;
const VFIO_GROUP_GET_DEVICE_FD: libc::c_ulong = VFIO_TYPE | 106;
const VFIO_DEVICE_GET_INFO: libc::c_ulong = VFIO_TYPE | 107;
const VFIO_DEVICE_GET_REGION_INFO: libc::c_ulong = VFIO_TYPE | 108;
const VFIO_DEVICE_RESET: libc::c_ulong = VFIO_TYPE | 111;
const VFIO_IOMMU_MAP_DMA: libc::c_ulong = VFIO_TYPE | 113;
const VFIO_IOMMU_UNMAP_DMA: libc::c_ulong = VFIO_TYPE | 114;
const VFIO_API_VERSION: i32 = 0;
const VFIO_TYPE1_IOMMU: usize = 1;
const VFIO_GROUP_FLAGS_VIABLE: u32 = 1 << 0;
const VFIO_DEVICE_FLAGS_PCI: u32 = 1 << 1;
const VFIO_REGION_INFO_FLAG_READ: u32 = 1 << 0;
const VFIO_REGION_INFO_FLAG_WRITE: u32 = 1 << 1;
const VFIO_REGION_INFO_FLAG_MMAP: u32 = 1 << 2;
const VFIO_DMA_MAP_FLAG_READ: u32 = 1 << 0;
const VFIO_DMA_MAP_FLAG_WRITE: u32 = 1 << 1;
const VFIO_PCI_CONFIG_REGION_INDEX: u32 = 7;

// PCI configuration space and modern virtio common configuration offsets.
const PCI_COMMAND: usize = 0x04;
const PCI_COMMAND_MEMORY: u16 = 0x2;
const PCI_COMMAND_MASTER: u16 = 0x4;
const PCI_STATUS: usize = 0x06;
const PCI_STATUS_CAP_LIST: u16 = 0x10;
const PCI_CAPABILITY_LIST: usize = 0x34;
const PCI_CAP_ID_VNDR: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const VIRTIO_PCI_COMMON_DFSELECT: usize = 0;
const VIRTIO_PCI_COMMON_DF: usize = 4;
const VIRTIO_PCI_COMMON_GFSELECT: usize = 8;
const VIRTIO_PCI_COMMON_GF: usize = 12;
const VIRTIO_PCI_COMMON_STATUS: usize = 20;
const VIRTIO_PCI_COMMON_CFGGENERATION: usize = 21;
const VIRTIO_PCI_COMMON_Q_SELECT: usize = 22;
const VIRTIO_PCI_COMMON_Q_SIZE: usize = 24;
const VIRTIO_PCI_COMMON_Q_MSIX: usize = 26;
const VIRTIO_PCI_COMMON_Q_ENABLE: usize = 28;
const VIRTIO_PCI_COMMON_Q_NOFF: usize = 30;
const VIRTIO_PCI_COMMON_Q_DESCLO: usize = 32;
const VIRTIO_PCI_COMMON_Q_AVAILLO: usize = 40;
const VIRTIO_PCI_COMMON_Q_USEDLO: usize = 48;
const VIRTIO_CONFIG_S_ACKNOWLEDGE: u8 = 1;
const VIRTIO_CONFIG_S_DRIVER: u8 = 2;
const VIRTIO_CONFIG_S_DRIVER_OK: u8 = 4;
const VIRTIO_CONFIG_S_FEATURES_OK: u8 = 8;
const VIRTIO_CONFIG_S_RESET: u8 = 0;
const DRIVER_STARTED: u8 = VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;
const FEATURES_ACCEPTED: u8 = DRIVER_STARTED | VIRTIO_CONFIG_S_FEATURES_OK;
const DRIVER_READY: u8 = FEATURES_ACCEPTED | VIRTIO_CONFIG_S_DRIVER_OK;
const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_ACCESS_PLATFORM: u32 = 33;
const PLATFORM_FEATURES: u32 =
    (1 << (VIRTIO_F_VERSION_1 - 32)) | (1 << (VIRTIO_F_ACCESS_PLATFORM - 32));
const VRING_DESC_F_WRITE: u16 = 2;
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

const DMA_SIZE: usize = 2 * 1024 * 1024;
const IOVA: u64 = 0x1000_0000;
const BUFFER_SIZE: usize = 2048;
const HEADER_SIZE: usize = 12;
const QUEUE_SIZE: u16 = 256;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn ioctl(fd: RawFd, request: libc::c_ulong, argument: usize) -> io::Result<i32> {
    // SAFETY: Callers provide the ABI argument required by each VFIO request.
    let result = unsafe { libc::ioctl(fd, request, argument) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[repr(C)]
struct GroupStatus {
    argsz: u32,
    flags: u32,
}
#[repr(C)]
struct DeviceInfo {
    argsz: u32,
    flags: u32,
    regions: u32,
    irqs: u32,
}
#[repr(C)]
#[derive(Default)]
struct RegionInfo {
    argsz: u32,
    flags: u32,
    index: u32,
    cap_offset: u32,
    size: u64,
    offset: u64,
}
#[repr(C)]
struct DmaMap {
    argsz: u32,
    flags: u32,
    vaddr: u64,
    iova: u64,
    size: u64,
}
#[repr(C)]
struct DmaUnmap {
    argsz: u32,
    flags: u32,
    iova: u64,
    size: u64,
}

struct Mapping {
    pointer: NonNull<u8>,
    length: usize,
}
impl Mapping {
    fn new(fd: RawFd, offset: u64, length: usize, anonymous: bool) -> io::Result<Self> {
        let offset =
            libc::off_t::try_from(offset).map_err(|_| invalid("mapping offset overflow"))?;
        let flags = if anonymous {
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
        } else {
            libc::MAP_SHARED
        };
        // SAFETY: mmap owns a fresh mapping; the returned pointer is checked.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd,
                offset,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pointer: NonNull::new(pointer.cast()).ok_or_else(|| invalid("null mapping"))?,
            length,
        })
    }
    fn read<T: Copy>(&self, offset: usize) -> T {
        assert!(offset + size_of::<T>() <= self.length);
        assert!(offset.is_multiple_of(align_of::<T>()));
        // SAFETY: The mapping bounds and alignment were checked above.
        unsafe {
            self.pointer
                .as_ptr()
                .add(offset)
                .cast::<T>()
                .read_volatile()
        }
    }
    fn write<T: Copy>(&self, offset: usize, value: T) {
        assert!(offset + size_of::<T>() <= self.length);
        assert!(offset.is_multiple_of(align_of::<T>()));
        // SAFETY: The mapping bounds and alignment were checked above.
        unsafe {
            self.pointer
                .as_ptr()
                .add(offset)
                .cast::<T>()
                .write_volatile(value)
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: This object owns this live mapping and its original length.
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.length);
        }
    }
}

#[derive(Clone, Copy)]
struct Capability {
    bar: usize,
    offset: usize,
    length: usize,
}
struct Queue {
    size: u16,
    desc: usize,
    avail: usize,
    used: usize,
    buffers: usize,
    next_used: u16,
    next_avail: u16,
    notify: usize,
    busy: Vec<bool>,
}
impl Queue {
    fn new(size: u16, base: usize, notify: usize) -> Self {
        let desc = base;
        let avail = desc + usize::from(size) * 16;
        let used = (avail + 6 + usize::from(size) * 2 + 4095) & !4095;
        let buffers = (used + 6 + usize::from(size) * 8 + 4095) & !4095;
        Self {
            size,
            desc,
            avail,
            used,
            buffers,
            next_used: 0,
            next_avail: 0,
            notify,
            busy: vec![false; size.into()],
        }
    }
    fn publish(&mut self, dma: &Mapping, id: u16) {
        dma.write(
            self.avail + 4 + usize::from(self.next_avail % self.size) * 2,
            id.to_le(),
        );
        fence(Ordering::Release);
        self.next_avail = self.next_avail.wrapping_add(1);
        dma.write(self.avail + 2, self.next_avail.to_le());
        fence(Ordering::SeqCst);
    }
    fn completion(&mut self, dma: &Mapping) -> io::Result<Option<(u16, usize)>> {
        let produced = u16::from_le(dma.read(self.used + 2));
        let pending = produced.wrapping_sub(self.next_used);
        if pending == 0 {
            return Ok(None);
        }
        if usize::from(pending) > self.busy.iter().filter(|busy| **busy).count() {
            return Err(invalid("device overran used queue"));
        }
        fence(Ordering::Acquire);
        let slot = self.used + 4 + usize::from(self.next_used % self.size) * 8;
        let id = u32::from_le(dma.read(slot));
        let length = u32::from_le(dma.read(slot + 4)) as usize;
        if id >= u32::from(self.size) || !self.busy[id as usize] {
            return Err(invalid("invalid used descriptor"));
        }
        self.next_used = self.next_used.wrapping_add(1);
        self.busy[id as usize] = false;
        Ok(Some((id as u16, length)))
    }
}

/// A guest-only, polling virtio Ethernet device with no negotiated offloads.
///
/// Opening a device resets it. Only a dedicated modern virtio-net PCI function
/// bound to vfio-pci inside an opted-in QEMU guest may be passed here.
pub struct VirtioNet {
    config_offset: u64,
    device: Option<File>,
    container: File,
    _group: File,
    bars: Vec<Option<Mapping>>,
    dma: Mapping,
    dma_mapped: bool,
    common: Capability,
    notify: Capability,
    rx: Queue,
    tx: Queue,
    mac: [u8; 6],
}

// SAFETY: The driver exclusively owns its mappings and queue state. All device
// access is serialized through its mutable API, and mappings are thread neutral.
unsafe impl Send for VirtioNet {}

impl VirtioNet {
    /// Open a domain-qualified PCI address, such as `0000:00:03.0`.
    pub fn open(pci_address: PciAddress) -> io::Result<Self> {
        guest_gate()?;
        let path = format!("/sys/bus/pci/devices/{pci_address}");
        if fs::read_to_string(format!("{path}/vendor"))?.trim() != "0x1af4"
            || fs::read_to_string(format!("{path}/device"))?.trim() != "0x1041"
        {
            return Err(invalid("expected a modern virtio-net PCI function"));
        }
        let group_path = fs::read_link(format!("{path}/iommu_group"))?;
        let group_name = group_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| invalid("missing IOMMU group"))?;
        if !group_name.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid IOMMU group"));
        }
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")?;
        if ioctl(container.as_raw_fd(), VFIO_GET_API_VERSION, 0)? != VFIO_API_VERSION
            || ioctl(
                container.as_raw_fd(),
                VFIO_CHECK_EXTENSION,
                VFIO_TYPE1_IOMMU,
            )? != 1
        {
            return Err(invalid("VFIO type one IOMMU is unavailable"));
        }
        let group = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/vfio/{group_name}"))?;
        let mut status = GroupStatus {
            argsz: size_of::<GroupStatus>() as u32,
            flags: 0,
        };
        ioctl(
            group.as_raw_fd(),
            VFIO_GROUP_GET_STATUS,
            (&mut status as *mut GroupStatus) as usize,
        )?;
        if status.flags & VFIO_GROUP_FLAGS_VIABLE == 0 {
            return Err(invalid("VFIO group is not viable"));
        }
        let container_fd = container.as_raw_fd();
        ioctl(
            group.as_raw_fd(),
            VFIO_GROUP_SET_CONTAINER,
            (&container_fd as *const RawFd) as usize,
        )?;
        ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)?;
        let address = std::ffi::CString::new(pci_address.to_string())
            .map_err(|_| invalid("invalid PCI address"))?;
        let fd = ioctl(
            group.as_raw_fd(),
            VFIO_GROUP_GET_DEVICE_FD,
            address.as_ptr() as usize,
        )?;
        use std::os::fd::FromRawFd;
        // SAFETY: VFIO returns a new owned device file descriptor.
        let device = unsafe { File::from_raw_fd(fd) };
        let mut info = DeviceInfo {
            argsz: size_of::<DeviceInfo>() as u32,
            flags: 0,
            regions: 0,
            irqs: 0,
        };
        ioctl(
            fd,
            VFIO_DEVICE_GET_INFO,
            (&mut info as *mut DeviceInfo) as usize,
        )?;
        if info.flags & VFIO_DEVICE_FLAGS_PCI == 0 || info.regions <= VFIO_PCI_CONFIG_REGION_INDEX {
            return Err(invalid("VFIO device is not PCI"));
        }
        let config_region = region(fd, VFIO_PCI_CONFIG_REGION_INDEX)?;
        let mut config = [0u8; 256];
        device.read_exact_at(&mut config, config_region.offset)?;
        let (common, notify, net, multiplier) = capabilities(&config)?;
        // Enable BAR decoding before touching common registers, keeping DMA
        // disabled until the IOMMU mapping and both queues are ready.
        let command = (u16::from_le_bytes([config[PCI_COMMAND], config[PCI_COMMAND + 1]])
            | PCI_COMMAND_MEMORY)
            & !PCI_COMMAND_MASTER;
        device.write_all_at(
            &command.to_le_bytes(),
            config_region.offset + PCI_COMMAND as u64,
        )?;
        let mut bars: Vec<Option<Mapping>> = (0..6).map(|_| None).collect();
        for capability in [common, notify, net] {
            let region = region(fd, capability.bar as u32)?;
            if region.flags
                & (VFIO_REGION_INFO_FLAG_READ
                    | VFIO_REGION_INFO_FLAG_WRITE
                    | VFIO_REGION_INFO_FLAG_MMAP)
                != (VFIO_REGION_INFO_FLAG_READ
                    | VFIO_REGION_INFO_FLAG_WRITE
                    | VFIO_REGION_INFO_FLAG_MMAP)
                || capability
                    .offset
                    .checked_add(capability.length)
                    .is_none_or(|end| end as u64 > region.size)
            {
                return Err(invalid(
                    "virtio capability is outside a writable mapped BAR",
                ));
            }
            if bars[capability.bar].is_none() {
                bars[capability.bar] = Some(Mapping::new(
                    fd,
                    region.offset,
                    usize::try_from(region.size).map_err(|_| invalid("BAR is too large"))?,
                    false,
                )?);
            }
        }
        let dma = Mapping::new(-1, 0, DMA_SIZE, true)?;
        let mut driver = Self {
            config_offset: config_region.offset,
            device: Some(device),
            container,
            _group: group,
            bars,
            dma,
            dma_mapped: false,
            common,
            notify,
            rx: Queue::new(1, 0, 0),
            tx: Queue::new(1, DMA_SIZE / 2, 0),
            mac: [0; 6],
        };
        driver.common_write(VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_S_RESET);
        if driver.common_read::<u8>(VIRTIO_PCI_COMMON_STATUS) != VIRTIO_CONFIG_S_RESET {
            return Err(invalid("virtio reset did not complete"));
        }
        driver.common_write(VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_S_ACKNOWLEDGE);
        driver.common_write(VIRTIO_PCI_COMMON_STATUS, DRIVER_STARTED);
        driver.common_write(VIRTIO_PCI_COMMON_DFSELECT, 1u32.to_le());
        if u32::from_le(driver.common_read(VIRTIO_PCI_COMMON_DF)) & PLATFORM_FEATURES
            != PLATFORM_FEATURES
        {
            return Err(invalid(
                "virtio version one and platform DMA access are required",
            ));
        }
        driver.common_write(VIRTIO_PCI_COMMON_DFSELECT, 0u32);
        if u32::from_le(driver.common_read(VIRTIO_PCI_COMMON_DF)) & (1 << VIRTIO_NET_F_MAC) == 0 {
            return Err(invalid("virtio MAC feature is required"));
        }
        driver.common_write(VIRTIO_PCI_COMMON_GFSELECT, 0u32);
        driver.common_write(VIRTIO_PCI_COMMON_GF, (1u32 << VIRTIO_NET_F_MAC).to_le());
        driver.common_write(VIRTIO_PCI_COMMON_GFSELECT, 1u32.to_le());
        driver.common_write(VIRTIO_PCI_COMMON_GF, PLATFORM_FEATURES.to_le());
        driver.common_write(VIRTIO_PCI_COMMON_STATUS, FEATURES_ACCEPTED);
        if driver.common_read::<u8>(VIRTIO_PCI_COMMON_STATUS) & VIRTIO_CONFIG_S_FEATURES_OK == 0 {
            return Err(invalid("virtio rejected features"));
        }
        let mut map = DmaMap {
            argsz: size_of::<DmaMap>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: driver.dma.pointer.as_ptr() as u64,
            iova: IOVA,
            size: DMA_SIZE as u64,
        };
        ioctl(
            container_fd,
            VFIO_IOMMU_MAP_DMA,
            (&mut map as *mut DmaMap) as usize,
        )?;
        driver.dma_mapped = true;
        driver.rx = driver.configure_queue(0, 0, multiplier)?;
        driver.tx = driver.configure_queue(1, DMA_SIZE / 2, multiplier)?;
        let mut stable = false;
        for _ in 0..100 {
            let generation = driver.common_read::<u8>(VIRTIO_PCI_COMMON_CFGGENERATION);
            for (offset, byte) in driver.mac.iter_mut().enumerate() {
                *byte = driver.bars[net.bar]
                    .as_ref()
                    .unwrap()
                    .read(net.offset + offset);
            }
            fence(Ordering::Acquire);
            if generation == driver.common_read::<u8>(VIRTIO_PCI_COMMON_CFGGENERATION) {
                stable = true;
                break;
            }
        }
        if !stable {
            return Err(invalid("unstable virtio network configuration"));
        }
        for id in 0..driver.rx.size {
            let desc = driver.rx.desc + usize::from(id) * 16;
            driver.dma.write(desc + 8, (BUFFER_SIZE as u32).to_le());
            driver.dma.write(desc + 12, VRING_DESC_F_WRITE.to_le());
            driver.rx.busy[usize::from(id)] = true;
            driver.rx.publish(&driver.dma, id);
        }
        let command = u16::from_le_bytes([config[PCI_COMMAND], config[PCI_COMMAND + 1]])
            | PCI_COMMAND_MEMORY
            | PCI_COMMAND_MASTER;
        let device = driver.device.as_ref().unwrap();
        device.write_all_at(
            &command.to_le_bytes(),
            config_region.offset + PCI_COMMAND as u64,
        )?;
        driver.common_write(VIRTIO_PCI_COMMON_STATUS, DRIVER_READY);
        driver.kick(0, driver.rx.notify);
        Ok(driver)
    }

    /// Return the MAC address advertised by the device.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// Poll one Ethernet frame. A short output buffer consumes the frame and
    /// returns an error. The virtio header is never exposed to the caller.
    pub fn receive(&mut self, frame: &mut [u8]) -> io::Result<Option<usize>> {
        self.check_status()?;
        let Some((id, length)) = self.rx.completion(&self.dma)? else {
            return Ok(None);
        };
        let result = if !(HEADER_SIZE + 14..=BUFFER_SIZE).contains(&length) {
            Err(invalid("invalid received frame length"))
        } else if frame.len() < length - HEADER_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer is too short",
            ))
        } else {
            let offset = self.rx.buffers + usize::from(id) * BUFFER_SIZE;
            if self.dma.read::<u8>(offset) != 0 || self.dma.read::<u8>(offset + 1) != 0 {
                Err(invalid("unexpected receive offload header"))
            } else {
                for (index, byte) in frame[..length - HEADER_SIZE].iter_mut().enumerate() {
                    *byte = self.dma.read(offset + HEADER_SIZE + index);
                }
                Ok(Some(length - HEADER_SIZE))
            }
        };
        self.rx.busy[usize::from(id)] = true;
        self.rx.publish(&self.dma, id);
        self.kick(0, self.rx.notify);
        result
    }

    /// Queue an Ethernet frame, returning false when all transmit buffers are busy.
    pub fn transmit(&mut self, frame: &[u8]) -> io::Result<bool> {
        self.check_status()?;
        if !(14..=BUFFER_SIZE - HEADER_SIZE).contains(&frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Ethernet frame length is outside supported bounds",
            ));
        }
        while self.tx.completion(&self.dma)?.is_some() {}
        let Some(id) = self.tx.busy.iter().position(|busy| !busy) else {
            return Ok(false);
        };
        let offset = self.tx.buffers + id * BUFFER_SIZE;
        for index in 0..HEADER_SIZE {
            self.dma.write(offset + index, 0u8);
        }
        for (index, byte) in frame.iter().enumerate() {
            self.dma.write(offset + HEADER_SIZE + index, *byte);
        }
        self.dma.write(
            self.tx.desc + id * 16 + 8,
            ((HEADER_SIZE + frame.len()) as u32).to_le(),
        );
        self.tx.busy[id] = true;
        self.tx.publish(&self.dma, id as u16);
        self.kick(1, self.tx.notify);
        Ok(true)
    }

    /// Poll transmit completions and report whether every submitted frame completed.
    pub fn transmit_idle(&mut self) -> io::Result<bool> {
        self.check_status()?;
        while self.tx.completion(&self.dma)?.is_some() {}
        Ok(self.tx.busy.iter().all(|busy| !busy))
    }

    fn common_read<T: Copy>(&self, offset: usize) -> T {
        self.bars[self.common.bar]
            .as_ref()
            .unwrap()
            .read(self.common.offset + offset)
    }
    fn common_write<T: Copy>(&self, offset: usize, value: T) {
        self.bars[self.common.bar]
            .as_ref()
            .unwrap()
            .write(self.common.offset + offset, value);
    }
    fn kick(&self, queue: u16, offset: usize) {
        self.bars[self.notify.bar]
            .as_ref()
            .unwrap()
            .write(self.notify.offset + offset, queue.to_le());
    }
    fn check_status(&self) -> io::Result<()> {
        if self.common_read::<u8>(VIRTIO_PCI_COMMON_STATUS) != DRIVER_READY {
            Err(invalid("virtio device requires reset"))
        } else {
            Ok(())
        }
    }
    fn configure_queue(&self, index: u16, base: usize, multiplier: u32) -> io::Result<Queue> {
        self.common_write(VIRTIO_PCI_COMMON_Q_SELECT, index.to_le());
        let maximum = u16::from_le(self.common_read(VIRTIO_PCI_COMMON_Q_SIZE));
        if maximum == 0 {
            return Err(invalid("required virtio queue is unavailable"));
        }
        let size = maximum.min(QUEUE_SIZE);
        if !size.is_power_of_two() {
            return Err(invalid("invalid split queue size"));
        }
        let notify = usize::from(u16::from_le(self.common_read(VIRTIO_PCI_COMMON_Q_NOFF)))
            .checked_mul(multiplier as usize)
            .ok_or_else(|| invalid("notify offset overflow"))?;
        if notify
            .checked_add(2)
            .is_none_or(|end| end > self.notify.length)
            || !(self.notify.offset + notify).is_multiple_of(2)
        {
            return Err(invalid("invalid queue notify offset"));
        }
        let queue = Queue::new(size, base, notify);
        if queue.buffers + usize::from(size) * BUFFER_SIZE > base + DMA_SIZE / 2 {
            return Err(invalid("queue exceeds DMA allocation"));
        }
        self.common_write(VIRTIO_PCI_COMMON_Q_SIZE, size.to_le());
        self.common_write(VIRTIO_PCI_COMMON_Q_MSIX, VIRTIO_MSI_NO_VECTOR.to_le());
        self.common_write(
            VIRTIO_PCI_COMMON_Q_DESCLO,
            (IOVA + queue.desc as u64).to_le(),
        );
        self.common_write(
            VIRTIO_PCI_COMMON_Q_AVAILLO,
            (IOVA + queue.avail as u64).to_le(),
        );
        self.common_write(
            VIRTIO_PCI_COMMON_Q_USEDLO,
            (IOVA + queue.used as u64).to_le(),
        );
        self.dma
            .write(queue.avail, VRING_AVAIL_F_NO_INTERRUPT.to_le());
        for id in 0..size {
            self.dma.write(
                queue.desc + usize::from(id) * 16,
                (IOVA + (queue.buffers + usize::from(id) * BUFFER_SIZE) as u64).to_le(),
            );
        }
        fence(Ordering::Release);
        self.common_write(VIRTIO_PCI_COMMON_Q_ENABLE, 1u16.to_le());
        Ok(queue)
    }
}
impl Drop for VirtioNet {
    fn drop(&mut self) {
        self.common_write(VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_S_RESET);
        if let Some(device) = self.device.take() {
            let _ =
                device.write_all_at(&0u16.to_le_bytes(), self.config_offset + PCI_COMMAND as u64);
            let _ = ioctl(device.as_raw_fd(), VFIO_DEVICE_RESET, 0);
            self.bars.clear();
            drop(device);
        }
        if self.dma_mapped {
            let mut unmap = DmaUnmap {
                argsz: size_of::<DmaUnmap>() as u32,
                flags: 0,
                iova: IOVA,
                size: DMA_SIZE as u64,
            };
            let _ = ioctl(
                self.container.as_raw_fd(),
                VFIO_IOMMU_UNMAP_DMA,
                (&mut unmap as *mut DmaUnmap) as usize,
            );
        }
    }
}

fn region(fd: RawFd, index: u32) -> io::Result<RegionInfo> {
    let mut info = RegionInfo {
        argsz: size_of::<RegionInfo>() as u32,
        index,
        ..RegionInfo::default()
    };
    ioctl(
        fd,
        VFIO_DEVICE_GET_REGION_INFO,
        (&mut info as *mut RegionInfo) as usize,
    )?;
    Ok(info)
}
fn guest_gate() -> io::Result<()> {
    if !cfg!(target_arch = "x86_64") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VFIO polling currently requires an x86_64 guest",
        ));
    }
    let vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor")?;
    let command_line = fs::read_to_string("/proc/cmdline")?;
    if vendor.trim() != "QEMU"
        || !command_line
            .split_ascii_whitespace()
            .any(|token| token == "fictionet.rawnic=1")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw Ethernet requires QEMU DMI and fictionet.rawnic=1 on the guest kernel command line",
        ));
    }
    Ok(())
}
/// A domain-qualified PCI function address, parsed before device access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciAddress {
    domain: u16,
    bus: u8,
    slot: u8,
    function: u8,
}

impl std::str::FromStr for PciAddress {
    type Err = io::Error;

    fn from_str(address: &str) -> io::Result<Self> {
        let malformed = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected domain:bus:slot.function PCI address",
            )
        };
        let bytes = address.as_bytes();
        if bytes.len() != 12
            || bytes[4] != b':'
            || bytes[7] != b':'
            || bytes[10] != b'.'
            || !bytes
                .iter()
                .enumerate()
                .all(|(i, b)| [4, 7, 10].contains(&i) || b.is_ascii_hexdigit())
        {
            return Err(malformed());
        }
        let result = Self {
            domain: u16::from_str_radix(&address[..4], 16).map_err(|_| malformed())?,
            bus: u8::from_str_radix(&address[5..7], 16).map_err(|_| malformed())?,
            slot: u8::from_str_radix(&address[8..10], 16).map_err(|_| malformed())?,
            function: u8::from_str_radix(&address[11..], 16).map_err(|_| malformed())?,
        };
        if result.slot > 31 || result.function > 7 {
            return Err(malformed());
        }
        Ok(result)
    }
}

impl std::fmt::Display for PciAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.domain, self.bus, self.slot, self.function
        )
    }
}

fn capabilities(config: &[u8; 256]) -> io::Result<(Capability, Capability, Capability, u32)> {
    if u16::from_le_bytes([config[PCI_STATUS], config[PCI_STATUS + 1]]) & PCI_STATUS_CAP_LIST == 0 {
        return Err(invalid("PCI capability list is absent"));
    }
    let mut cursor = usize::from(config[PCI_CAPABILITY_LIST]);
    let mut visited = [false; 256];
    let (mut common, mut notify, mut net) = (None, None, None);
    let mut multiplier = 0;
    while cursor != 0 {
        if !(0x40..=0xfc).contains(&cursor) || cursor % 4 != 0 || visited[cursor] {
            return Err(invalid("invalid PCI capability chain"));
        }
        visited[cursor] = true;
        if config[cursor] == PCI_CAP_ID_VNDR {
            if cursor + 16 > 256 {
                return Err(invalid("truncated virtio capability"));
            }
            let length = usize::from(config[cursor + 2]);
            if length < 16 || cursor + length > 256 {
                return Err(invalid("invalid virtio capability length"));
            }
            let bar = usize::from(config[cursor + 4]);
            if bar >= 6 {
                return Err(invalid("invalid virtio BAR"));
            }
            let offset =
                u32::from_le_bytes(config[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            let length_bytes =
                u32::from_le_bytes(config[cursor + 12..cursor + 16].try_into().unwrap()) as usize;
            let cap = Capability {
                bar,
                offset,
                length: length_bytes,
            };
            match config[cursor + 3] {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    if length_bytes < 56
                        || !offset.is_multiple_of(8)
                        || common.replace(cap).is_some()
                    {
                        return Err(invalid("invalid common capability"));
                    }
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    if length < 20 || notify.replace(cap).is_some() {
                        return Err(invalid("invalid notify capability"));
                    }
                    multiplier =
                        u32::from_le_bytes(config[cursor + 16..cursor + 20].try_into().unwrap());
                }
                VIRTIO_PCI_CAP_DEVICE_CFG if length_bytes < 6 || net.is_some() => {
                    return Err(invalid("invalid network capability"));
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => net = Some(cap),
                _ => {}
            }
        }
        cursor = usize::from(config[cursor + 1]);
    }
    Ok((
        common.ok_or_else(|| invalid("missing common capability"))?,
        notify.ok_or_else(|| invalid("missing notify capability"))?,
        net.ok_or_else(|| invalid("missing network capability"))?,
        multiplier,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_queue_indices_wrap_without_losing_ownership() {
        let dma = Mapping::new(-1, 0, DMA_SIZE, true).unwrap();
        let mut queue = Queue::new(2, 0, 0);
        for counter in 0..131_073u32 {
            let id = (counter % 2) as u16;
            queue.busy[usize::from(id)] = true;
            queue.publish(&dma, id);
            let slot = queue.used + 4 + usize::from(queue.next_used % queue.size) * 8;
            dma.write(slot, u32::from(id).to_le());
            dma.write(slot + 4, 42u32.to_le());
            dma.write(queue.used + 2, queue.next_used.wrapping_add(1).to_le());
            assert_eq!(queue.completion(&dma).unwrap(), Some((id, 42)));
            assert!(!queue.busy[usize::from(id)]);
            assert_eq!(queue.completion(&dma).unwrap(), None);
        }
    }

    #[test]
    fn used_queue_rejects_unowned_and_excess_completions() {
        let dma = Mapping::new(-1, 0, DMA_SIZE, true).unwrap();
        let mut queue = Queue::new(2, 0, 0);
        queue.busy[0] = true;
        dma.write(queue.used + 2, 2u16.to_le());
        assert!(queue.completion(&dma).is_err());
        dma.write(queue.used + 2, 1u16.to_le());
        dma.write(queue.used + 4, 1u32.to_le());
        assert!(queue.completion(&dma).is_err());
        dma.write(queue.used + 4, 0u32.to_le());
        assert!(queue.completion(&dma).unwrap().is_some());
        queue.busy[1] = true;
        dma.write(queue.used + 2, 2u16.to_le());
        dma.write(queue.used + 12, 0u32.to_le());
        assert!(queue.completion(&dma).is_err());
    }

    #[test]
    fn malformed_capabilities_are_rejected() {
        let mut config = [0; 256];
        config[6] = 0x10;
        config[PCI_CAPABILITY_LIST] = 0xfc;
        config[0xfc] = 9;
        assert_eq!(
            capabilities(&config).err().unwrap().to_string(),
            "truncated virtio capability"
        );
        config[PCI_CAPABILITY_LIST] = 0x40;
        config[0x40] = 9;
        config[0x42] = 16;
        config[0x43] = 1;
        config[0x48] = 1;
        config[0x4c] = 56;
        assert_eq!(
            capabilities(&config).err().unwrap().to_string(),
            "invalid common capability"
        );
        config[0x48] = 0;
        config[0x44] = 6;
        assert_eq!(
            capabilities(&config).err().unwrap().to_string(),
            "invalid virtio BAR"
        );
    }

    #[test]
    fn pci_addresses_are_strict() {
        assert!("0000:00:03.0".parse::<PciAddress>().is_ok());
        let address = "ABCD:EF:1F.7".parse::<PciAddress>().unwrap();
        assert_eq!(address.to_string(), "abcd:ef:1f.7");
        assert_eq!(address.to_string().parse::<PciAddress>().unwrap(), address);
        for address in [
            "0000:00:03.0\0",
            "0000:00:é3.0",
            "../vfio/vfio",
            "0000:00:20.0",
            "0000:00:03.8",
            "0000:00:03.f",
            "00:03.0",
        ] {
            assert!(address.parse::<PciAddress>().is_err());
        }
    }

    #[test]
    fn capability_cycles_are_rejected() {
        let mut config = [0; 256];
        config[6] = 0x10;
        config[PCI_CAPABILITY_LIST] = 0x40;
        config[0x41] = 0x40;
        assert!(capabilities(&config).is_err());
    }

    #[test]
    fn queue_layout_fits_each_dma_half() {
        for size in [1, 2, 128, 256] {
            let queue = Queue::new(size, DMA_SIZE / 2, 0);
            assert!(queue.buffers + usize::from(size) * BUFFER_SIZE <= DMA_SIZE);
            assert_eq!(queue.desc % 16, 0);
            assert_eq!(queue.used % 4, 0);
        }
    }
}
