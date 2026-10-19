//! Fixed capacities used by Fictionet. Unit tests retain upstream fixture capacities.

pub const ASSEMBLER_MAX_SEGMENT_COUNT: usize = 4;
pub const IPV6_HBH_MAX_OPTIONS: usize = 4;

#[cfg(not(test))]
pub const IFACE_MAX_ADDR_COUNT: usize = 2;
#[cfg(test)]
pub const IFACE_MAX_ADDR_COUNT: usize = 8;

#[cfg(not(test))]
pub const IFACE_MAX_ROUTE_COUNT: usize = 2;
#[cfg(test)]
pub const IFACE_MAX_ROUTE_COUNT: usize = 4;

#[cfg(not(test))]
pub const FRAGMENTATION_BUFFER_SIZE: usize = 1500;
#[cfg(test)]
pub const FRAGMENTATION_BUFFER_SIZE: usize = 4096;

#[cfg(not(test))]
pub const REASSEMBLY_BUFFER_COUNT: usize = 1;
#[cfg(test)]
pub const REASSEMBLY_BUFFER_COUNT: usize = 4;
