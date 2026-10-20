//! A per-run qcow2 overlay over the read-only download, written in Rust.
//!
//! The overlay starts empty, so every cluster reads through to the backing
//! image; the guest's writes land only in the overlay, and the download is
//! never opened for writing. The overlay's virtual size is larger than the
//! image's, so cloud-init's growpart can expand the root partition into the
//! new space. Cloud Hypervisor opens it with `backing_files=on`.

use std::io;
use std::path::Path;

const CLUSTER_BITS: u32 = 16;
const CLUSTER: u64 = 1 << CLUSTER_BITS;
/// qcow2 with 16-bit refcounts.
const REFCOUNT_ORDER: u32 = 4;

/// Writes an empty qcow2 overlay at `path` of `virtual_size` bytes, backed
/// by `backing` (an absolute path stored in the header). The file holds
/// only its metadata until the guest writes.
pub fn write_overlay(path: &Path, backing: &Path, virtual_size: u64) -> io::Result<()> {
    let backing = backing.to_str().ok_or_else(|| {
        io::Error::other("the backing image path is not UTF-8, which qcow2 cannot store")
    })?;
    let backing = backing.as_bytes();

    // L2 entries per cluster, and the span one L2 table covers.
    let l2_entries = CLUSTER / 8;
    let l2_span = l2_entries * CLUSTER;
    let l1_entries = virtual_size.div_ceil(l2_span);
    let l1_bytes = l1_entries * 8;
    let l1_clusters = l1_bytes.div_ceil(CLUSTER).max(1);

    // Cluster layout: header (with the backing name), refcount table,
    // refcount block, then the L1 table.
    let refcount_table_offset = CLUSTER;
    let refcount_block_offset = 2 * CLUSTER;
    let l1_table_offset = 3 * CLUSTER;
    let total_clusters = 3 + l1_clusters;
    let file_len = total_clusters * CLUSTER;

    let mut image = vec![0u8; file_len as usize];

    // Header (big-endian), QCOW2 version 3.
    let backing_offset: u64 = 112; // right after the v3 header, inside cluster 0
    let put32 =
        |img: &mut [u8], at: usize, v: u32| img[at..at + 4].copy_from_slice(&v.to_be_bytes());
    let put64 =
        |img: &mut [u8], at: usize, v: u64| img[at..at + 8].copy_from_slice(&v.to_be_bytes());
    image[0..4].copy_from_slice(b"QFI\xfb");
    put32(&mut image, 4, 3); // version
    put64(&mut image, 8, backing_offset); // backing_file_offset
    put32(&mut image, 16, backing.len() as u32); // backing_file_size
    put32(&mut image, 20, CLUSTER_BITS); // cluster_bits
    put64(&mut image, 24, virtual_size); // size
    put32(&mut image, 32, 0); // crypt_method
    put32(&mut image, 36, l1_entries as u32); // l1_size
    put64(&mut image, 40, l1_table_offset); // l1_table_offset
    put64(&mut image, 48, refcount_table_offset); // refcount_table_offset
    put32(&mut image, 56, 1); // refcount_table_clusters
    put32(&mut image, 60, 0); // nb_snapshots
    put64(&mut image, 64, 0); // snapshots_offset
    // v3 fields.
    put64(&mut image, 72, 0); // incompatible_features
    put64(&mut image, 80, 0); // compatible_features
    put64(&mut image, 88, 0); // autoclear_features
    put32(&mut image, 96, REFCOUNT_ORDER); // refcount_order
    put32(&mut image, 100, 112); // header_length
    image[backing_offset as usize..backing_offset as usize + backing.len()]
        .copy_from_slice(backing);

    // Refcount table: one entry pointing at the single refcount block.
    put64(
        &mut image,
        refcount_table_offset as usize,
        refcount_block_offset,
    );

    // Refcount block: the metadata clusters each have one reference. A
    // 16-bit refcount per cluster, big-endian.
    let rb = refcount_block_offset as usize;
    for cluster in 0..total_clusters {
        let at = rb + (cluster as usize) * 2;
        image[at..at + 2].copy_from_slice(&1u16.to_be_bytes());
    }

    // The L1 table stays all zero: no L2 is allocated, so every guest
    // cluster falls through to the backing image.

    let part = path.with_extension("qcow2.part");
    std::fs::write(&part, &image)?;
    std::fs::rename(&part, path)?;
    Ok(())
}
