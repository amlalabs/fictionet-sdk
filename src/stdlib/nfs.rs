//! NFS version 3 and MOUNT version 3: reading and writing the arguments
//! and results of every procedure, with no I/O.
//!
//! NFS (Network File System) lets a client read and write files that live
//! on a server as if they were local. Version 3 is the one most servers
//! still offer. A client first asks the MOUNT program for the file handle
//! of an exported directory, then calls NFS procedures with handles:
//! LOOKUP a name in a directory to get the handle of what it names, READ
//! and WRITE a file, READDIR a directory, and so on. Both programs run
//! over ONC RPC. NFS listens on TCP and UDP port 2049, and MOUNT on
//! whatever port the portmapper gives for program 100005. This module
//! follows RFC 1813, which defines both, and RFC 1833 for the portmapper.
//!
//! Nothing here reads a socket. A world that plays a file server takes RPC
//! calls from the [`onc_rpc`](super::onc_rpc) module, reads each one's
//! arguments with [`Request::parse`] or [`MountRequest::parse`], and
//! answers with the results of a [`Response`] or [`MountResponse`]. Which
//! files exist, what they hold, and which handles name them is up to world
//! code. A world that plays a client writes calls with [`Request::call`]
//! and reads results with [`Response::parse`].
//!
//! For TCP, [`onc_rpc::messages`](super::onc_rpc::messages) combines record
//! marking, bounded assembly, and RPC parsing. Read NFS arguments with a
//! closure. Procedure numbers remain ordinary arguments, outside [`Wire`](super::codec::Wire):
//!
//! ```
//! use fictionet::stdlib::{codec::{Decode, Stream}, nfs, onc_rpc};
//!
//! let requests = onc_rpc::messages(onc_rpc::MAX_RECORD).map(|message| {
//!     message.map(|message| match message.body {
//!         onc_rpc::Body::Call(call) => {
//!             // Route by program and version, and check RPC version first.
//!             let request = nfs::Request::parse(&call);
//!             Some((message.xid, call, request))
//!         }
//!         onc_rpc::Body::Reply(_) => None,
//!     })
//! });
//! let mut stream = Stream::new(requests);
//! assert!(stream.next().is_none());
//! ```
//!
//! File handles, names, paths, data, and lists have explicit limits.
//! Writers return an error when a value exceeds those limits or would
//! parse differently. They preserve counts, optional fields, and EOF flags.
//! Argument and result writers require a procedure, so they stay outside
//! [`Wire`](super::codec::Wire).
//!
//! File names and paths are bytes, not text: RFC 1813 sets no character
//! set for them, and servers such as Linux's take any bytes but NUL and
//! `/` in a name. Host and group names in MOUNT results are text.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::nfs::{procedure, DirOp, FileHandle, LookupOk, NfsError, Request, Response};
//! use fictionet::stdlib::onc_rpc::{Accept, Body, Message, Reply};
//!
//! /// A server whose root directory, handle [1], holds one file: notes.txt.
//! fn answer(request: &Request) -> Response {
//!     match request {
//!         Request::Lookup(op) if op.dir.0 == [1] && op.name == b"notes.txt" => Response::Lookup(Ok(LookupOk {
//!             object: FileHandle(vec![2]),
//!             object_attributes: None,
//!             dir_attributes: None,
//!         })),
//!         Request::Lookup(_) => Response::Lookup(Err((NfsError::NoEnt, None))),
//!         other => Response::failed(other, NfsError::NotSupp),
//!     }
//! }
//!
//! // A client looks up notes.txt in the root. Call 9.
//! let lookup = Request::Lookup(DirOp { dir: FileHandle(vec![1]), name: "notes.txt".into() });
//! let message = Message::parse(&lookup.call(9).unwrap().to_bytes().unwrap()).unwrap();
//! let Body::Call(call) = &message.body else { panic!("not a call") };
//! let reply = match Request::parse(call) {
//!     Ok(request) => answer(&request).reply().unwrap(),
//!     Err(status) => Reply::accepted(status),
//! };
//! let bytes = message.reply(reply).to_bytes().unwrap();
//!
//! // The client reads the results.
//! let Body::Reply(Reply::Accepted { status: Accept::Success(results), .. }) = Message::parse(&bytes).unwrap().body
//! else {
//!     panic!("not a result")
//! };
//! // NFS3_OK, a 1-byte handle and its padding, and no attributes for either.
//! assert_eq!(results, [0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
//! let Ok(Response::Lookup(Ok(found))) = Response::parse(procedure::LOOKUP, &results) else { panic!("not found") };
//! assert_eq!(found.object, FileHandle(vec![2]));
//! ```

use std::num::NonZeroU32;

use super::onc_rpc::{Accept, Call, Message, Reader, Reply, Writer, XdrError};

/// The port NFS listens on, over TCP and UDP.
pub const PORT: u16 = 2049;
/// The NFS program number.
pub const NFS_PROGRAM: u32 = 100_003;
/// The NFS version this module reads and writes.
pub const NFS_VERSION: u32 = 3;
/// The MOUNT program number. Clients find its port through the portmapper.
pub const MOUNT_PROGRAM: u32 = 100_005;
/// The MOUNT version this module reads and writes.
pub const MOUNT_VERSION: u32 = 3;

/// The longest file handle, in bytes (NFS3_FHSIZE and FHSIZE3).
pub const MAX_FH: usize = 64;
/// The longest file name in a directory, in bytes. RFC 1813 sets no limit
/// on filename3, so this is the common one of 255.
pub const MAX_NAME: usize = 255;
/// The longest MOUNT directory path, in bytes (MNTPATHLEN).
pub const MAX_PATH: usize = 1024;
/// The longest symbolic link target, in bytes. RFC 1813 sets no limit on
/// nfspath3, so this is PATH_MAX on Linux, which its servers use.
pub const MAX_SYMLINK: usize = 4096;
/// The longest host or group name in MOUNT results, in bytes (MNTNAMLEN).
pub const MAX_MOUNT_NAME: usize = 255;
/// The most bytes one READ result or WRITE call carries.
pub const MAX_DATA: usize = 1 << 20;
/// The most entries one READDIR or READDIRPLUS result holds. The byte
/// limit, [`MAX_DIR_BYTES`], is reached first unless names are short.
pub const MAX_DIR_ENTRIES: usize = 1 << 16;
/// The most bytes the entries of one READDIR or READDIRPLUS result take,
/// each with the word before it that says an entry follows. A client asks
/// for at most a count of bytes in all, and Linux servers answer at most
/// 1 MiB. A writer stops before this and writes `eof` as false; a reader
/// refuses a longer list.
pub const MAX_DIR_BYTES: usize = 1 << 20;
/// The most authentication flavors one MNT result lists.
pub const MAX_AUTH_FLAVORS: usize = 16;
/// The most exports one EXPORT result lists.
pub const MAX_EXPORTS: usize = 1024;
/// The most bytes in one EXPORT result. A writer leaves out the exports
/// that would go past it, so the reply fits in one record of
/// [`MAX_RECORD`](super::onc_rpc::MAX_RECORD) bytes, and a reader refuses
/// a longer result. Without it, the longest paths and group lists would
/// make results of about 70 MB.
pub const MAX_EXPORT_BYTES: usize = 1 << 20;
/// The most groups one export lists.
pub const MAX_GROUPS: usize = 256;
/// The most mounts one DUMP result lists.
pub const MAX_MOUNTS: usize = 1024;
/// The length of a cookie verifier, a create verifier and a write
/// verifier, in bytes.
pub const VERIFIER_LEN: usize = 8;

/// NFS version 3 procedure numbers.
pub mod procedure {
    #![allow(missing_docs)]
    pub const NULL: u32 = 0;
    pub const GETATTR: u32 = 1;
    pub const SETATTR: u32 = 2;
    pub const LOOKUP: u32 = 3;
    pub const ACCESS: u32 = 4;
    pub const READLINK: u32 = 5;
    pub const READ: u32 = 6;
    pub const WRITE: u32 = 7;
    pub const CREATE: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const SYMLINK: u32 = 10;
    pub const MKNOD: u32 = 11;
    pub const REMOVE: u32 = 12;
    pub const RMDIR: u32 = 13;
    pub const RENAME: u32 = 14;
    pub const LINK: u32 = 15;
    pub const READDIR: u32 = 16;
    pub const READDIRPLUS: u32 = 17;
    pub const FSSTAT: u32 = 18;
    pub const FSINFO: u32 = 19;
    pub const PATHCONF: u32 = 20;
    pub const COMMIT: u32 = 21;
}

/// MOUNT version 3 procedure numbers.
pub mod mount_procedure {
    #![allow(missing_docs)]
    pub const NULL: u32 = 0;
    pub const MNT: u32 = 1;
    pub const DUMP: u32 = 2;
    pub const UMNT: u32 = 3;
    pub const UMNTALL: u32 = 4;
    pub const EXPORT: u32 = 5;
}

/// The bits of an ACCESS call and result: which kinds of access the
/// client asks about, and which the server allows.
pub mod access {
    /// Read data from a file or read a directory.
    pub const READ: u32 = 0x01;
    /// Look up a name in a directory. It means nothing for other files.
    pub const LOOKUP: u32 = 0x02;
    /// Rewrite existing file data or modify existing directory entries.
    pub const MODIFY: u32 = 0x04;
    /// Write new data or add directory entries.
    pub const EXTEND: u32 = 0x08;
    /// Delete an existing directory entry.
    pub const DELETE: u32 = 0x10;
    /// Run a file. It means nothing for a directory.
    pub const EXECUTE: u32 = 0x20;
}

/// The bits of the `properties` field of an FSINFO result.
pub mod fsf {
    /// The file system supports hard links.
    pub const LINK: u32 = 0x01;
    /// The file system supports symbolic links.
    pub const SYMLINK: u32 = 0x02;
    /// PATHCONF gives the same answers for every file in the file system.
    pub const HOMOGENEOUS: u32 = 0x08;
    /// The server can set a file's times through SETATTR.
    pub const CANSETTIME: u32 = 0x10;
}

/// Why an NFS procedure failed: an nfsstat3 other than NFS3_OK. A
/// successful result is the `Ok` side of a [`Response`]'s `Result`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NfsError {
    /// Not the owner (1).
    Perm,
    /// No such file or directory (2).
    NoEnt,
    /// A hard I/O error (5).
    Io,
    /// No such device or address (6).
    Nxio,
    /// Permission denied (13).
    Acces,
    /// The file exists (17).
    Exist,
    /// A link across devices (18).
    Xdev,
    /// No such device (19).
    Nodev,
    /// Not a directory (20).
    NotDir,
    /// Is a directory (21).
    IsDir,
    /// An argument is not valid (22).
    Inval,
    /// The file is too large (27).
    Fbig,
    /// No space left on the device (28).
    Nospc,
    /// The file system is read-only (30).
    Rofs,
    /// Too many hard links (31).
    Mlink,
    /// The name is too long (63).
    NameTooLong,
    /// The directory is not empty (66).
    NotEmpty,
    /// The quota is used up (69).
    Dquot,
    /// The file handle no longer names a file (70).
    Stale,
    /// Too many levels of remote paths (71).
    Remote,
    /// The file handle is not valid (10001).
    BadHandle,
    /// SETATTR's guard did not match the file's ctime (10002).
    NotSync,
    /// A READDIR cookie is stale (10003).
    BadCookie,
    /// The operation is not supported (10004).
    NotSupp,
    /// A buffer or request is too small (10005).
    TooSmall,
    /// The server failed in a way no other code covers (10006).
    ServerFault,
    /// The server does not create objects of that type (10007).
    BadType,
    /// The server is busy; the client should try again later (10008).
    Jukebox,
    /// Any other nonzero code. A code that has its own variant writes the
    /// same, but reads back as that variant.
    Other(NonZeroU32),
}

impl NfsError {
    /// The nfsstat3 number.
    pub fn code(self) -> u32 {
        match self {
            NfsError::Perm => 1,
            NfsError::NoEnt => 2,
            NfsError::Io => 5,
            NfsError::Nxio => 6,
            NfsError::Acces => 13,
            NfsError::Exist => 17,
            NfsError::Xdev => 18,
            NfsError::Nodev => 19,
            NfsError::NotDir => 20,
            NfsError::IsDir => 21,
            NfsError::Inval => 22,
            NfsError::Fbig => 27,
            NfsError::Nospc => 28,
            NfsError::Rofs => 30,
            NfsError::Mlink => 31,
            NfsError::NameTooLong => 63,
            NfsError::NotEmpty => 66,
            NfsError::Dquot => 69,
            NfsError::Stale => 70,
            NfsError::Remote => 71,
            NfsError::BadHandle => 10001,
            NfsError::NotSync => 10002,
            NfsError::BadCookie => 10003,
            NfsError::NotSupp => 10004,
            NfsError::TooSmall => 10005,
            NfsError::ServerFault => 10006,
            NfsError::BadType => 10007,
            NfsError::Jukebox => 10008,
            NfsError::Other(n) => n.get(),
        }
    }

    /// The error for nfsstat3 `code`, or `None` for 0, NFS3_OK.
    pub fn from_code(code: u32) -> Option<NfsError> {
        Some(match code {
            1 => NfsError::Perm,
            2 => NfsError::NoEnt,
            5 => NfsError::Io,
            6 => NfsError::Nxio,
            13 => NfsError::Acces,
            17 => NfsError::Exist,
            18 => NfsError::Xdev,
            19 => NfsError::Nodev,
            20 => NfsError::NotDir,
            21 => NfsError::IsDir,
            22 => NfsError::Inval,
            27 => NfsError::Fbig,
            28 => NfsError::Nospc,
            30 => NfsError::Rofs,
            31 => NfsError::Mlink,
            63 => NfsError::NameTooLong,
            66 => NfsError::NotEmpty,
            69 => NfsError::Dquot,
            70 => NfsError::Stale,
            71 => NfsError::Remote,
            10001 => NfsError::BadHandle,
            10002 => NfsError::NotSync,
            10003 => NfsError::BadCookie,
            10004 => NfsError::NotSupp,
            10005 => NfsError::TooSmall,
            10006 => NfsError::ServerFault,
            10007 => NfsError::BadType,
            10008 => NfsError::Jukebox,
            n => NfsError::Other(NonZeroU32::new(n)?),
        })
    }
}

impl std::fmt::Display for NfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            NfsError::Perm => "not the owner",
            NfsError::NoEnt => "no such file or directory",
            NfsError::Io => "I/O error",
            NfsError::Nxio => "no such device or address",
            NfsError::Acces => "permission denied",
            NfsError::Exist => "file exists",
            NfsError::Xdev => "link across devices",
            NfsError::Nodev => "no such device",
            NfsError::NotDir => "not a directory",
            NfsError::IsDir => "is a directory",
            NfsError::Inval => "invalid argument",
            NfsError::Fbig => "file too large",
            NfsError::Nospc => "no space left on device",
            NfsError::Rofs => "read-only file system",
            NfsError::Mlink => "too many hard links",
            NfsError::NameTooLong => "name too long",
            NfsError::NotEmpty => "directory not empty",
            NfsError::Dquot => "quota exceeded",
            NfsError::Stale => "stale file handle",
            NfsError::Remote => "too many levels of remote paths",
            NfsError::BadHandle => "bad file handle",
            NfsError::NotSync => "update synchronization mismatch",
            NfsError::BadCookie => "stale READDIR cookie",
            NfsError::NotSupp => "operation not supported",
            NfsError::TooSmall => "buffer or request too small",
            NfsError::ServerFault => "server fault",
            NfsError::BadType => "object type not supported",
            NfsError::Jukebox => "server busy, try again later",
            NfsError::Other(n) => return write!(f, "NFS error {n}"),
        };
        f.write_str(text)
    }
}

impl std::error::Error for NfsError {}

/// A file handle: bytes the server chose to name a file. The client never
/// looks inside. At most [`MAX_FH`] bytes. A writer writes a longer one
/// with a writer error. It is never replaced by a different handle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FileHandle(pub Vec<u8>);

impl FileHandle {
    /// Reads a handle (nfs_fh3, or fhandle3 in MOUNT).
    pub fn read(r: &mut Reader<'_>) -> Result<FileHandle, XdrError> {
        Ok(FileHandle(r.opaque(MAX_FH)?.to_vec()))
    }

    /// Writes the handle. More than [`MAX_FH`] bytes sets a writer error.
    pub fn write(&self, w: &mut Writer) {
        write_opaque(w, &self.0, MAX_FH);
    }

    /// Whether it is at most [`MAX_FH`] bytes, so a writer writes it as it
    /// is.
    pub fn fits(&self) -> bool {
        self.0.len() <= MAX_FH
    }
}

/// What kind of file an object is (ftype3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    /// A regular file (1).
    Regular,
    /// A directory (2).
    Directory,
    /// A block device (3).
    Block,
    /// A character device (4).
    Character,
    /// A symbolic link (5).
    Symlink,
    /// A socket (6).
    Socket,
    /// A named pipe (7).
    Fifo,
}

impl FileType {
    /// The ftype3 number.
    pub fn code(self) -> u32 {
        match self {
            FileType::Regular => 1,
            FileType::Directory => 2,
            FileType::Block => 3,
            FileType::Character => 4,
            FileType::Symlink => 5,
            FileType::Socket => 6,
            FileType::Fifo => 7,
        }
    }

    /// The type for ftype3 `code`, if it is one.
    pub fn from_code(code: u32) -> Option<FileType> {
        Some(match code {
            1 => FileType::Regular,
            2 => FileType::Directory,
            3 => FileType::Block,
            4 => FileType::Character,
            5 => FileType::Symlink,
            6 => FileType::Socket,
            7 => FileType::Fifo,
            _ => return None,
        })
    }

    /// Reads an ftype3. A value outside 1 to 7 is refused.
    pub fn read(r: &mut Reader<'_>) -> Result<FileType, XdrError> {
        let n = r.uint()?;
        FileType::from_code(n).ok_or(XdrError::Discriminant(n))
    }

    /// Writes the ftype3.
    pub fn write(self, w: &mut Writer) {
        w.uint(self.code());
    }
}

/// A device's major and minor numbers (specdata3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SpecData {
    /// The major number.
    pub major: u32,
    /// The minor number.
    pub minor: u32,
}

impl SpecData {
    /// Reads a specdata3.
    pub fn read(r: &mut Reader<'_>) -> Result<SpecData, XdrError> {
        Ok(SpecData { major: r.uint()?, minor: r.uint()? })
    }

    /// Writes the specdata3.
    pub fn write(self, w: &mut Writer) {
        w.uint(self.major).uint(self.minor);
    }
}

/// A time: seconds and nanoseconds since 1970-01-01 UTC (nfstime3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Time {
    /// Seconds.
    pub seconds: u32,
    /// Nanoseconds past the second.
    pub nseconds: u32,
}

impl Time {
    /// Reads an nfstime3.
    pub fn read(r: &mut Reader<'_>) -> Result<Time, XdrError> {
        Ok(Time { seconds: r.uint()?, nseconds: r.uint()? })
    }

    /// Writes the nfstime3.
    pub fn write(self, w: &mut Writer) {
        w.uint(self.seconds).uint(self.nseconds);
    }
}

/// A file's attributes (fattr3): 84 bytes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fattr {
    /// What kind of file it is.
    pub kind: FileType,
    /// The permission bits, as in Unix.
    pub mode: u32,
    /// How many hard links it has.
    pub nlink: u32,
    /// The owner's user ID.
    pub uid: u32,
    /// The group ID.
    pub gid: u32,
    /// The size in bytes.
    pub size: u64,
    /// The bytes of disk it takes.
    pub used: u64,
    /// The device numbers, for a block or character device.
    pub rdev: SpecData,
    /// Which file system it is on.
    pub fsid: u64,
    /// Its number within the file system.
    pub fileid: u64,
    /// When its data was last read.
    pub atime: Time,
    /// When its data was last changed.
    pub mtime: Time,
    /// When its attributes were last changed.
    pub ctime: Time,
}

impl Fattr {
    /// Reads an fattr3.
    pub fn read(r: &mut Reader<'_>) -> Result<Fattr, XdrError> {
        Ok(Fattr {
            kind: FileType::read(r)?,
            mode: r.uint()?,
            nlink: r.uint()?,
            uid: r.uint()?,
            gid: r.uint()?,
            size: r.uhyper()?,
            used: r.uhyper()?,
            rdev: SpecData::read(r)?,
            fsid: r.uhyper()?,
            fileid: r.uhyper()?,
            atime: Time::read(r)?,
            mtime: Time::read(r)?,
            ctime: Time::read(r)?,
        })
    }

    /// Writes the fattr3.
    pub fn write(&self, w: &mut Writer) {
        self.kind.write(w);
        w.uint(self.mode).uint(self.nlink).uint(self.uid).uint(self.gid);
        w.uhyper(self.size).uhyper(self.used);
        self.rdev.write(w);
        w.uhyper(self.fsid).uhyper(self.fileid);
        self.atime.write(w);
        self.mtime.write(w);
        self.ctime.write(w);
    }
}

/// The attributes a server reports from before an operation, so a client
/// can tell whether its cache is still good (wcc_attr).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WccAttr {
    /// The size in bytes.
    pub size: u64,
    /// When the data was last changed.
    pub mtime: Time,
    /// When the attributes were last changed.
    pub ctime: Time,
}

impl WccAttr {
    /// Reads a wcc_attr.
    pub fn read(r: &mut Reader<'_>) -> Result<WccAttr, XdrError> {
        Ok(WccAttr { size: r.uhyper()?, mtime: Time::read(r)?, ctime: Time::read(r)? })
    }

    /// Writes the wcc_attr.
    pub fn write(&self, w: &mut Writer) {
        w.uhyper(self.size);
        self.mtime.write(w);
        self.ctime.write(w);
    }
}

/// Weak cache consistency data: an object's attributes from before and
/// after an operation that changed it (wcc_data). Either may be missing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WccData {
    /// Some attributes from before (pre_op_attr).
    pub before: Option<WccAttr>,
    /// All attributes from after (post_op_attr).
    pub after: Option<Fattr>,
}

impl WccData {
    /// Reads a wcc_data.
    pub fn read(r: &mut Reader<'_>) -> Result<WccData, XdrError> {
        Ok(WccData { before: r.optional(WccAttr::read)?, after: read_post_op(r)? })
    }

    /// Writes the wcc_data.
    pub fn write(&self, w: &mut Writer) {
        w.optional(self.before.as_ref(), |w, a| a.write(w));
        write_post_op(w, &self.after);
    }
}

/// Reads a post_op_attr: attributes a server may leave out.
pub fn read_post_op(r: &mut Reader<'_>) -> Result<Option<Fattr>, XdrError> {
    r.optional(Fattr::read)
}

/// Writes a post_op_attr.
pub fn write_post_op(w: &mut Writer, attributes: &Option<Fattr>) {
    w.optional(attributes.as_ref(), |w, a| a.write(w));
}

/// How SETATTR, or an operation that creates an object, sets a time
/// (set_atime and set_mtime).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SetTime {
    /// Leave it as it is (DONT_CHANGE, 0).
    #[default]
    DontChange,
    /// Set it to the server's clock (SET_TO_SERVER_TIME, 1).
    ServerTime,
    /// Set it to this time (SET_TO_CLIENT_TIME, 2).
    ClientTime(Time),
}

impl SetTime {
    /// Reads a set_atime or set_mtime. A time_how outside 0 to 2 is
    /// refused.
    pub fn read(r: &mut Reader<'_>) -> Result<SetTime, XdrError> {
        match r.uint()? {
            0 => Ok(SetTime::DontChange),
            1 => Ok(SetTime::ServerTime),
            2 => Ok(SetTime::ClientTime(Time::read(r)?)),
            n => Err(XdrError::Discriminant(n)),
        }
    }

    /// Writes the set_atime or set_mtime.
    pub fn write(self, w: &mut Writer) {
        match self {
            SetTime::DontChange => {
                w.uint(0);
            }
            SetTime::ServerTime => {
                w.uint(1);
            }
            SetTime::ClientTime(t) => {
                w.uint(2);
                t.write(w);
            }
        }
    }
}

/// The attributes a client asks to set (sattr3). A field that is `None`,
/// or a time that is [`SetTime::DontChange`], is left as it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Sattr {
    /// The permission bits.
    pub mode: Option<u32>,
    /// The owner's user ID.
    pub uid: Option<u32>,
    /// The group ID.
    pub gid: Option<u32>,
    /// The size in bytes, to cut or extend the file to.
    pub size: Option<u64>,
    /// The last access time.
    pub atime: SetTime,
    /// The last change time.
    pub mtime: SetTime,
}

impl Sattr {
    /// Reads an sattr3.
    pub fn read(r: &mut Reader<'_>) -> Result<Sattr, XdrError> {
        Ok(Sattr {
            mode: r.optional(Reader::uint)?,
            uid: r.optional(Reader::uint)?,
            gid: r.optional(Reader::uint)?,
            size: r.optional(Reader::uhyper)?,
            atime: SetTime::read(r)?,
            mtime: SetTime::read(r)?,
        })
    }

    /// Writes the sattr3.
    pub fn write(&self, w: &mut Writer) {
        w.optional(self.mode.as_ref(), |w, v| {
            w.uint(*v);
        });
        w.optional(self.uid.as_ref(), |w, v| {
            w.uint(*v);
        });
        w.optional(self.gid.as_ref(), |w, v| {
            w.uint(*v);
        });
        w.optional(self.size.as_ref(), |w, v| {
            w.uhyper(*v);
        });
        self.atime.write(w);
        self.mtime.write(w);
    }
}

/// A name in a directory (diropargs3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DirOp {
    /// The directory's handle.
    pub dir: FileHandle,
    /// The name, at most [`MAX_NAME`] bytes, in whatever character set
    /// the client uses.
    pub name: Vec<u8>,
}

impl DirOp {
    /// Reads a diropargs3.
    pub fn read(r: &mut Reader<'_>) -> Result<DirOp, XdrError> {
        Ok(DirOp { dir: FileHandle::read(r)?, name: read_name(r)? })
    }

    /// Writes the diropargs3. A name longer than [`MAX_NAME`] bytes is
    /// refused by the writer.
    pub fn write(&self, w: &mut Writer) {
        self.dir.write(w);
        write_opaque(w, &self.name, MAX_NAME);
    }
}

/// How WRITE stores data before it answers (stable_how).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StableHow {
    /// The server may keep the data in memory until COMMIT (0).
    #[default]
    Unstable,
    /// The data must be on disk, but not every attribute (1).
    DataSync,
    /// The data and attributes must be on disk (2).
    FileSync,
}

impl StableHow {
    /// Reads a stable_how. A value outside 0 to 2 is refused.
    pub fn read(r: &mut Reader<'_>) -> Result<StableHow, XdrError> {
        match r.uint()? {
            0 => Ok(StableHow::Unstable),
            1 => Ok(StableHow::DataSync),
            2 => Ok(StableHow::FileSync),
            n => Err(XdrError::Discriminant(n)),
        }
    }

    /// Writes the stable_how.
    pub fn write(self, w: &mut Writer) {
        w.uint(match self {
            StableHow::Unstable => 0,
            StableHow::DataSync => 1,
            StableHow::FileSync => 2,
        });
    }
}

/// How CREATE makes a file (createhow3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CreateHow {
    /// Make the file, or use it if it exists (UNCHECKED, 0).
    Unchecked(Sattr),
    /// Make the file, and fail if it exists (GUARDED, 1).
    Guarded(Sattr),
    /// Make the file once, marked with this verifier, so that a retried
    /// call does not fail (EXCLUSIVE, 2).
    Exclusive([u8; VERIFIER_LEN]),
}

impl CreateHow {
    /// Reads a createhow3. A mode outside 0 to 2 is refused.
    pub fn read(r: &mut Reader<'_>) -> Result<CreateHow, XdrError> {
        match r.uint()? {
            0 => Ok(CreateHow::Unchecked(Sattr::read(r)?)),
            1 => Ok(CreateHow::Guarded(Sattr::read(r)?)),
            2 => Ok(CreateHow::Exclusive(read_verifier(r)?)),
            n => Err(XdrError::Discriminant(n)),
        }
    }

    /// Writes the createhow3.
    pub fn write(&self, w: &mut Writer) {
        match self {
            CreateHow::Unchecked(a) => {
                w.uint(0);
                a.write(w);
            }
            CreateHow::Guarded(a) => {
                w.uint(1);
                a.write(w);
            }
            CreateHow::Exclusive(v) => {
                w.uint(2).opaque_fixed(v);
            }
        }
    }
}

/// What MKNOD makes (mknoddata3). Only devices, sockets and named pipes
/// carry attributes. A server answers the other types with
/// [`NfsError::BadType`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MknodData {
    /// A character device.
    Character {
        /// The attributes to set.
        attributes: Sattr,
        /// The device numbers.
        spec: SpecData,
    },
    /// A block device.
    Block {
        /// The attributes to set.
        attributes: Sattr,
        /// The device numbers.
        spec: SpecData,
    },
    /// A socket, with the attributes to set.
    Socket(Sattr),
    /// A named pipe, with the attributes to set.
    Fifo(Sattr),
    /// A regular file, which MKNOD does not make.
    Regular,
    /// A directory, which MKNOD does not make.
    Directory,
    /// A symbolic link, which MKNOD does not make.
    Symlink,
}

impl MknodData {
    /// The type of file it makes.
    pub fn kind(&self) -> FileType {
        match self {
            MknodData::Character { .. } => FileType::Character,
            MknodData::Block { .. } => FileType::Block,
            MknodData::Socket(_) => FileType::Socket,
            MknodData::Fifo(_) => FileType::Fifo,
            MknodData::Regular => FileType::Regular,
            MknodData::Directory => FileType::Directory,
            MknodData::Symlink => FileType::Symlink,
        }
    }

    /// Reads a mknoddata3.
    pub fn read(r: &mut Reader<'_>) -> Result<MknodData, XdrError> {
        Ok(match FileType::read(r)? {
            FileType::Character => {
                MknodData::Character { attributes: Sattr::read(r)?, spec: SpecData::read(r)? }
            }
            FileType::Block => MknodData::Block { attributes: Sattr::read(r)?, spec: SpecData::read(r)? },
            FileType::Socket => MknodData::Socket(Sattr::read(r)?),
            FileType::Fifo => MknodData::Fifo(Sattr::read(r)?),
            FileType::Regular => MknodData::Regular,
            FileType::Directory => MknodData::Directory,
            FileType::Symlink => MknodData::Symlink,
        })
    }

    /// Writes the mknoddata3.
    pub fn write(&self, w: &mut Writer) {
        self.kind().write(w);
        match self {
            MknodData::Character { attributes, spec } | MknodData::Block { attributes, spec } => {
                attributes.write(w);
                spec.write(w);
            }
            MknodData::Socket(a) | MknodData::Fifo(a) => a.write(w),
            MknodData::Regular | MknodData::Directory | MknodData::Symlink => {}
        }
    }
}

/// The arguments of an NFS version 3 call: what a client asks a server to
/// do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Procedure 0: do nothing. Clients use it to check the server is up.
    Null,
    /// Procedure 1: get a file's attributes.
    GetAttr(FileHandle),
    /// Procedure 2: set a file's attributes.
    SetAttr {
        /// The file.
        object: FileHandle,
        /// The attributes to set.
        attributes: Sattr,
        /// If given, set them only if the file's ctime is this.
        guard: Option<Time>,
    },
    /// Procedure 3: look up a name in a directory.
    Lookup(DirOp),
    /// Procedure 4: ask which kinds of access, of the [`access`] bits
    /// given, the caller has.
    Access {
        /// The file.
        object: FileHandle,
        /// The [`access`] bits to check.
        access: u32,
    },
    /// Procedure 5: read a symbolic link's target.
    ReadLink(FileHandle),
    /// Procedure 6: read `count` bytes from `offset`.
    Read {
        /// The file.
        file: FileHandle,
        /// Where to start.
        offset: u64,
        /// How many bytes to read.
        count: u32,
    },
    /// Procedure 7: write data at `offset`.
    Write {
        /// The file.
        file: FileHandle,
        /// Where to start.
        offset: u64,
        /// How many bytes to write. A reader refuses a call where it is
        /// not the data's length, as Linux servers do, and a writer
        /// writes the length of the data it writes in its place.
        count: u32,
        /// How the server must store it before it answers.
        stable: StableHow,
        /// The data, at most [`MAX_DATA`] bytes. A writer writes only the
        /// first [`MAX_DATA`], a shorter write that the server's count
        /// of bytes written then reports.
        data: Vec<u8>,
    },
    /// Procedure 8: make a regular file.
    Create {
        /// The directory and name.
        location: DirOp,
        /// How to make it.
        how: CreateHow,
    },
    /// Procedure 9: make a directory.
    Mkdir {
        /// The directory and name.
        location: DirOp,
        /// The attributes to set.
        attributes: Sattr,
    },
    /// Procedure 10: make a symbolic link.
    Symlink {
        /// The directory and name.
        location: DirOp,
        /// The attributes to set.
        attributes: Sattr,
        /// The link's target, at most [`MAX_SYMLINK`] bytes. A longer
        /// one is refused by the writer.
        target: Vec<u8>,
    },
    /// Procedure 11: make a device, socket or named pipe.
    Mknod {
        /// The directory and name.
        location: DirOp,
        /// What to make.
        what: MknodData,
    },
    /// Procedure 12: remove a file.
    Remove(DirOp),
    /// Procedure 13: remove an empty directory.
    Rmdir(DirOp),
    /// Procedure 14: rename a file or directory.
    Rename {
        /// The old directory and name.
        from: DirOp,
        /// The new directory and name.
        to: DirOp,
    },
    /// Procedure 15: make a hard link to a file.
    Link {
        /// The file.
        file: FileHandle,
        /// Where the new link goes.
        link: DirOp,
    },
    /// Procedure 16: read names from a directory.
    ReadDir {
        /// The directory.
        dir: FileHandle,
        /// Where to go on from: 0 at the start, then the last entry's
        /// cookie.
        cookie: u64,
        /// The verifier from the last result, or zeros at the start.
        cookieverf: [u8; VERIFIER_LEN],
        /// The most bytes of results the client takes.
        count: u32,
    },
    /// Procedure 17: read names, attributes and handles from a directory.
    ReadDirPlus {
        /// The directory.
        dir: FileHandle,
        /// Where to go on from.
        cookie: u64,
        /// The verifier from the last result, or zeros at the start.
        cookieverf: [u8; VERIFIER_LEN],
        /// The most bytes of names and cookies the client takes.
        dircount: u32,
        /// The most bytes of results the client takes.
        maxcount: u32,
    },
    /// Procedure 18: get a file system's space and file counts.
    FsStat(FileHandle),
    /// Procedure 19: get a file system's limits and preferences.
    FsInfo(FileHandle),
    /// Procedure 20: get the POSIX pathconf values for a file.
    PathConf(FileHandle),
    /// Procedure 21: put data written unstably on disk.
    Commit {
        /// The file.
        file: FileHandle,
        /// Where the range starts.
        offset: u64,
        /// How many bytes, or 0 for all from `offset` on.
        count: u32,
    },
}

impl Request {
    /// Reads the request a call makes. When the call is not one, the error
    /// is the status a server replies with: the wrong program, a version
    /// other than 3, a procedure past COMMIT, or arguments that do not
    /// read or have bytes left over.
    pub fn parse(call: &Call) -> Result<Request, Accept> {
        if call.program != NFS_PROGRAM {
            return Err(Accept::ProgUnavail);
        }
        if call.version != NFS_VERSION {
            return Err(Accept::ProgMismatch { low: NFS_VERSION, high: NFS_VERSION });
        }
        if call.procedure > procedure::COMMIT {
            return Err(Accept::ProcUnavail);
        }
        Request::read(call.procedure, &call.args).map_err(|_| Accept::GarbageArgs)
    }

    /// Reads the arguments `args` of procedure `procedure`. They must end
    /// where the last field does. A procedure past COMMIT is refused as
    /// [`XdrError::Discriminant`].
    pub fn read(procedure: u32, args: &[u8]) -> Result<Request, XdrError> {
        let r = &mut Reader::new(args);
        let request = match procedure {
            procedure::NULL => Request::Null,
            procedure::GETATTR => Request::GetAttr(FileHandle::read(r)?),
            procedure::SETATTR => Request::SetAttr {
                object: FileHandle::read(r)?,
                attributes: Sattr::read(r)?,
                guard: r.optional(Time::read)?,
            },
            procedure::LOOKUP => Request::Lookup(DirOp::read(r)?),
            procedure::ACCESS => Request::Access { object: FileHandle::read(r)?, access: r.uint()? },
            procedure::READLINK => Request::ReadLink(FileHandle::read(r)?),
            procedure::READ => {
                Request::Read { file: FileHandle::read(r)?, offset: r.uhyper()?, count: r.uint()? }
            }
            procedure::WRITE => {
                let file = FileHandle::read(r)?;
                let offset = r.uhyper()?;
                let count = r.uint()?;
                let stable = StableHow::read(r)?;
                Request::Write { file, offset, count, stable, data: read_data(r, count)? }
            }
            procedure::CREATE => Request::Create { location: DirOp::read(r)?, how: CreateHow::read(r)? },
            procedure::MKDIR => Request::Mkdir { location: DirOp::read(r)?, attributes: Sattr::read(r)? },
            procedure::SYMLINK => Request::Symlink {
                location: DirOp::read(r)?,
                attributes: Sattr::read(r)?,
                target: read_symlink(r)?,
            },
            procedure::MKNOD => Request::Mknod { location: DirOp::read(r)?, what: MknodData::read(r)? },
            procedure::REMOVE => Request::Remove(DirOp::read(r)?),
            procedure::RMDIR => Request::Rmdir(DirOp::read(r)?),
            procedure::RENAME => Request::Rename { from: DirOp::read(r)?, to: DirOp::read(r)? },
            procedure::LINK => Request::Link { file: FileHandle::read(r)?, link: DirOp::read(r)? },
            procedure::READDIR => Request::ReadDir {
                dir: FileHandle::read(r)?,
                cookie: r.uhyper()?,
                cookieverf: read_verifier(r)?,
                count: r.uint()?,
            },
            procedure::READDIRPLUS => Request::ReadDirPlus {
                dir: FileHandle::read(r)?,
                cookie: r.uhyper()?,
                cookieverf: read_verifier(r)?,
                dircount: r.uint()?,
                maxcount: r.uint()?,
            },
            procedure::FSSTAT => Request::FsStat(FileHandle::read(r)?),
            procedure::FSINFO => Request::FsInfo(FileHandle::read(r)?),
            procedure::PATHCONF => Request::PathConf(FileHandle::read(r)?),
            procedure::COMMIT => {
                Request::Commit { file: FileHandle::read(r)?, offset: r.uhyper()?, count: r.uint()? }
            }
            n => return Err(XdrError::Discriminant(n)),
        };
        r.finish()?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            Request::Null => procedure::NULL,
            Request::GetAttr(_) => procedure::GETATTR,
            Request::SetAttr { .. } => procedure::SETATTR,
            Request::Lookup(_) => procedure::LOOKUP,
            Request::Access { .. } => procedure::ACCESS,
            Request::ReadLink(_) => procedure::READLINK,
            Request::Read { .. } => procedure::READ,
            Request::Write { .. } => procedure::WRITE,
            Request::Create { .. } => procedure::CREATE,
            Request::Mkdir { .. } => procedure::MKDIR,
            Request::Symlink { .. } => procedure::SYMLINK,
            Request::Mknod { .. } => procedure::MKNOD,
            Request::Remove(_) => procedure::REMOVE,
            Request::Rmdir(_) => procedure::RMDIR,
            Request::Rename { .. } => procedure::RENAME,
            Request::Link { .. } => procedure::LINK,
            Request::ReadDir { .. } => procedure::READDIR,
            Request::ReadDirPlus { .. } => procedure::READDIRPLUS,
            Request::FsStat(_) => procedure::FSSTAT,
            Request::FsInfo(_) => procedure::FSINFO,
            Request::PathConf(_) => procedure::PATHCONF,
            Request::Commit { .. } => procedure::COMMIT,
        }
    }

    /// The call's arguments, which [`Request::read`] always reads back.
    /// Invalid handles, names, paths, counts, and data return an error.
    pub fn to_args(&self) -> Result<Vec<u8>, XdrError> {
        let w = &mut Writer::new();
        match self {
            Request::Null => {}
            Request::GetAttr(fh)
            | Request::ReadLink(fh)
            | Request::FsStat(fh)
            | Request::FsInfo(fh)
            | Request::PathConf(fh) => fh.write(w),
            Request::SetAttr { object, attributes, guard } => {
                object.write(w);
                attributes.write(w);
                w.optional(guard.as_ref(), |w, t| t.write(w));
            }
            Request::Lookup(op) | Request::Remove(op) | Request::Rmdir(op) => op.write(w),
            Request::Access { object, access } => {
                object.write(w);
                w.uint(*access);
            }
            Request::Read { file, offset, count } | Request::Commit { file, offset, count } => {
                file.write(w);
                w.uhyper(*offset).uint(*count);
            }
            Request::Write { file, offset, count, stable, data } => {
                if data.len() > MAX_DATA || usize::try_from(*count).ok() != Some(data.len()) {
                    return Err(XdrError::NonCanonical);
                }
                file.write(w);
                w.uhyper(*offset).uint(*count);
                stable.write(w);
                w.opaque(data);
            }
            Request::Create { location, how } => {
                location.write(w);
                how.write(w);
            }
            Request::Mkdir { location, attributes } => {
                location.write(w);
                attributes.write(w);
            }
            Request::Symlink { location, attributes, target } => {
                location.write(w);
                attributes.write(w);
                write_opaque(w, target, MAX_SYMLINK);
            }
            Request::Mknod { location, what } => {
                location.write(w);
                what.write(w);
            }
            Request::Rename { from, to } => {
                from.write(w);
                to.write(w);
            }
            Request::Link { file, link } => {
                file.write(w);
                link.write(w);
            }
            Request::ReadDir { dir, cookie, cookieverf, count } => {
                dir.write(w);
                w.uhyper(*cookie).opaque_fixed(cookieverf).uint(*count);
            }
            Request::ReadDirPlus { dir, cookie, cookieverf, dircount, maxcount } => {
                dir.write(w);
                w.uhyper(*cookie).opaque_fixed(cookieverf).uint(*dircount).uint(*maxcount);
            }
        }
        let bytes = std::mem::take(w).finish()?;
        if Self::read(self.procedure(), &bytes).as_ref() != Ok(self) {
            return Err(XdrError::NonCanonical);
        }
        Ok(bytes)
    }

    /// A call message that makes this request, with AUTH_NONE. A world
    /// that needs AUTH_SYS sets the call's `cred` afterwards.
    pub fn call(&self, xid: u32) -> Result<Message, XdrError> {
        let call = Call::new(NFS_PROGRAM, NFS_VERSION, self.procedure(), self.to_args()?);
        Ok(Message { xid, body: super::onc_rpc::Body::Call(call) })
    }
}

/// What came of an NFS procedure: `Ok` with the successful results, or
/// `Err` with the error and the results a failure still carries.
pub type Outcome<T, F> = Result<T, (NfsError, F)>;

/// The results of a successful LOOKUP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LookupOk {
    /// The handle of what the name names.
    pub object: FileHandle,
    /// Its attributes.
    pub object_attributes: Option<Fattr>,
    /// The directory's attributes.
    pub dir_attributes: Option<Fattr>,
}

/// The results of a successful ACCESS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessOk {
    /// The file's attributes.
    pub attributes: Option<Fattr>,
    /// The [`access`] bits the caller has, of those it asked about.
    pub access: u32,
}

/// The results of a successful READLINK.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadLinkOk {
    /// The link's attributes.
    pub attributes: Option<Fattr>,
    /// The link's target, at most [`MAX_SYMLINK`] bytes. A longer one is
    /// refused by the writer.
    pub target: Vec<u8>,
}

/// The results of a successful READ.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadOk {
    /// The file's attributes.
    pub attributes: Option<Fattr>,
    /// How many bytes were read. A reader refuses results where it is not
    /// the data's length, as Linux clients do, and a writer writes the
    /// length of the data it writes in its place.
    pub count: u32,
    /// Whether the read reached the end of the file. A writer that cuts
    /// the data writes it as false.
    pub eof: bool,
    /// The data, at most [`MAX_DATA`] bytes. A writer writes only the
    /// first [`MAX_DATA`], a short read the client goes on from.
    pub data: Vec<u8>,
}

/// The results of a successful WRITE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteOk {
    /// The file's attributes from before and after.
    pub wcc: WccData,
    /// How many bytes were written.
    pub count: u32,
    /// How the data was stored.
    pub committed: StableHow,
    /// A value that changes when the server restarts, so a client knows
    /// to write unstable data again.
    pub verf: [u8; VERIFIER_LEN],
}

/// The results of a successful CREATE, MKDIR, SYMLINK or MKNOD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateOk {
    /// The new object's handle, if the server gives it. A writer leaves
    /// out one longer than [`MAX_FH`].
    pub object: Option<FileHandle>,
    /// The new object's attributes.
    pub attributes: Option<Fattr>,
    /// The directory's attributes from before and after.
    pub dir_wcc: WccData,
}

/// The results of RENAME, whether it worked or not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenameWcc {
    /// The old directory's attributes from before and after.
    pub from_dir: WccData,
    /// The new directory's attributes from before and after.
    pub to_dir: WccData,
}

/// The results of LINK, whether it worked or not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkWcc {
    /// The file's attributes.
    pub attributes: Option<Fattr>,
    /// The directory's attributes from before and after.
    pub dir_wcc: WccData,
}

/// One name in a READDIR result (entry3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Entry {
    /// The file's number within the file system.
    pub fileid: u64,
    /// The name, at most [`MAX_NAME`] bytes. A writer leaves out an entry
    /// with a longer one.
    pub name: Vec<u8>,
    /// Where a later READDIR goes on from after this entry.
    pub cookie: u64,
}

/// The results of a successful READDIR.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadDirOk {
    /// The directory's attributes.
    pub attributes: Option<Fattr>,
    /// The verifier to send with the next READDIR.
    pub cookieverf: [u8; VERIFIER_LEN],
    /// The names, at most [`MAX_DIR_ENTRIES`] and [`MAX_DIR_BYTES`]. A
    /// writer leaves out the rest and writes `eof` as false, so the client
    /// asks again from the last cookie written.
    pub entries: Vec<Entry>,
    /// Whether the list reaches the end of the directory.
    pub eof: bool,
}

/// One name in a READDIRPLUS result, with its attributes and handle
/// (entryplus3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryPlus {
    /// The file's number within the file system.
    pub fileid: u64,
    /// The name, at most [`MAX_NAME`] bytes. A writer leaves out an entry
    /// with a longer one.
    pub name: Vec<u8>,
    /// Where a later READDIRPLUS goes on from after this entry.
    pub cookie: u64,
    /// The file's attributes.
    pub attributes: Option<Fattr>,
    /// The file's handle. A writer leaves out one longer than
    /// [`MAX_FH`].
    pub handle: Option<FileHandle>,
}

/// The results of a successful READDIRPLUS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadDirPlusOk {
    /// The directory's attributes.
    pub attributes: Option<Fattr>,
    /// The verifier to send with the next READDIRPLUS.
    pub cookieverf: [u8; VERIFIER_LEN],
    /// The entries, at most [`MAX_DIR_ENTRIES`] and [`MAX_DIR_BYTES`]. A
    /// writer leaves out the rest and writes `eof` as false, as for
    /// [`ReadDirOk`].
    pub entries: Vec<EntryPlus>,
    /// Whether the list reaches the end of the directory.
    pub eof: bool,
}

/// The results of a successful FSSTAT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsStatOk {
    /// The attributes of the file asked about.
    pub attributes: Option<Fattr>,
    /// Total bytes.
    pub tbytes: u64,
    /// Free bytes.
    pub fbytes: u64,
    /// Free bytes the caller may use.
    pub abytes: u64,
    /// Total file slots.
    pub tfiles: u64,
    /// Free file slots.
    pub ffiles: u64,
    /// Free file slots the caller may use.
    pub afiles: u64,
    /// How many seconds these numbers stay the same, or 0 if they may
    /// change at any time.
    pub invarsec: u32,
}

/// The results of a successful FSINFO.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsInfoOk {
    /// The attributes of the file asked about.
    pub attributes: Option<Fattr>,
    /// The largest READ the server takes.
    pub rtmax: u32,
    /// The READ size the server prefers.
    pub rtpref: u32,
    /// READ sizes should be a multiple of this.
    pub rtmult: u32,
    /// The largest WRITE the server takes.
    pub wtmax: u32,
    /// The WRITE size the server prefers.
    pub wtpref: u32,
    /// WRITE sizes should be a multiple of this.
    pub wtmult: u32,
    /// The READDIR count the server prefers.
    pub dtpref: u32,
    /// The largest file size.
    pub maxfilesize: u64,
    /// How fine the server's times are.
    pub time_delta: Time,
    /// The [`fsf`] bits.
    pub properties: u32,
}

/// The results of a successful PATHCONF.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathConfOk {
    /// The file's attributes.
    pub attributes: Option<Fattr>,
    /// The most hard links a file may have.
    pub linkmax: u32,
    /// The longest name, in bytes.
    pub name_max: u32,
    /// Whether a longer name is refused rather than cut short.
    pub no_trunc: bool,
    /// Whether only a privileged user may change a file's owner.
    pub chown_restricted: bool,
    /// Whether names ignore case.
    pub case_insensitive: bool,
    /// Whether names keep the case they were made with.
    pub case_preserving: bool,
}

/// The results of a successful COMMIT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommitOk {
    /// The file's attributes from before and after.
    pub wcc: WccData,
    /// The same verifier WRITE gives, so the client can tell whether the
    /// server restarted.
    pub verf: [u8; VERIFIER_LEN],
}

/// The results of an NFS version 3 procedure: what a server answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// To NULL: nothing.
    Null,
    /// To GETATTR: the attributes. A failure carries nothing more.
    GetAttr(Result<Fattr, NfsError>),
    /// To SETATTR: the file's attributes from before and after.
    SetAttr(Outcome<WccData, WccData>),
    /// To LOOKUP. A failure carries the directory's attributes.
    Lookup(Outcome<LookupOk, Option<Fattr>>),
    /// To ACCESS. A failure carries the file's attributes.
    Access(Outcome<AccessOk, Option<Fattr>>),
    /// To READLINK. A failure carries the link's attributes.
    ReadLink(Outcome<ReadLinkOk, Option<Fattr>>),
    /// To READ. A failure carries the file's attributes.
    Read(Outcome<ReadOk, Option<Fattr>>),
    /// To WRITE. A failure carries the file's attributes from before and
    /// after.
    Write(Outcome<WriteOk, WccData>),
    /// To CREATE. A failure carries the directory's attributes from
    /// before and after.
    Create(Outcome<CreateOk, WccData>),
    /// To MKDIR, like CREATE.
    Mkdir(Outcome<CreateOk, WccData>),
    /// To SYMLINK, like CREATE.
    Symlink(Outcome<CreateOk, WccData>),
    /// To MKNOD, like CREATE.
    Mknod(Outcome<CreateOk, WccData>),
    /// To REMOVE: the directory's attributes from before and after.
    Remove(Outcome<WccData, WccData>),
    /// To RMDIR: the parent directory's attributes from before and after.
    Rmdir(Outcome<WccData, WccData>),
    /// To RENAME: both directories' attributes from before and after.
    Rename(Outcome<RenameWcc, RenameWcc>),
    /// To LINK: the file's attributes and the directory's.
    Link(Outcome<LinkWcc, LinkWcc>),
    /// To READDIR. A failure carries the directory's attributes.
    ReadDir(Outcome<ReadDirOk, Option<Fattr>>),
    /// To READDIRPLUS. A failure carries the directory's attributes.
    ReadDirPlus(Outcome<ReadDirPlusOk, Option<Fattr>>),
    /// To FSSTAT. A failure carries the file's attributes.
    FsStat(Outcome<FsStatOk, Option<Fattr>>),
    /// To FSINFO. A failure carries the file's attributes.
    FsInfo(Outcome<FsInfoOk, Option<Fattr>>),
    /// To PATHCONF. A failure carries the file's attributes.
    PathConf(Outcome<PathConfOk, Option<Fattr>>),
    /// To COMMIT. A failure carries the file's attributes from before and
    /// after.
    Commit(Outcome<CommitOk, WccData>),
}

impl Response {
    /// The response that answers `request` with `error`, leaving out
    /// every attribute a failure may carry. NULL cannot fail, so it is
    /// answered with [`Response::Null`].
    pub fn failed(request: &Request, error: NfsError) -> Response {
        let attrs = (error, None);
        let wcc = (error, WccData::default());
        match request {
            Request::Null => Response::Null,
            Request::GetAttr(_) => Response::GetAttr(Err(error)),
            Request::SetAttr { .. } => Response::SetAttr(Err(wcc)),
            Request::Lookup(_) => Response::Lookup(Err(attrs)),
            Request::Access { .. } => Response::Access(Err(attrs)),
            Request::ReadLink(_) => Response::ReadLink(Err(attrs)),
            Request::Read { .. } => Response::Read(Err(attrs)),
            Request::Write { .. } => Response::Write(Err(wcc)),
            Request::Create { .. } => Response::Create(Err(wcc)),
            Request::Mkdir { .. } => Response::Mkdir(Err(wcc)),
            Request::Symlink { .. } => Response::Symlink(Err(wcc)),
            Request::Mknod { .. } => Response::Mknod(Err(wcc)),
            Request::Remove(_) => Response::Remove(Err(wcc)),
            Request::Rmdir(_) => Response::Rmdir(Err(wcc)),
            Request::Rename { .. } => Response::Rename(Err((error, RenameWcc::default()))),
            Request::Link { .. } => Response::Link(Err((error, LinkWcc::default()))),
            Request::ReadDir { .. } => Response::ReadDir(Err(attrs)),
            Request::ReadDirPlus { .. } => Response::ReadDirPlus(Err(attrs)),
            Request::FsStat(_) => Response::FsStat(Err(attrs)),
            Request::FsInfo(_) => Response::FsInfo(Err(attrs)),
            Request::PathConf(_) => Response::PathConf(Err(attrs)),
            Request::Commit { .. } => Response::Commit(Err(wcc)),
        }
    }

    /// Reads the results `results` of procedure `procedure`, as a client
    /// does. They must end where the last field does. A procedure past
    /// COMMIT is refused as [`XdrError::Discriminant`].
    pub fn parse(procedure: u32, results: &[u8]) -> Result<Response, XdrError> {
        let r = &mut Reader::new(results);
        let response = match procedure {
            procedure::NULL => Response::Null,
            procedure::GETATTR => {
                Response::GetAttr(read_outcome(r, Fattr::read, |_| Ok(())).map(|o| o.map_err(|(e, ())| e))?)
            }
            procedure::SETATTR => Response::SetAttr(read_outcome(r, WccData::read, WccData::read)?),
            procedure::LOOKUP => Response::Lookup(read_outcome(
                r,
                |r| {
                    Ok(LookupOk {
                        object: FileHandle::read(r)?,
                        object_attributes: read_post_op(r)?,
                        dir_attributes: read_post_op(r)?,
                    })
                },
                read_post_op,
            )?),
            procedure::ACCESS => Response::Access(read_outcome(
                r,
                |r| Ok(AccessOk { attributes: read_post_op(r)?, access: r.uint()? }),
                read_post_op,
            )?),
            procedure::READLINK => Response::ReadLink(read_outcome(
                r,
                |r| Ok(ReadLinkOk { attributes: read_post_op(r)?, target: read_symlink(r)? }),
                read_post_op,
            )?),
            procedure::READ => Response::Read(read_outcome(
                r,
                |r| {
                    let attributes = read_post_op(r)?;
                    let count = r.uint()?;
                    let eof = r.bool()?;
                    Ok(ReadOk { attributes, count, eof, data: read_data(r, count)? })
                },
                read_post_op,
            )?),
            procedure::WRITE => Response::Write(read_outcome(
                r,
                |r| {
                    Ok(WriteOk {
                        wcc: WccData::read(r)?,
                        count: r.uint()?,
                        committed: StableHow::read(r)?,
                        verf: read_verifier(r)?,
                    })
                },
                WccData::read,
            )?),
            procedure::CREATE => Response::Create(read_outcome(r, read_create_ok, WccData::read)?),
            procedure::MKDIR => Response::Mkdir(read_outcome(r, read_create_ok, WccData::read)?),
            procedure::SYMLINK => Response::Symlink(read_outcome(r, read_create_ok, WccData::read)?),
            procedure::MKNOD => Response::Mknod(read_outcome(r, read_create_ok, WccData::read)?),
            procedure::REMOVE => Response::Remove(read_outcome(r, WccData::read, WccData::read)?),
            procedure::RMDIR => Response::Rmdir(read_outcome(r, WccData::read, WccData::read)?),
            procedure::RENAME => Response::Rename(read_outcome(r, read_rename_wcc, read_rename_wcc)?),
            procedure::LINK => Response::Link(read_outcome(r, read_link_wcc, read_link_wcc)?),
            procedure::READDIR => Response::ReadDir(read_outcome(
                r,
                |r| {
                    Ok(ReadDirOk {
                        attributes: read_post_op(r)?,
                        cookieverf: read_verifier(r)?,
                        entries: read_list(r, MAX_DIR_ENTRIES, MAX_DIR_BYTES, |r| {
                            Ok(Entry { fileid: r.uhyper()?, name: read_name(r)?, cookie: r.uhyper()? })
                        })?,
                        eof: r.bool()?,
                    })
                },
                read_post_op,
            )?),
            procedure::READDIRPLUS => Response::ReadDirPlus(read_outcome(
                r,
                |r| {
                    Ok(ReadDirPlusOk {
                        attributes: read_post_op(r)?,
                        cookieverf: read_verifier(r)?,
                        entries: read_list(r, MAX_DIR_ENTRIES, MAX_DIR_BYTES, |r| {
                            Ok(EntryPlus {
                                fileid: r.uhyper()?,
                                name: read_name(r)?,
                                cookie: r.uhyper()?,
                                attributes: read_post_op(r)?,
                                handle: r.optional(FileHandle::read)?,
                            })
                        })?,
                        eof: r.bool()?,
                    })
                },
                read_post_op,
            )?),
            procedure::FSSTAT => Response::FsStat(read_outcome(
                r,
                |r| {
                    Ok(FsStatOk {
                        attributes: read_post_op(r)?,
                        tbytes: r.uhyper()?,
                        fbytes: r.uhyper()?,
                        abytes: r.uhyper()?,
                        tfiles: r.uhyper()?,
                        ffiles: r.uhyper()?,
                        afiles: r.uhyper()?,
                        invarsec: r.uint()?,
                    })
                },
                read_post_op,
            )?),
            procedure::FSINFO => Response::FsInfo(read_outcome(
                r,
                |r| {
                    Ok(FsInfoOk {
                        attributes: read_post_op(r)?,
                        rtmax: r.uint()?,
                        rtpref: r.uint()?,
                        rtmult: r.uint()?,
                        wtmax: r.uint()?,
                        wtpref: r.uint()?,
                        wtmult: r.uint()?,
                        dtpref: r.uint()?,
                        maxfilesize: r.uhyper()?,
                        time_delta: Time::read(r)?,
                        properties: r.uint()?,
                    })
                },
                read_post_op,
            )?),
            procedure::PATHCONF => Response::PathConf(read_outcome(
                r,
                |r| {
                    Ok(PathConfOk {
                        attributes: read_post_op(r)?,
                        linkmax: r.uint()?,
                        name_max: r.uint()?,
                        no_trunc: r.bool()?,
                        chown_restricted: r.bool()?,
                        case_insensitive: r.bool()?,
                        case_preserving: r.bool()?,
                    })
                },
                read_post_op,
            )?),
            procedure::COMMIT => Response::Commit(read_outcome(
                r,
                |r| Ok(CommitOk { wcc: WccData::read(r)?, verf: read_verifier(r)? }),
                WccData::read,
            )?),
            n => return Err(XdrError::Discriminant(n)),
        };
        r.finish()?;
        Ok(response)
    }

    /// The procedure this answers.
    pub fn procedure(&self) -> u32 {
        match self {
            Response::Null => procedure::NULL,
            Response::GetAttr(_) => procedure::GETATTR,
            Response::SetAttr(_) => procedure::SETATTR,
            Response::Lookup(_) => procedure::LOOKUP,
            Response::Access(_) => procedure::ACCESS,
            Response::ReadLink(_) => procedure::READLINK,
            Response::Read(_) => procedure::READ,
            Response::Write(_) => procedure::WRITE,
            Response::Create(_) => procedure::CREATE,
            Response::Mkdir(_) => procedure::MKDIR,
            Response::Symlink(_) => procedure::SYMLINK,
            Response::Mknod(_) => procedure::MKNOD,
            Response::Remove(_) => procedure::REMOVE,
            Response::Rmdir(_) => procedure::RMDIR,
            Response::Rename(_) => procedure::RENAME,
            Response::Link(_) => procedure::LINK,
            Response::ReadDir(_) => procedure::READDIR,
            Response::ReadDirPlus(_) => procedure::READDIRPLUS,
            Response::FsStat(_) => procedure::FSSTAT,
            Response::FsInfo(_) => procedure::FSINFO,
            Response::PathConf(_) => procedure::PATHCONF,
            Response::Commit(_) => procedure::COMMIT,
        }
    }

    /// The results in XDR, which [`Response::parse`] always reads back.
    /// Invalid fields and oversized lists return an error. Counts and
    /// EOF flags must match the value the parser would return.
    pub fn to_results(&self) -> Result<Vec<u8>, XdrError> {
        let w = &mut Writer::new();
        match self {
            Response::Null => {}
            Response::GetAttr(res) => match res {
                Ok(a) => {
                    w.uint(0);
                    a.write(w);
                }
                Err(e) => {
                    w.uint(e.code());
                }
            },
            Response::SetAttr(res) | Response::Remove(res) | Response::Rmdir(res) => {
                write_outcome(w, res, |w, d| d.write(w), |w, d| d.write(w))
            }
            Response::Lookup(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    ok.object.write(w);
                    write_post_op(w, &ok.object_attributes);
                    write_post_op(w, &ok.dir_attributes);
                },
                write_post_op,
            ),
            Response::Access(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.uint(ok.access);
                },
                write_post_op,
            ),
            Response::ReadLink(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    write_opaque(w, &ok.target, MAX_SYMLINK);
                },
                write_post_op,
            ),
            Response::Read(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.uint(ok.count).bool(ok.eof);
                    write_opaque(w, &ok.data, MAX_DATA);
                },
                write_post_op,
            ),
            Response::Write(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    ok.wcc.write(w);
                    w.uint(ok.count);
                    ok.committed.write(w);
                    w.opaque_fixed(&ok.verf);
                },
                |w, d| d.write(w),
            ),
            Response::Create(res) | Response::Mkdir(res) | Response::Symlink(res) | Response::Mknod(res) => {
                write_outcome(
                    w,
                    res,
                    |w, ok| {
                        w.optional(ok.object.as_ref(), |w, fh| fh.write(w));
                        write_post_op(w, &ok.attributes);
                        ok.dir_wcc.write(w);
                    },
                    |w, d| d.write(w),
                )
            }
            Response::Rename(res) => {
                let both = |w: &mut Writer, d: &RenameWcc| {
                    d.from_dir.write(w);
                    d.to_dir.write(w);
                };
                write_outcome(w, res, both, both)
            }
            Response::Link(res) => {
                let both = |w: &mut Writer, d: &LinkWcc| {
                    write_post_op(w, &d.attributes);
                    d.dir_wcc.write(w);
                };
                write_outcome(w, res, both, both)
            }
            Response::ReadDir(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.opaque_fixed(&ok.cookieverf);
                    let named = ok.entries.iter();
                    write_list(w, named, MAX_DIR_ENTRIES, MAX_DIR_BYTES, |w, e| {
                        w.uhyper(e.fileid);
                        write_opaque(w, &e.name, MAX_NAME);
                        w.uhyper(e.cookie);
                    });
                    w.bool(ok.eof);
                },
                write_post_op,
            ),
            Response::ReadDirPlus(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.opaque_fixed(&ok.cookieverf);
                    let named = ok.entries.iter();
                    write_list(w, named, MAX_DIR_ENTRIES, MAX_DIR_BYTES, |w, e| {
                        w.uhyper(e.fileid);
                        write_opaque(w, &e.name, MAX_NAME);
                        w.uhyper(e.cookie);
                        write_post_op(w, &e.attributes);
                        w.optional(e.handle.as_ref(), |w, fh| fh.write(w));
                    });
                    w.bool(ok.eof);
                },
                write_post_op,
            ),
            Response::FsStat(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.uhyper(ok.tbytes).uhyper(ok.fbytes).uhyper(ok.abytes);
                    w.uhyper(ok.tfiles).uhyper(ok.ffiles).uhyper(ok.afiles).uint(ok.invarsec);
                },
                write_post_op,
            ),
            Response::FsInfo(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.uint(ok.rtmax).uint(ok.rtpref).uint(ok.rtmult);
                    w.uint(ok.wtmax).uint(ok.wtpref).uint(ok.wtmult);
                    w.uint(ok.dtpref).uhyper(ok.maxfilesize);
                    ok.time_delta.write(w);
                    w.uint(ok.properties);
                },
                write_post_op,
            ),
            Response::PathConf(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    write_post_op(w, &ok.attributes);
                    w.uint(ok.linkmax).uint(ok.name_max);
                    w.bool(ok.no_trunc)
                        .bool(ok.chown_restricted)
                        .bool(ok.case_insensitive)
                        .bool(ok.case_preserving);
                },
                write_post_op,
            ),
            Response::Commit(res) => write_outcome(
                w,
                res,
                |w, ok| {
                    ok.wcc.write(w);
                    w.opaque_fixed(&ok.verf);
                },
                |w, d| d.write(w),
            ),
        }
        let bytes = std::mem::take(w).finish()?;
        if Self::parse(self.procedure(), &bytes).as_ref() != Ok(self) {
            return Err(XdrError::NonCanonical);
        }
        Ok(bytes)
    }

    /// An RPC reply that carries these results, with an AUTH_NONE
    /// verifier.
    pub fn reply(&self) -> Result<Reply, XdrError> {
        Ok(Reply::success(self.to_results()?))
    }
}

/// Why a MOUNT procedure failed: a mountstat3 other than MNT3_OK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MountError {
    /// Not the owner (1).
    Perm,
    /// No such file or directory (2).
    NoEnt,
    /// An I/O error (5).
    Io,
    /// Permission denied (13).
    Acces,
    /// Not a directory (20).
    NotDir,
    /// An argument is not valid (22).
    Inval,
    /// The path is too long (63).
    NameTooLong,
    /// The operation is not supported (10004).
    NotSupp,
    /// The server failed in a way no other code covers (10006).
    ServerFault,
    /// Any other nonzero code. A code that has its own variant writes the
    /// same, but reads back as that variant.
    Other(NonZeroU32),
}

impl MountError {
    /// The mountstat3 number.
    pub fn code(self) -> u32 {
        match self {
            MountError::Perm => 1,
            MountError::NoEnt => 2,
            MountError::Io => 5,
            MountError::Acces => 13,
            MountError::NotDir => 20,
            MountError::Inval => 22,
            MountError::NameTooLong => 63,
            MountError::NotSupp => 10004,
            MountError::ServerFault => 10006,
            MountError::Other(n) => n.get(),
        }
    }

    /// The error for mountstat3 `code`, or `None` for 0, MNT3_OK.
    pub fn from_code(code: u32) -> Option<MountError> {
        Some(match code {
            1 => MountError::Perm,
            2 => MountError::NoEnt,
            5 => MountError::Io,
            13 => MountError::Acces,
            20 => MountError::NotDir,
            22 => MountError::Inval,
            63 => MountError::NameTooLong,
            10004 => MountError::NotSupp,
            10006 => MountError::ServerFault,
            n => MountError::Other(NonZeroU32::new(n)?),
        })
    }
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            MountError::Perm => "not the owner",
            MountError::NoEnt => "no such file or directory",
            MountError::Io => "I/O error",
            MountError::Acces => "permission denied",
            MountError::NotDir => "not a directory",
            MountError::Inval => "invalid argument",
            MountError::NameTooLong => "path too long",
            MountError::NotSupp => "operation not supported",
            MountError::ServerFault => "server fault",
            MountError::Other(n) => return write!(f, "MOUNT error {n}"),
        };
        f.write_str(text)
    }
}

impl std::error::Error for MountError {}

/// The arguments of a MOUNT version 3 call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountRequest {
    /// Procedure 0: do nothing.
    Null,
    /// Procedure 1: get the handle of an exported directory, by its path
    /// on the server, at most [`MAX_PATH`] bytes. A longer one is written
    /// empty.
    Mnt(Vec<u8>),
    /// Procedure 2: list which hosts have mounted what.
    Dump,
    /// Procedure 3: say the caller no longer uses this path.
    Umnt(Vec<u8>),
    /// Procedure 4: say the caller no longer uses any path.
    UmntAll,
    /// Procedure 5: list the exported directories.
    Export,
}

impl MountRequest {
    /// Reads the request a call makes. When the call is not one, the error
    /// is the status a server replies with, as for [`Request::parse`].
    pub fn parse(call: &Call) -> Result<MountRequest, Accept> {
        if call.program != MOUNT_PROGRAM {
            return Err(Accept::ProgUnavail);
        }
        if call.version != MOUNT_VERSION {
            return Err(Accept::ProgMismatch { low: MOUNT_VERSION, high: MOUNT_VERSION });
        }
        if call.procedure > mount_procedure::EXPORT {
            return Err(Accept::ProcUnavail);
        }
        MountRequest::read(call.procedure, &call.args).map_err(|_| Accept::GarbageArgs)
    }

    /// Reads the arguments `args` of MOUNT procedure `procedure`. A
    /// procedure past EXPORT is refused as [`XdrError::Discriminant`].
    pub fn read(procedure: u32, args: &[u8]) -> Result<MountRequest, XdrError> {
        let r = &mut Reader::new(args);
        let request = match procedure {
            mount_procedure::NULL => MountRequest::Null,
            mount_procedure::MNT => MountRequest::Mnt(read_path(r)?),
            mount_procedure::DUMP => MountRequest::Dump,
            mount_procedure::UMNT => MountRequest::Umnt(read_path(r)?),
            mount_procedure::UMNTALL => MountRequest::UmntAll,
            mount_procedure::EXPORT => MountRequest::Export,
            n => return Err(XdrError::Discriminant(n)),
        };
        r.finish()?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            MountRequest::Null => mount_procedure::NULL,
            MountRequest::Mnt(_) => mount_procedure::MNT,
            MountRequest::Dump => mount_procedure::DUMP,
            MountRequest::Umnt(_) => mount_procedure::UMNT,
            MountRequest::UmntAll => mount_procedure::UMNTALL,
            MountRequest::Export => mount_procedure::EXPORT,
        }
    }

    /// The call's arguments. Paths above [`MAX_PATH`] return an error.
    pub fn to_args(&self) -> Result<Vec<u8>, XdrError> {
        let mut w = Writer::new();
        if let MountRequest::Mnt(path) | MountRequest::Umnt(path) = self {
            write_opaque(&mut w, path, MAX_PATH);
        }
        let bytes = w.finish()?;
        if Self::read(self.procedure(), &bytes).as_ref() != Ok(self) {
            return Err(XdrError::NonCanonical);
        }
        Ok(bytes)
    }

    /// A call message that makes this request, with AUTH_NONE.
    pub fn call(&self, xid: u32) -> Result<Message, XdrError> {
        let call = Call::new(MOUNT_PROGRAM, MOUNT_VERSION, self.procedure(), self.to_args()?);
        Ok(Message { xid, body: super::onc_rpc::Body::Call(call) })
    }
}

/// The results of a successful MNT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mounted {
    /// The handle of the exported directory: the root of what the client
    /// sees.
    pub handle: FileHandle,
    /// The RPC authentication flavors the server takes, such as
    /// [`flavor::SYS`](super::onc_rpc::flavor::SYS). At most
    /// [`MAX_AUTH_FLAVORS`].
    pub auth_flavors: Vec<u32>,
}

/// One mount in a DUMP result (mountbody).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MountEntry {
    /// The client's host name, at most [`MAX_MOUNT_NAME`] bytes. A writer
    /// leaves out an entry with a longer one.
    pub hostname: String,
    /// The path it mounted, at most [`MAX_PATH`] bytes. A writer leaves
    /// out an entry with a longer one.
    pub directory: Vec<u8>,
}

/// One exported directory in an EXPORT result (exportnode).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExportEntry {
    /// The path, at most [`MAX_PATH`] bytes. A writer leaves out an export
    /// with a longer one.
    pub directory: Vec<u8>,
    /// The hosts or groups that may mount it, each at most
    /// [`MAX_MOUNT_NAME`] bytes, and at most [`MAX_GROUPS`] of them. An
    /// empty list means any host may, so a writer writes a longer name
    /// empty rather than leave it out.
    pub groups: Vec<String>,
}

/// The results of a MOUNT version 3 procedure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountResponse {
    /// To NULL: nothing.
    Null,
    /// To MNT: the handle, or why there is none.
    Mnt(Result<Mounted, MountError>),
    /// To DUMP: the mounts, at most [`MAX_MOUNTS`].
    Dump(Vec<MountEntry>),
    /// To UMNT: nothing.
    Umnt,
    /// To UMNTALL: nothing.
    UmntAll,
    /// To EXPORT: the exports, at most [`MAX_EXPORTS`]. A writer also stops
    /// before [`MAX_EXPORT_BYTES`].
    Export(Vec<ExportEntry>),
}

impl MountResponse {
    /// Reads the results `results` of MOUNT procedure `procedure`. A
    /// procedure past EXPORT is refused as [`XdrError::Discriminant`].
    pub fn parse(procedure: u32, results: &[u8]) -> Result<MountResponse, XdrError> {
        let r = &mut Reader::new(results);
        let response = match procedure {
            mount_procedure::NULL => MountResponse::Null,
            mount_procedure::MNT => MountResponse::Mnt(match MountError::from_code(r.uint()?) {
                None => Ok(Mounted {
                    handle: FileHandle::read(r)?,
                    auth_flavors: r.array(MAX_AUTH_FLAVORS, Reader::uint)?,
                }),
                Some(e) => Err(e),
            }),
            mount_procedure::DUMP => MountResponse::Dump(read_list(r, MAX_MOUNTS, usize::MAX, |r| {
                Ok(MountEntry { hostname: read_mount_name(r)?, directory: read_path(r)? })
            })?),
            mount_procedure::UMNT => MountResponse::Umnt,
            mount_procedure::UMNTALL => MountResponse::UmntAll,
            mount_procedure::EXPORT => {
                MountResponse::Export(read_list(r, MAX_EXPORTS, EXPORT_LIST_BYTES, |r| {
                    Ok(ExportEntry {
                        directory: read_path(r)?,
                        groups: read_list(r, MAX_GROUPS, usize::MAX, read_mount_name)?,
                    })
                })?)
            }
            n => return Err(XdrError::Discriminant(n)),
        };
        r.finish()?;
        Ok(response)
    }

    /// The procedure this answers.
    pub fn procedure(&self) -> u32 {
        match self {
            MountResponse::Null => mount_procedure::NULL,
            MountResponse::Mnt(_) => mount_procedure::MNT,
            MountResponse::Dump(_) => mount_procedure::DUMP,
            MountResponse::Umnt => mount_procedure::UMNT,
            MountResponse::UmntAll => mount_procedure::UMNTALL,
            MountResponse::Export(_) => mount_procedure::EXPORT,
        }
    }

    /// The results in XDR, which [`MountResponse::parse`] always reads
    /// back. Invalid handles, names, paths, and lists return an error.
    pub fn to_results(&self) -> Result<Vec<u8>, XdrError> {
        let w = &mut Writer::new();
        match self {
            MountResponse::Null | MountResponse::Umnt | MountResponse::UmntAll => {}
            MountResponse::Mnt(Ok(m)) => {
                w.uint(0);
                m.handle.write(w);
                if m.auth_flavors.len() > MAX_AUTH_FLAVORS {
                    return Err(XdrError::TooLong(u32::try_from(m.auth_flavors.len()).unwrap_or(u32::MAX)));
                }
                let flavors = &m.auth_flavors;
                w.array(flavors, |w, f| {
                    w.uint(*f);
                });
            }
            MountResponse::Mnt(Err(e)) => {
                w.uint(e.code());
            }
            MountResponse::Dump(mounts) => {
                let kept = mounts.iter();
                write_list(w, kept, MAX_MOUNTS, usize::MAX, |w, m| {
                    write_opaque(w, m.hostname.as_bytes(), MAX_MOUNT_NAME);
                    write_opaque(w, &m.directory, MAX_PATH);
                });
            }
            MountResponse::Export(exports) => {
                // One export is at most about 68 KB, so the first always
                // fits in EXPORT_LIST_BYTES.
                let kept = exports.iter();
                write_list(w, kept, MAX_EXPORTS, EXPORT_LIST_BYTES, |w, e| {
                    write_opaque(w, &e.directory, MAX_PATH);
                    write_list(w, e.groups.iter(), MAX_GROUPS, usize::MAX, |w, g| {
                        write_opaque(w, g.as_bytes(), MAX_MOUNT_NAME);
                    });
                });
            }
        }
        let bytes = std::mem::take(w).finish()?;
        if Self::parse(self.procedure(), &bytes).as_ref() != Ok(self) {
            return Err(XdrError::NonCanonical);
        }
        Ok(bytes)
    }

    /// An RPC reply that carries these results, with an AUTH_NONE
    /// verifier.
    pub fn reply(&self) -> Result<Reply, XdrError> {
        Ok(Reply::success(self.to_results()?))
    }
}

/// Reads a union on nfsstat3: `ok` for NFS3_OK, else the error and `fail`.
fn read_outcome<'a, T, F>(
    r: &mut Reader<'a>,
    ok: impl FnOnce(&mut Reader<'a>) -> Result<T, XdrError>,
    fail: impl FnOnce(&mut Reader<'a>) -> Result<F, XdrError>,
) -> Result<Outcome<T, F>, XdrError> {
    match NfsError::from_code(r.uint()?) {
        None => Ok(Ok(ok(r)?)),
        Some(e) => Ok(Err((e, fail(r)?))),
    }
}

/// Writes a union on nfsstat3.
fn write_outcome<T, F>(
    w: &mut Writer,
    res: &Outcome<T, F>,
    ok: impl FnOnce(&mut Writer, &T),
    fail: impl FnOnce(&mut Writer, &F),
) {
    match res {
        Ok(t) => {
            w.uint(0);
            ok(w, t);
        }
        Err((e, f)) => {
            w.uint(e.code());
            fail(w, f);
        }
    }
}

/// The most bytes the items of an EXPORT list take: all of
/// [`MAX_EXPORT_BYTES`] but the word that ends the list.
const EXPORT_LIST_BYTES: usize = MAX_EXPORT_BYTES - 4;

/// Reads a linked list (a chain of optional items) of at most `max`
/// items, in a loop, not by recursion. The items, each with the word
/// before it, take at most `max_bytes`.
fn read_list<'a, T>(
    r: &mut Reader<'a>,
    max: usize,
    max_bytes: usize,
    mut item: impl FnMut(&mut Reader<'a>) -> Result<T, XdrError>,
) -> Result<Vec<T>, XdrError> {
    let start = r.position();
    let mut out = Vec::new();
    while r.bool()? {
        if out.len() >= max {
            return Err(XdrError::TooLong(u32::try_from(out.len()).unwrap_or(u32::MAX).saturating_add(1)));
        }
        out.push(item(r)?);
        let used = r.position() - start;
        if used > max_bytes {
            return Err(XdrError::TooLong(u32::try_from(used).unwrap_or(u32::MAX)));
        }
    }
    Ok(out)
}

/// Appends a complete linked list within its count and byte limits.
fn write_list<'a, T: 'a>(
    w: &mut Writer,
    items: impl IntoIterator<Item = &'a T>,
    max: usize,
    max_bytes: usize,
    mut item: impl FnMut(&mut Writer, &T),
) {
    let mut used = 0usize;
    for (written, value) in items.into_iter().enumerate() {
        if written >= max {
            w.reject(XdrError::TooLong(u32::try_from(written).unwrap_or(u32::MAX)));
            return;
        }
        let mut one = Writer::new();
        one.bool(true);
        item(&mut one, value);
        let one = match one.finish() {
            Ok(bytes) => bytes,
            Err(error) => {
                w.reject(error);
                return;
            }
        };
        let Some(total) = used.checked_add(one.len()).filter(|n| *n <= max_bytes) else {
            w.reject(XdrError::TooLong(u32::try_from(max_bytes).unwrap_or(u32::MAX)));
            return;
        };
        w.opaque_fixed(&one);
        used = total;
    }
    w.bool(false);
}

/// Reads variable-length data of at most [`MAX_DATA`] bytes, which must be
/// `count` bytes long.
fn read_data(r: &mut Reader<'_>, count: u32) -> Result<Vec<u8>, XdrError> {
    let data = r.opaque(MAX_DATA)?;
    if data.len() != count as usize {
        return Err(XdrError::TooLong(count.max(data.len() as u32)));
    }
    Ok(data.to_vec())
}

fn read_create_ok(r: &mut Reader<'_>) -> Result<CreateOk, XdrError> {
    Ok(CreateOk {
        object: r.optional(FileHandle::read)?,
        attributes: read_post_op(r)?,
        dir_wcc: WccData::read(r)?,
    })
}

fn read_rename_wcc(r: &mut Reader<'_>) -> Result<RenameWcc, XdrError> {
    Ok(RenameWcc { from_dir: WccData::read(r)?, to_dir: WccData::read(r)? })
}

fn read_link_wcc(r: &mut Reader<'_>) -> Result<LinkWcc, XdrError> {
    Ok(LinkWcc { attributes: read_post_op(r)?, dir_wcc: WccData::read(r)? })
}

fn read_verifier(r: &mut Reader<'_>) -> Result<[u8; VERIFIER_LEN], XdrError> {
    let b = r.opaque_fixed(VERIFIER_LEN)?;
    let mut v = [0; VERIFIER_LEN];
    v.copy_from_slice(b);
    Ok(v)
}

fn read_name(r: &mut Reader<'_>) -> Result<Vec<u8>, XdrError> {
    Ok(r.opaque(MAX_NAME)?.to_vec())
}

fn read_path(r: &mut Reader<'_>) -> Result<Vec<u8>, XdrError> {
    Ok(r.opaque(MAX_PATH)?.to_vec())
}

fn read_symlink(r: &mut Reader<'_>) -> Result<Vec<u8>, XdrError> {
    Ok(r.opaque(MAX_SYMLINK)?.to_vec())
}

fn read_mount_name(r: &mut Reader<'_>) -> Result<String, XdrError> {
    Ok(r.string(MAX_MOUNT_NAME)?.to_owned())
}

/// Appends a bounded opaque field, or records a writer error.
fn write_opaque(w: &mut Writer, bytes: &[u8], max: usize) {
    if bytes.len() > max {
        w.reject(XdrError::TooLong(u32::try_from(bytes.len()).unwrap_or(u32::MAX)));
    } else {
        w.opaque(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::super::onc_rpc::{Body, MAX_RECORD, Record, records};
    use super::*;
    use crate::stdlib::codec::test_support::Lcg;
    use crate::stdlib::codec::{Assembled, Stream, Wire, contract, finish, pump, test_support};

    fn fh(b: &[u8]) -> FileHandle {
        FileHandle(b.to_vec())
    }

    fn op(dir: &[u8], name: &str) -> DirOp {
        DirOp { dir: fh(dir), name: name.into() }
    }

    fn attrs() -> Fattr {
        Fattr {
            kind: FileType::Regular,
            mode: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 100,
            size: 5,
            used: 4096,
            rdev: SpecData::default(),
            fsid: 7,
            fileid: 42,
            atime: Time { seconds: 1, nseconds: 2 },
            mtime: Time { seconds: 3, nseconds: 4 },
            ctime: Time { seconds: 5, nseconds: 6 },
        }
    }

    fn wcc() -> WccData {
        WccData {
            before: Some(WccAttr {
                size: 1,
                mtime: Time::default(),
                ctime: Time { seconds: 9, nseconds: 0 },
            }),
            after: Some(attrs()),
        }
    }

    fn sattr() -> Sattr {
        Sattr {
            mode: Some(0o755),
            uid: None,
            gid: Some(5),
            size: Some(0),
            atime: SetTime::ServerTime,
            mtime: SetTime::ClientTime(Time { seconds: 10, nseconds: 11 }),
        }
    }

    /// One request of every procedure, with every union arm.
    fn requests() -> Vec<Request> {
        vec![
            Request::Null,
            Request::GetAttr(fh(&[1, 2, 3])),
            Request::SetAttr {
                object: fh(&[1]),
                attributes: sattr(),
                guard: Some(Time { seconds: 5, nseconds: 6 }),
            },
            Request::SetAttr { object: fh(&[1]), attributes: Sattr::default(), guard: None },
            Request::Lookup(op(&[1], "notes.txt")),
            Request::Access { object: fh(&[2]), access: access::READ | access::LOOKUP },
            Request::ReadLink(fh(&[3])),
            Request::Read { file: fh(&[2]), offset: 1 << 40, count: 4096 },
            Request::Write {
                file: fh(&[2]),
                offset: 0,
                count: 5,
                stable: StableHow::FileSync,
                data: b"hello".to_vec(),
            },
            Request::Write { file: fh(&[2]), offset: 9, count: 0, stable: StableHow::DataSync, data: vec![] },
            Request::Create { location: op(&[1], "a"), how: CreateHow::Unchecked(sattr()) },
            Request::Create { location: op(&[1], "b"), how: CreateHow::Guarded(Sattr::default()) },
            Request::Create { location: op(&[1], "c"), how: CreateHow::Exclusive([1, 2, 3, 4, 5, 6, 7, 8]) },
            Request::Mkdir { location: op(&[1], "dir"), attributes: sattr() },
            Request::Symlink {
                location: op(&[1], "ln"),
                attributes: Sattr::default(),
                target: "/etc/passwd".into(),
            },
            Request::Mknod {
                location: op(&[1], "tty"),
                what: MknodData::Character { attributes: sattr(), spec: SpecData { major: 4, minor: 1 } },
            },
            Request::Mknod {
                location: op(&[1], "sda"),
                what: MknodData::Block {
                    attributes: Sattr::default(),
                    spec: SpecData { major: 8, minor: 0 },
                },
            },
            Request::Mknod { location: op(&[1], "sock"), what: MknodData::Socket(sattr()) },
            Request::Mknod { location: op(&[1], "pipe"), what: MknodData::Fifo(Sattr::default()) },
            Request::Mknod { location: op(&[1], "f"), what: MknodData::Regular },
            Request::Mknod { location: op(&[1], "d"), what: MknodData::Directory },
            Request::Mknod { location: op(&[1], "l"), what: MknodData::Symlink },
            Request::Remove(op(&[1], "a")),
            Request::Rmdir(op(&[1], "dir")),
            Request::Rename { from: op(&[1], "a"), to: op(&[9, 9], "b") },
            Request::Link { file: fh(&[2]), link: op(&[1], "hard") },
            Request::ReadDir { dir: fh(&[1]), cookie: 0, cookieverf: [0; 8], count: 8192 },
            Request::ReadDirPlus {
                dir: fh(&[1]),
                cookie: 3,
                cookieverf: [9; 8],
                dircount: 1024,
                maxcount: 8192,
            },
            Request::FsStat(fh(&[1])),
            Request::FsInfo(fh(&[1])),
            Request::PathConf(fh(&[1])),
            Request::Commit { file: fh(&[2]), offset: 0, count: 0 },
        ]
    }

    /// One response of every procedure, both successful and failed.
    fn responses() -> Vec<Response> {
        let create = CreateOk { object: Some(fh(&[4])), attributes: Some(attrs()), dir_wcc: wcc() };
        let bare = CreateOk { object: None, attributes: None, dir_wcc: WccData::default() };
        vec![
            Response::Null,
            Response::GetAttr(Ok(attrs())),
            Response::GetAttr(Err(NfsError::Stale)),
            Response::SetAttr(Ok(wcc())),
            Response::SetAttr(Err((NfsError::NotSync, wcc()))),
            Response::Lookup(Ok(LookupOk {
                object: fh(&[2]),
                object_attributes: Some(attrs()),
                dir_attributes: None,
            })),
            Response::Lookup(Err((NfsError::NoEnt, Some(attrs())))),
            Response::Access(Ok(AccessOk { attributes: None, access: access::READ })),
            Response::Access(Err((NfsError::Acces, None))),
            Response::ReadLink(Ok(ReadLinkOk { attributes: Some(attrs()), target: "../x".into() })),
            Response::ReadLink(Err((NfsError::Inval, None))),
            Response::Read(Ok(ReadOk {
                attributes: Some(attrs()),
                count: 5,
                eof: true,
                data: b"hello".to_vec(),
            })),
            Response::Read(Err((NfsError::IsDir, None))),
            Response::Write(Ok(WriteOk {
                wcc: wcc(),
                count: 5,
                committed: StableHow::Unstable,
                verf: [7; 8],
            })),
            Response::Write(Err((NfsError::Nospc, WccData::default()))),
            Response::Create(Ok(create.clone())),
            Response::Create(Err((NfsError::Exist, wcc()))),
            Response::Mkdir(Ok(bare.clone())),
            Response::Mkdir(Err((NfsError::Rofs, WccData::default()))),
            Response::Symlink(Ok(create)),
            Response::Symlink(Err((NfsError::NotSupp, WccData::default()))),
            Response::Mknod(Ok(bare)),
            Response::Mknod(Err((NfsError::BadType, WccData::default()))),
            Response::Remove(Ok(wcc())),
            Response::Remove(Err((NfsError::NoEnt, WccData::default()))),
            Response::Rmdir(Ok(WccData::default())),
            Response::Rmdir(Err((NfsError::NotEmpty, wcc()))),
            Response::Rename(Ok(RenameWcc { from_dir: wcc(), to_dir: WccData::default() })),
            Response::Rename(Err((NfsError::Xdev, RenameWcc::default()))),
            Response::Link(Ok(LinkWcc { attributes: Some(attrs()), dir_wcc: wcc() })),
            Response::Link(Err((NfsError::Mlink, LinkWcc::default()))),
            Response::ReadDir(Ok(ReadDirOk {
                attributes: None,
                cookieverf: [1; 8],
                entries: vec![
                    Entry { fileid: 1, name: ".".into(), cookie: 1 },
                    Entry { fileid: 2, name: "notes.txt".into(), cookie: 2 },
                ],
                eof: true,
            })),
            Response::ReadDir(Ok(ReadDirOk {
                attributes: Some(attrs()),
                cookieverf: [0; 8],
                entries: vec![],
                eof: false,
            })),
            Response::ReadDir(Err((NfsError::BadCookie, None))),
            Response::ReadDirPlus(Ok(ReadDirPlusOk {
                attributes: Some(attrs()),
                cookieverf: [2; 8],
                entries: vec![
                    EntryPlus {
                        fileid: 2,
                        name: "a".into(),
                        cookie: 1,
                        attributes: Some(attrs()),
                        handle: Some(fh(&[5])),
                    },
                    EntryPlus { fileid: 3, name: "b".into(), cookie: 2, attributes: None, handle: None },
                ],
                eof: false,
            })),
            Response::ReadDirPlus(Err((NfsError::TooSmall, Some(attrs())))),
            Response::FsStat(Ok(FsStatOk {
                attributes: None,
                tbytes: 1 << 40,
                fbytes: 1 << 30,
                abytes: 1 << 29,
                tfiles: 1000,
                ffiles: 900,
                afiles: 800,
                invarsec: 0,
            })),
            Response::FsStat(Err((NfsError::Io, None))),
            Response::FsInfo(Ok(FsInfoOk {
                attributes: Some(attrs()),
                rtmax: 1 << 20,
                rtpref: 1 << 16,
                rtmult: 4096,
                wtmax: 1 << 20,
                wtpref: 1 << 16,
                wtmult: 4096,
                dtpref: 8192,
                maxfilesize: u64::MAX,
                time_delta: Time { seconds: 0, nseconds: 1 },
                properties: fsf::LINK | fsf::SYMLINK | fsf::HOMOGENEOUS | fsf::CANSETTIME,
            })),
            Response::FsInfo(Err((NfsError::ServerFault, None))),
            Response::PathConf(Ok(PathConfOk {
                attributes: None,
                linkmax: 32000,
                name_max: 255,
                no_trunc: true,
                chown_restricted: true,
                case_insensitive: false,
                case_preserving: true,
            })),
            Response::PathConf(Err((NfsError::Other(NonZeroU32::new(12345).unwrap()), None))),
            Response::Commit(Ok(CommitOk { wcc: wcc(), verf: [3; 8] })),
            Response::Commit(Err((NfsError::Jukebox, wcc()))),
        ]
    }

    fn mount_requests() -> Vec<MountRequest> {
        vec![
            MountRequest::Null,
            MountRequest::Mnt("/export/home".into()),
            MountRequest::Dump,
            MountRequest::Umnt("/export/home".into()),
            MountRequest::UmntAll,
            MountRequest::Export,
        ]
    }

    fn mount_responses() -> Vec<MountResponse> {
        vec![
            MountResponse::Null,
            MountResponse::Mnt(Ok(Mounted { handle: fh(&[1; 32]), auth_flavors: vec![0, 1] })),
            MountResponse::Mnt(Err(MountError::Acces)),
            MountResponse::Dump(vec![]),
            MountResponse::Dump(vec![
                MountEntry { hostname: "client1".into(), directory: "/export".into() },
                MountEntry { hostname: "client2".into(), directory: "/export/home".into() },
            ]),
            MountResponse::Umnt,
            MountResponse::UmntAll,
            MountResponse::Export(vec![]),
            MountResponse::Export(vec![
                ExportEntry { directory: "/export".into(), groups: vec![] },
                ExportEntry { directory: "/data".into(), groups: vec!["10.0.0.0/8".into(), "lab".into()] },
            ]),
        ]
    }

    #[test]
    fn getattr_call_bytes() {
        // RFC 1813, section 3.3.1: GETATTR3args is one nfs_fh3.
        let call = Request::GetAttr(fh(&[0xab, 0xcd, 0xef])).call(1).unwrap();
        let bytes = call.to_bytes().unwrap();
        assert_eq!(
            bytes,
            [
                0, 0, 0, 1, // xid
                0, 0, 0, 0, // call
                0, 0, 0, 2, // RPC version
                0, 1, 0x86, 0xa3, // program 100003
                0, 0, 0, 3, // version 3
                0, 0, 0, 1, // GETATTR
                0, 0, 0, 0, 0, 0, 0, 0, // AUTH_NONE credential
                0, 0, 0, 0, 0, 0, 0, 0, // AUTH_NONE verifier
                0, 0, 0, 3, 0xab, 0xcd, 0xef, 0, // the handle, padded
            ]
        );
        let Body::Call(c) = Message::parse(&bytes).unwrap().body else { panic!() };
        assert_eq!(Request::parse(&c), Ok(Request::GetAttr(fh(&[0xab, 0xcd, 0xef]))));
    }

    #[test]
    fn fattr_is_84_bytes() {
        let mut w = Writer::new();
        attrs().write(&mut w);
        let b = w.finish().unwrap();
        assert_eq!(b.len(), 84);
        // type, mode, nlink, uid, gid, size: in that order.
        assert_eq!(
            &b[..28],
            &[0, 0, 0, 1, 0, 0, 1, 0xa4, 0, 0, 0, 1, 0, 0, 3, 0xe8, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 5]
        );
        let mut r = Reader::new(&b);
        assert_eq!(Fattr::read(&mut r), Ok(attrs()));
        r.finish().unwrap();
    }

    #[test]
    fn lookup_and_write_args_bytes() {
        let args = Request::Lookup(op(&[1, 2], "a")).to_args().unwrap();
        assert_eq!(args, [0, 0, 0, 2, 1, 2, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 0]);
        let args =
            Request::Write { file: fh(&[]), offset: 2, count: 1, stable: StableHow::FileSync, data: vec![9] }
                .to_args()
                .unwrap();
        assert_eq!(
            args,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 9, 0, 0, 0]
        );
    }

    #[test]
    fn readdir_results_are_a_chain() {
        let resp = Response::ReadDir(Ok(ReadDirOk {
            attributes: None,
            cookieverf: [0; 8],
            entries: vec![Entry { fileid: 5, name: "x".into(), cookie: 6 }],
            eof: true,
        }));
        let b = resp.to_results().unwrap();
        assert_eq!(
            b,
            [
                0, 0, 0, 0, // NFS3_OK
                0, 0, 0, 0, // no directory attributes
                0, 0, 0, 0, 0, 0, 0, 0, // cookie verifier
                0, 0, 0, 1, // an entry follows
                0, 0, 0, 0, 0, 0, 0, 5, // fileid
                0, 0, 0, 1, b'x', 0, 0, 0, // name
                0, 0, 0, 0, 0, 0, 0, 6, // cookie
                0, 0, 0, 0, // no more entries
                0, 0, 0, 1, // eof
            ]
        );
        assert_eq!(Response::parse(procedure::READDIR, &b), Ok(resp));
    }

    #[test]
    fn mount_bytes() {
        let m = MountRequest::Mnt("/x".into()).call(3).unwrap();
        let Body::Call(c) = &m.body else { panic!() };
        assert_eq!((c.program, c.version, c.procedure), (100_005, 3, 1));
        assert_eq!(c.args, [0, 0, 0, 2, b'/', b'x', 0, 0]);
        let r = MountResponse::Mnt(Ok(Mounted { handle: fh(&[7]), auth_flavors: vec![1] }));
        assert_eq!(r.to_results().unwrap(), [0, 0, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]);
        let e = MountResponse::Export(vec![ExportEntry { directory: "/".into(), groups: vec!["g".into()] }]);
        assert_eq!(
            e.to_results().unwrap(),
            [
                0, 0, 0, 1, 0, 0, 0, 1, b'/', 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, b'g', 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0
            ]
        );
        assert_eq!(MountResponse::Mnt(Err(MountError::NoEnt)).to_results().unwrap(), [0, 0, 0, 2]);
    }

    #[test]
    fn requests_round_trip() {
        for req in requests() {
            let args = req.to_args().unwrap();
            assert_eq!(Request::read(req.procedure(), &args), Ok(req.clone()), "{req:?}");
            let m = Message::parse(&req.call(5).unwrap().to_bytes().unwrap()).unwrap();
            let Body::Call(c) = &m.body else { panic!() };
            assert_eq!(Request::parse(c), Ok(req.clone()));
            // Every strict prefix is refused.
            for n in 0..args.len() {
                assert!(Request::read(req.procedure(), &args[..n]).is_err(), "{req:?} at {n}");
            }
            // So are bytes left over.
            let mut longer = args.clone();
            longer.extend_from_slice(&[0; 4]);
            assert_eq!(Request::read(req.procedure(), &longer), Err(XdrError::Trailing(4)));
        }
        for req in mount_requests() {
            let args = req.to_args().unwrap();
            assert_eq!(MountRequest::read(req.procedure(), &args), Ok(req.clone()));
            let Body::Call(c) = req.call(1).unwrap().body else { panic!() };
            assert_eq!(MountRequest::parse(&c), Ok(req.clone()));
            for n in 0..args.len() {
                assert!(MountRequest::read(req.procedure(), &args[..n]).is_err());
            }
            let mut longer = args.clone();
            longer.extend_from_slice(&[0; 4]);
            assert_eq!(MountRequest::read(req.procedure(), &longer), Err(XdrError::Trailing(4)));
        }
    }

    #[test]
    fn requests_compose_with_codec_records() {
        use crate::stdlib::{
            codec::{Decode, Wire, contract},
            onc_rpc,
        };

        const RECORD_LIMIT: usize = 4096;
        let make = || {
            onc_rpc::messages(RECORD_LIMIT).map(|message| {
                message.map(|message| match message.body {
                    Body::Call(call) => Some((message.xid, Request::read(call.procedure, &call.args))),
                    Body::Reply(_) => None,
                })
            })
        };
        for request in requests() {
            let message = request.call(19).unwrap();
            let bytes = <Message as Wire>::to_bytes(&message).unwrap();
            contract::check_wire::<Message>(&bytes);
            contract::check_decode(make, &onc_rpc::encode_fragments(&bytes, 5).unwrap());
        }
    }

    #[test]
    fn responses_round_trip() {
        for resp in responses() {
            let b = resp.to_results().unwrap();
            assert_eq!(Response::parse(resp.procedure(), &b), Ok(resp.clone()), "{resp:?}");
            assert_eq!(resp.reply().unwrap(), Reply::success(b.clone()));
            for n in 0..b.len() {
                assert!(Response::parse(resp.procedure(), &b[..n]).is_err(), "{resp:?} at {n}");
            }
            let mut longer = b.clone();
            longer.push(0);
            assert_eq!(Response::parse(resp.procedure(), &longer), Err(XdrError::Trailing(1)));
        }
        for resp in mount_responses() {
            let b = resp.to_results().unwrap();
            assert_eq!(MountResponse::parse(resp.procedure(), &b), Ok(resp.clone()), "{resp:?}");
            assert_eq!(resp.reply().unwrap(), Reply::success(b.clone()));
            for n in 0..b.len() {
                assert!(MountResponse::parse(resp.procedure(), &b[..n]).is_err(), "{resp:?} at {n}");
            }
        }
    }

    #[test]
    fn failed_answers_every_request() {
        for req in requests() {
            let resp = Response::failed(&req, NfsError::Perm);
            assert_eq!(resp.procedure(), req.procedure());
            let b = resp.to_results().unwrap();
            if req != Request::Null {
                assert_eq!(&b[..4], &[0, 0, 0, 1]);
            }
            assert_eq!(Response::parse(req.procedure(), &b), Ok(resp));
        }
    }

    #[test]
    fn calls_that_are_not_nfs() {
        let mut c = Call::new(
            NFS_PROGRAM,
            NFS_VERSION,
            procedure::GETATTR,
            Request::GetAttr(fh(&[1])).to_args().unwrap(),
        );
        assert!(Request::parse(&c).is_ok());
        c.program = 100_000;
        assert_eq!(Request::parse(&c), Err(Accept::ProgUnavail));
        c.program = NFS_PROGRAM;
        c.version = 2;
        assert_eq!(Request::parse(&c), Err(Accept::ProgMismatch { low: 3, high: 3 }));
        c.version = 3;
        c.procedure = 22;
        assert_eq!(Request::parse(&c), Err(Accept::ProcUnavail));
        c.procedure = procedure::GETATTR;
        c.args.push(0);
        assert_eq!(Request::parse(&c), Err(Accept::GarbageArgs));
        c.args.clear();
        assert_eq!(Request::parse(&c), Err(Accept::GarbageArgs));
        assert_eq!(Request::read(22, &[]), Err(XdrError::Discriminant(22)));

        let mut m = Call::new(MOUNT_PROGRAM, MOUNT_VERSION, mount_procedure::EXPORT, vec![]);
        assert_eq!(MountRequest::parse(&m), Ok(MountRequest::Export));
        m.program = NFS_PROGRAM;
        assert_eq!(MountRequest::parse(&m), Err(Accept::ProgUnavail));
        m.program = MOUNT_PROGRAM;
        m.version = 1;
        assert_eq!(MountRequest::parse(&m), Err(Accept::ProgMismatch { low: 3, high: 3 }));
        m.version = 3;
        m.procedure = 6;
        assert_eq!(MountRequest::parse(&m), Err(Accept::ProcUnavail));
        m.procedure = mount_procedure::EXPORT;
        m.args = vec![0; 4];
        assert_eq!(MountRequest::parse(&m), Err(Accept::GarbageArgs));
        assert_eq!(MountRequest::read(6, &[]), Err(XdrError::Discriminant(6)));
        assert_eq!(Response::parse(22, &[]), Err(XdrError::Discriminant(22)));
        assert_eq!(MountResponse::parse(6, &[]), Err(XdrError::Discriminant(6)));
    }

    #[test]
    fn bad_fields_are_refused() {
        // A handle over 64 bytes.
        let mut b = vec![0, 0, 0, 65];
        b.extend_from_slice(&[0; 68]);
        assert_eq!(Request::read(procedure::GETATTR, &b), Err(XdrError::TooLong(65)));
        // A name over 255 bytes.
        let long = "n".repeat(256);
        let mut w = Writer::new();
        w.opaque(&[1]).string(&long);
        assert_eq!(Request::read(procedure::LOOKUP, w.as_bytes()), Err(XdrError::TooLong(256)));
        // Padding that is not zero.
        assert_eq!(Request::read(procedure::GETATTR, &[0, 0, 0, 1, 1, 0, 0, 1]), Err(XdrError::Padding));
        // stable_how 3.
        let mut w = Writer::new();
        w.opaque(&[1]).uhyper(0).uint(0).uint(3).opaque(&[]);
        assert_eq!(Request::read(procedure::WRITE, w.as_bytes()), Err(XdrError::Discriminant(3)));
        // createmode 3.
        let mut args = Request::Lookup(op(&[1], "a")).to_args().unwrap();
        args.extend_from_slice(&[0, 0, 0, 3]);
        assert_eq!(Request::read(procedure::CREATE, &args), Err(XdrError::Discriminant(3)));
        // time_how 3, in an sattr3 with nothing else set.
        let mut args = Request::Lookup(op(&[1], "a")).to_args().unwrap();
        args.extend_from_slice(&[0; 16]);
        args.extend_from_slice(&[0, 0, 0, 3, 0, 0, 0, 0]);
        assert_eq!(Request::read(procedure::MKDIR, &args), Err(XdrError::Discriminant(3)));
        // ftype3 0 and 8.
        let mut args = Request::Lookup(op(&[1], "a")).to_args().unwrap();
        args.extend_from_slice(&[0, 0, 0, 8]);
        assert_eq!(Request::read(procedure::MKNOD, &args), Err(XdrError::Discriminant(8)));
        let mut b = vec![0, 0, 0, 0];
        b.extend_from_slice(&[0; 84]);
        assert_eq!(Response::parse(procedure::GETATTR, &b), Err(XdrError::Discriminant(0)));
        // A boolean of 2 for a guard.
        let mut w = Writer::new();
        w.opaque(&[1]);
        Sattr::default().write(&mut w);
        w.uint(2);
        assert_eq!(Request::read(procedure::SETATTR, w.as_bytes()), Err(XdrError::Bool(2)));
        // Data over MAX_DATA in WRITE, refused by its length alone.
        let mut w = Writer::new();
        w.opaque(&[1]).uhyper(0).uint(0).uint(0).uint(MAX_DATA as u32 + 1);
        assert_eq!(
            Request::read(procedure::WRITE, w.as_bytes()),
            Err(XdrError::TooLong(MAX_DATA as u32 + 1))
        );
        // A symlink target over MAX_SYMLINK.
        let mut w = Writer::new();
        w.opaque(&[1]).string("l");
        Sattr::default().write(&mut w);
        w.string(&"t".repeat(MAX_SYMLINK + 1));
        assert_eq!(Request::read(procedure::SYMLINK, w.as_bytes()), Err(XdrError::TooLong(4097)));
        // Too many auth flavors.
        let mut w = Writer::new();
        w.uint(0).opaque(&[1]).uint(17);
        assert_eq!(MountResponse::parse(mount_procedure::MNT, w.as_bytes()), Err(XdrError::TooLong(17)));
        // A mount host name over MAX_MOUNT_NAME.
        let mut w = Writer::new();
        w.bool(true).string(&"h".repeat(256));
        assert_eq!(MountResponse::parse(mount_procedure::DUMP, w.as_bytes()), Err(XdrError::TooLong(256)));
    }

    #[test]
    fn symlink_targets_are_not_mount_paths() {
        // nfspath3 is string<>, with no MNTPATHLEN bound. Linux servers
        // allow PATH_MAX (4096) bytes, so a 2000-byte target must read.
        let target = "t".repeat(2000);
        let req =
            Request::Symlink { location: op(&[1], "l"), attributes: Sattr::default(), target: target.into() };
        assert_eq!(Request::read(procedure::SYMLINK, &req.to_args().unwrap()), Ok(req));
        let resp = Response::ReadLink(Ok(ReadLinkOk { attributes: None, target: vec![b'x'; MAX_SYMLINK] }));
        assert_eq!(Response::parse(procedure::READLINK, &resp.to_results().unwrap()), Ok(resp));
        let mut w = Writer::new();
        w.uint(0).bool(false).string(&"x".repeat(MAX_SYMLINK + 1));
        assert_eq!(Response::parse(procedure::READLINK, w.as_bytes()), Err(XdrError::TooLong(4097)));
        // A MOUNT dirpath keeps its MNTPATHLEN bound.
        let mut w = Writer::new();
        w.string(&"p".repeat(MAX_PATH + 1));
        assert_eq!(MountRequest::read(mount_procedure::MNT, w.as_bytes()), Err(XdrError::TooLong(1025)));
    }

    #[test]
    fn long_lists_are_refused() {
        let entries = |n: usize| {
            let mut w = Writer::new();
            w.uint(0).bool(false).opaque_fixed(&[0; 8]);
            for i in 0..n {
                w.bool(true).uhyper(i as u64).string("e").uhyper(i as u64);
            }
            w.bool(false).bool(true);
            w.finish().unwrap()
        };
        // Each entry takes 28 bytes with the word before it.
        let most = MAX_DIR_BYTES / 28;
        assert!(Response::parse(procedure::READDIR, &entries(most)).is_ok());
        assert_eq!(
            Response::parse(procedure::READDIR, &entries(most + 1)),
            Err(XdrError::TooLong((28 * (most + 1)) as u32))
        );
        let groups = |n: usize| {
            let mut w = Writer::new();
            w.bool(true).string("/");
            for _ in 0..n {
                w.bool(true).string("g");
            }
            w.bool(false).bool(false);
            w.finish().unwrap()
        };
        assert!(MountResponse::parse(mount_procedure::EXPORT, &groups(MAX_GROUPS)).is_ok());
        assert_eq!(
            MountResponse::parse(mount_procedure::EXPORT, &groups(MAX_GROUPS + 1)),
            Err(XdrError::TooLong(MAX_GROUPS as u32 + 1))
        );
    }

    #[test]
    fn errors_and_codes() {
        assert_eq!(NfsError::from_code(0), None);
        assert_eq!(MountError::from_code(0), None);
        for code in (1..=100).chain(10_000..=10_010).chain([u32::MAX]) {
            assert_eq!(NfsError::from_code(code).unwrap().code(), code);
            assert_eq!(MountError::from_code(code).unwrap().code(), code);
        }
        assert_eq!(NfsError::from_code(70), Some(NfsError::Stale));
        assert_eq!(NfsError::from_code(10008), Some(NfsError::Jukebox));
        assert_eq!(MountError::from_code(13), Some(MountError::Acces));
        assert_eq!(NfsError::NoEnt.to_string(), "no such file or directory");
        assert_eq!(NfsError::from_code(3).unwrap().to_string(), "NFS error 3");
        assert_eq!(MountError::from_code(3).unwrap().to_string(), "MOUNT error 3");
        for code in 0..10 {
            if let Some(t) = FileType::from_code(code) {
                assert_eq!(t.code(), code);
            } else {
                assert!(code == 0 || code > 7);
            }
        }
        // An unknown status reads as Other and writes back the same.
        let b = [0, 0, 0, 99];
        let resp = Response::parse(procedure::GETATTR, &b).unwrap();
        assert_eq!(resp, Response::GetAttr(Err(NfsError::Other(NonZeroU32::new(99).unwrap()))));
        assert_eq!(resp.to_results().unwrap(), b);
    }

    #[test]
    fn writers_refuse_long_handles_names_and_paths() {
        let long_fh = FileHandle(vec![1; MAX_FH + 1]);
        assert!(!long_fh.fits());
        for request in [
            Request::GetAttr(long_fh.clone()),
            Request::Lookup(DirOp { dir: fh(&[1]), name: vec![b'n'; MAX_NAME + 1] }),
            Request::Symlink {
                location: op(&[1], "l"),
                attributes: Sattr::default(),
                target: vec![b't'; MAX_SYMLINK + 1],
            },
        ] {
            assert!(request.to_args().is_err());
        }
        for response in [
            Response::ReadLink(Ok(ReadLinkOk { attributes: None, target: vec![b'x'; MAX_SYMLINK + 1] })),
            Response::Create(Ok(CreateOk { object: Some(long_fh.clone()), ..CreateOk::default() })),
        ] {
            assert!(response.to_results().is_err());
        }
        assert!(MountRequest::Mnt(vec![b'p'; MAX_PATH + 1]).to_args().is_err());
        for mounted in [
            Mounted { handle: long_fh, auth_flavors: vec![1] },
            Mounted { handle: fh(&[1]), auth_flavors: vec![1; MAX_AUTH_FLAVORS + 1] },
        ] {
            assert!(MountResponse::Mnt(Ok(mounted)).to_results().is_err());
        }
    }

    #[test]
    fn list_writers_refuse_invalid_entries() {
        let response = Response::ReadDir(Ok(ReadDirOk {
            entries: vec![Entry { fileid: 2, name: vec![b'n'; MAX_NAME + 1], cookie: 2 }],
            eof: true,
            ..ReadDirOk::default()
        }));
        assert!(response.to_results().is_err());
        for entry in [
            EntryPlus { name: vec![b'n'; MAX_NAME + 1], ..EntryPlus::default() },
            EntryPlus { handle: Some(FileHandle(vec![1; MAX_FH + 1])), ..EntryPlus::default() },
        ] {
            assert!(
                Response::ReadDirPlus(Ok(ReadDirPlusOk { entries: vec![entry], ..ReadDirPlusOk::default() }))
                    .to_results()
                    .is_err()
            );
        }
        for entry in [
            ExportEntry { directory: vec![b'd'; MAX_PATH + 1], groups: vec![] },
            ExportEntry { directory: b"/x".to_vec(), groups: vec!["g".repeat(MAX_MOUNT_NAME + 1)] },
        ] {
            assert!(MountResponse::Export(vec![entry]).to_results().is_err());
        }
        for entry in [
            MountEntry { hostname: "h".repeat(MAX_MOUNT_NAME + 1), directory: b"/".to_vec() },
            MountEntry { hostname: "h".into(), directory: vec![b'd'; MAX_PATH + 1] },
        ] {
            assert!(MountResponse::Dump(vec![entry]).to_results().is_err());
        }
        let entry = MountEntry { hostname: "h".into(), directory: b"/".to_vec() };
        assert!(MountResponse::Dump(vec![entry; MAX_MOUNTS + 1]).to_results().is_err());
    }

    #[test]
    fn names_are_bytes() {
        // RFC 1813 sets no character set; Linux servers take Latin-1 names.
        let mut w = Writer::new();
        w.opaque(&[1]).opaque(&[0xff]);
        assert_eq!(
            Request::read(procedure::LOOKUP, w.as_bytes()),
            Ok(Request::Lookup(DirOp { dir: fh(&[1]), name: vec![0xff] }))
        );
        // A READDIR reply with one such name reads, and writes back the same.
        let b = [
            0, 0, 0, 0, // NFS3_OK
            0, 0, 0, 0, // no directory attributes
            0, 0, 0, 0, 0, 0, 0, 0, // cookie verifier
            0, 0, 0, 1, // an entry follows
            0, 0, 0, 0, 0, 0, 0, 5, // fileid
            0, 0, 0, 2, b'\xe9', b't', 0, 0, // name: "et" with e-acute in Latin-1
            0, 0, 0, 0, 0, 0, 0, 6, // cookie
            0, 0, 0, 0, // no more entries
            0, 0, 0, 1, // eof
        ];
        let resp = Response::parse(procedure::READDIR, &b).unwrap();
        let Response::ReadDir(Ok(ok)) = &resp else { panic!() };
        assert_eq!(ok.entries[0].name, [0xe9, b't']);
        assert_eq!(resp.to_results().unwrap(), b);
        // And a MOUNT path.
        let mut w = Writer::new();
        w.opaque(b"/caf\xe9");
        assert_eq!(MountRequest::read(1, w.as_bytes()), Ok(MountRequest::Mnt(b"/caf\xe9".to_vec())));
    }

    #[test]
    fn read_and_write_counts_match_their_data() {
        // RFC 1813, sections 3.3.6 and 3.3.7: count is the number of bytes
        // of data. Linux refuses a mismatch on both sides.
        let mut w = Writer::new();
        w.uint(0).bool(false).uint(2).bool(true).opaque(b"x");
        assert_eq!(Response::parse(procedure::READ, w.as_bytes()), Err(XdrError::TooLong(2)));
        let mut w = Writer::new();
        w.opaque(&[1]).uhyper(0).uint(2).uint(0).opaque(b"xyz");
        assert_eq!(Request::read(procedure::WRITE, w.as_bytes()), Err(XdrError::TooLong(3)));
        let request = Request::Write {
            file: fh(&[1]),
            offset: 0,
            count: 9,
            stable: StableHow::Unstable,
            data: vec![1; 4],
        };
        assert!(request.to_args().is_err());
        let request = Request::Write {
            file: fh(&[1]),
            offset: 0,
            count: MAX_DATA as u32 + 3,
            stable: StableHow::Unstable,
            data: vec![1; MAX_DATA + 3],
        };
        assert!(request.to_args().is_err());
        let response = Response::Read(Ok(ReadOk {
            attributes: None,
            count: MAX_DATA as u32 + 1,
            eof: true,
            data: vec![0; MAX_DATA + 1],
        }));
        assert!(response.to_results().is_err());
        let resp = Response::Read(Ok(ReadOk { attributes: None, count: 3, eof: true, data: vec![0; 3] }));
        assert_eq!(Response::parse(procedure::READ, &resp.to_results().unwrap()), Ok(resp));
    }

    #[test]
    fn export_lists_read_only_what_writes_back() {
        // 16 exports, each with 256 groups of 255 bytes: about 1.08 MB,
        // past MAX_EXPORT_BYTES. A reader refuses it rather than take a
        // list a writer would cut.
        let exports: Vec<ExportEntry> = (0..16)
            .map(|i| ExportEntry {
                directory: format!("/e{i:02}").into_bytes(),
                groups: (0..MAX_GROUPS).map(|g| format!("{g:03}{}", "g".repeat(252))).collect(),
            })
            .collect();
        let mut w = Writer::new();
        for e in &exports {
            w.bool(true).opaque(&e.directory);
            for g in &e.groups {
                w.bool(true).string(g);
            }
            w.bool(false);
        }
        w.bool(false);
        let b = w.finish().unwrap();
        assert!(b.len() > MAX_EXPORT_BYTES);
        assert!(matches!(MountResponse::parse(mount_procedure::EXPORT, &b), Err(XdrError::TooLong(_))));
        assert!(MountResponse::Export(exports.clone()).to_results().is_err());
        let response = MountResponse::Export(exports[..15].to_vec());
        let bytes = response.to_results().unwrap();
        assert_eq!(MountResponse::parse(mount_procedure::EXPORT, &bytes), Ok(response));
        assert!(
            MountResponse::Export(vec![
                ExportEntry { directory: b"/".to_vec(), groups: vec![] };
                MAX_EXPORTS + 5
            ])
            .to_results()
            .is_err()
        );
    }

    #[test]
    fn directory_lists_follow_a_byte_limit() {
        // A READDIR asked with count 65536 may carry 1025 short entries.
        let entries: Vec<Entry> = (0..1025)
            .map(|i| Entry { fileid: i, name: format!("{i:04}").into_bytes(), cookie: i + 1 })
            .collect();
        let resp = Response::ReadDir(Ok(ReadDirOk { entries, eof: true, ..ReadDirOk::default() }));
        let b = resp.to_results().unwrap();
        assert!(b.len() < 65536);
        assert_eq!(Response::parse(procedure::READDIR, &b), Ok(resp));
        let entries = (0..MAX_DIR_BYTES as u64 / 28 + 1)
            .map(|i| Entry { fileid: i, name: b"e".to_vec(), cookie: i + 1 })
            .collect();
        let response = Response::ReadDir(Ok(ReadDirOk { entries, eof: true, ..ReadDirOk::default() }));
        assert!(response.to_results().is_err());
        let entries = vec![EntryPlus::default(); MAX_DIR_BYTES / 32 + 1];
        let response =
            Response::ReadDirPlus(Ok(ReadDirPlusOk { entries, eof: true, ..ReadDirPlusOk::default() }));
        assert!(response.to_results().is_err());
        // A list within the limit keeps its eof.
        let entries = vec![EntryPlus::default(); MAX_DIR_BYTES / 32];
        let resp =
            Response::ReadDirPlus(Ok(ReadDirPlusOk { entries, eof: true, ..ReadDirPlusOk::default() }));
        assert_eq!(Response::parse(procedure::READDIRPLUS, &resp.to_results().unwrap()), Ok(resp));
    }

    #[test]
    fn largest_messages_fit_in_a_record() {
        // Values within each protocol limit fit in a strict RPC record.
        let fat = FileHandle(vec![1; MAX_FH]);
        let name = vec![b'n'; MAX_NAME];
        let path = vec![b'p'; MAX_PATH];
        let group = "g".repeat(MAX_MOUNT_NAME);
        let plus = EntryPlus {
            fileid: 1,
            name: name.clone(),
            cookie: 2,
            attributes: Some(attrs()),
            handle: Some(fat.clone()),
        };
        let replies = [
            Response::Read(Ok(ReadOk {
                attributes: Some(attrs()),
                count: MAX_DATA as u32,
                eof: true,
                data: vec![7; MAX_DATA],
            }))
            .reply()
            .unwrap(),
            Response::ReadDirPlus(Ok(ReadDirPlusOk {
                attributes: Some(attrs()),
                entries: vec![plus; MAX_DIR_BYTES / 440],
                ..ReadDirPlusOk::default()
            }))
            .reply()
            .unwrap(),
            MountResponse::Export(vec![
                ExportEntry {
                    directory: path.clone(),
                    groups: vec![group; MAX_GROUPS]
                };
                MAX_EXPORT_BYTES / (MAX_PATH + 12 + MAX_GROUPS * (MAX_MOUNT_NAME + 9))
            ])
            .reply()
            .unwrap(),
            MountResponse::Dump(vec![
                MountEntry { hostname: "h".repeat(MAX_MOUNT_NAME), directory: path };
                MAX_MOUNTS
            ])
            .reply()
            .unwrap(),
        ];
        let call = Message::parse(&Request::Null.call(1).unwrap().to_bytes().unwrap()).unwrap();
        let mut messages: Vec<Message> = replies.into_iter().map(|r| call.reply(r)).collect();
        messages.push(
            Request::Write {
                file: fat.clone(),
                offset: 0,
                count: MAX_DATA as u32,
                stable: StableHow::Unstable,
                data: vec![1; MAX_DATA],
            }
            .call(2)
            .unwrap(),
        );
        messages.push(
            Request::Symlink {
                location: DirOp { dir: fat, name },
                attributes: sattr(),
                target: vec![b't'; MAX_SYMLINK],
            }
            .call(3)
            .unwrap(),
        );
        for m in messages {
            let bytes = m.to_bytes().unwrap();
            let record = Record(bytes);
            assert_eq!(Record::parse(&record.to_bytes().unwrap()), Ok(record));
        }
    }

    #[test]
    fn calls_over_tcp_one_byte_at_a_time() {
        let mut stream = Vec::new();
        for (i, req) in requests().iter().enumerate() {
            stream
                .extend(Record(req.call(i as u32).unwrap().to_bytes().unwrap().to_vec()).to_bytes().unwrap());
        }
        stream.extend(
            Record(MountRequest::Mnt("/export".into()).call(99).unwrap().to_bytes().unwrap().to_vec())
                .to_bytes()
                .unwrap(),
        );
        let mut d = Stream::new(records(MAX_RECORD));
        let mut got = Vec::new();
        let mut mounts = Vec::new();
        contract::check_decode(|| records(MAX_RECORD), &stream);
        for b in test_support::chunks(&stream, &[1]) {
            pump(&mut d, b, |record| {
                let Assembled::Message(record) = record;
                let m = Message::parse(&record).unwrap();
                let Body::Call(c) = &m.body else { panic!() };
                match c.program {
                    NFS_PROGRAM => got.push(Request::parse(c).unwrap()),
                    _ => mounts.push(MountRequest::parse(c).unwrap()),
                }
            })
            .unwrap();
        }
        finish(&mut d, |_| panic!("unexpected record at EOF")).unwrap();
        assert_eq!(got, requests());
        assert_eq!(mounts, [MountRequest::Mnt("/export".into())]);
    }

    fn random_fattr(rng: &mut Lcg) -> Fattr {
        Fattr {
            kind: FileType::from_code((rng.below(7) as u32) + 1).unwrap(),
            mode: (rng.next() as u32),
            nlink: (rng.next() as u32),
            uid: (rng.next() as u32),
            gid: (rng.next() as u32),
            size: (rng.next() << 32 | rng.next()),
            used: (rng.next() << 32 | rng.next()),
            rdev: SpecData { major: (rng.next() as u32), minor: (rng.next() as u32) },
            fsid: (rng.next() << 32 | rng.next()),
            fileid: (rng.next() << 32 | rng.next()),
            atime: Time { seconds: (rng.next() as u32), nseconds: (rng.next() as u32) },
            mtime: Time { seconds: (rng.next() as u32), nseconds: (rng.next() as u32) },
            ctime: Time { seconds: (rng.next() as u32), nseconds: (rng.next() as u32) },
        }
    }

    /// Checks that `bytes` either fails to read as procedure `p`, or reads
    /// back to exactly the same bytes, for every reader.
    fn check_any(p: u32, bytes: &[u8]) {
        if let Ok(req) = Request::read(p, bytes) {
            assert_eq!(req.to_args().unwrap(), bytes);
        }
        if let Ok(resp) = Response::parse(p, bytes) {
            assert_eq!(resp.to_results().unwrap(), bytes);
        }
        if let Ok(req) = MountRequest::read(p, bytes) {
            assert_eq!(req.to_args().unwrap(), bytes);
        }
        if let Ok(resp) = MountResponse::parse(p, bytes) {
            assert_eq!(resp.to_results().unwrap(), bytes);
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x1813_1833);
        let mut seeds: Vec<(u32, Vec<u8>)> = Vec::new();
        for r in requests() {
            seeds.push((r.procedure(), r.to_args().unwrap()));
        }
        for r in responses() {
            seeds.push((r.procedure(), r.to_results().unwrap()));
        }
        for r in mount_requests() {
            seeds.push((r.procedure(), r.to_args().unwrap()));
        }
        for r in mount_responses() {
            seeds.push((r.procedure(), r.to_results().unwrap()));
        }
        for _ in 0..20_000 {
            let (p, seed) = &seeds[(rng.below(seeds.len() as u64) as u32) as usize];
            let mut b = seed.clone();
            // Mutate: flip bytes, set small words, cut or grow.
            for _ in 0..=(rng.below(4) as u32) {
                match rng.below(5) as u32 {
                    0 if !b.is_empty() => {
                        let i = (rng.below(b.len() as u64) as u32) as usize;
                        b[i] = (rng.next() as u32) as u8;
                    }
                    1 if b.len() >= 4 => {
                        let i = (rng.below(b.len() as u64 / 4) as u32) as usize * 4;
                        b[i..i + 4].copy_from_slice(&(rng.below(4) as u32).to_be_bytes());
                    }
                    2 if !b.is_empty() => {
                        let n = (rng.below(b.len() as u64) as u32) as usize;
                        b.truncate(n);
                    }
                    3 => b.extend((0..(rng.below(12) as u32)).map(|_| (rng.next() as u32) as u8)),
                    _ => {}
                }
            }
            let p = if (rng.below(8) as u32) == 0 { rng.below(24) as u32 } else { *p };
            check_any(p, &b);
        }
        // Fully random bytes, for every procedure number and a few past.
        for _ in 0..5_000 {
            let len = (rng.below(200) as u32) as usize;
            let b: Vec<u8> = (0..len)
                .map(|_| if (rng.next() as u32) & 1 == 1 { 0 } else { (rng.next() as u32) as u8 })
                .collect();
            check_any(rng.below(24) as u32, &b);
        }
        // Random values round trip.
        for _ in 0..2_000 {
            let a = random_fattr(&mut rng);
            let entries: Vec<EntryPlus> = (0..(rng.below(5) as u32))
                .map(|i| EntryPlus {
                    fileid: (rng.next() << 32 | rng.next()),
                    name: (0..(rng.below(300) as u32)).map(|_| (rng.next() as u32) as u8).collect(),
                    cookie: u64::from(i),
                    attributes: ((rng.next() as u32) & 1 == 1).then_some(a),
                    handle: ((rng.next() as u32) & 1 == 1)
                        .then(|| FileHandle(vec![7; (rng.below(80) as u32) as usize])),
                })
                .collect();
            let resp = Response::ReadDirPlus(Ok(ReadDirPlusOk {
                attributes: ((rng.next() as u32) & 1 == 1).then_some(a),
                cookieverf: (rng.next() << 32 | rng.next()).to_be_bytes(),
                entries,
                eof: ((rng.next() as u32) & 1 == 1),
            }));
            if let Ok(bytes) = resp.to_results() {
                assert_eq!(Response::parse(procedure::READDIRPLUS, &bytes), Ok(resp));
            }
            let req = Request::SetAttr {
                object: FileHandle(vec![3; (rng.below(70) as u32) as usize]),
                attributes: Sattr {
                    mode: ((rng.next() as u32) & 1 == 1).then(|| rng.next() as u32),
                    uid: ((rng.next() as u32) & 1 == 1).then(|| rng.next() as u32),
                    gid: ((rng.next() as u32) & 1 == 1).then(|| rng.next() as u32),
                    size: ((rng.next() as u32) & 1 == 1).then(|| rng.next() << 32 | rng.next()),
                    atime: [SetTime::DontChange, SetTime::ServerTime, SetTime::ClientTime(a.mtime)]
                        [(rng.below(3) as u32) as usize],
                    mtime: [SetTime::DontChange, SetTime::ServerTime, SetTime::ClientTime(a.ctime)]
                        [(rng.below(3) as u32) as usize],
                },
                guard: ((rng.next() as u32) & 1 == 1).then_some(a.atime),
            };
            if let Ok(args) = req.to_args() {
                assert_eq!(Request::read(procedure::SETATTR, &args), Ok(req));
            }
        }
        // A random stream of records, read one byte at a time.
        let mut stream = Vec::new();
        for _ in 0..300 {
            let mut b = Vec::new();
            b.extend((0..(rng.below(64) as u32)).map(|_| (rng.next() as u32) as u8));
            stream.extend(Record(b.to_vec()).to_bytes().unwrap());
        }
        contract::check_decode(|| records(1 << 16), &stream);
        let mut decoder = Stream::new(records(1 << 16));
        pump(&mut decoder, &stream, |record| {
            let Assembled::Message(record) = record;
            if let Ok(Message { body: Body::Call(call), .. }) = Message::parse(&record) {
                let _ = Request::parse(&call);
                let _ = MountRequest::parse(&call);
            }
            check_any(rng.below(22) as u32, &record);
        })
        .unwrap();
    }
}
