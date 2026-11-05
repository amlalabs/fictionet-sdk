//! A SQL Server client and server as their TDS messages describe them.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::protocols::tds::{Column, Login7, TypeInfo, data_type};
//! use fictionet_extras::sql_server;
//!
//! let login = Login7 {
//!     user_name: "sa".into(),
//!     host_name: "WS-17".into(),
//!     ..sql_server::odbc_login()
//! };
//! assert_eq!(Login7::parse(&login.to_bytes()?), Ok(login));
//! let name = Column::new(
//!     "name",
//!     TypeInfo::string(data_type::NVARCHAR, 100, sql_server::LATIN1_GENERAL_CI_AS),
//! );
//! # drop(name);
//! # Ok::<(), fictionet::stdlib::protocols::tds::Error>(())
//! ```

use fictionet::stdlib::protocols::tds::{Login7, tds_version};

/// The collation SQL Server uses by default for US English installations:
/// Latin1_General_CI_AS (case insensitive, accent sensitive), as the five
/// bytes of a TDS collation.
pub const LATIN1_GENERAL_CI_AS: [u8; 5] = [0x09, 0x04, 0xd0, 0x00, 0x34];

/// The login an ODBC client sends: TDS 7.4, 4096-byte packets, the option
/// bits of Microsoft's ODBC driver, US English (locale 0x0409), the client
/// library name "ODBC", and every other string empty. Fill in the user,
/// host, application and the rest.
pub fn odbc_login() -> Login7 {
    Login7 {
        tds_version: tds_version::V7_4,
        packet_size: 4096,
        client_prog_ver: 0,
        client_pid: 0,
        connection_id: 0,
        option_flags1: 0xe0,
        option_flags2: 0x03,
        type_flags: 0,
        option_flags3: 0,
        client_time_zone: 0,
        client_lcid: 0x0409,
        host_name: String::new(),
        user_name: String::new(),
        password: String::new(),
        app_name: String::new(),
        server_name: String::new(),
        client_interface: "ODBC".into(),
        language: String::new(),
        database: String::new(),
        client_id: [0; 6],
        sspi: Vec::new(),
        attach_db_file: String::new(),
        change_password: String::new(),
        features: None,
    }
}
