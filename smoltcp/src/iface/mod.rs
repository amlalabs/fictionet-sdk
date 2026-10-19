/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod fragmentation;
mod interface;

mod route;

mod socket_set;

mod packet;

pub use self::interface::{
    Config, Interface, InterfaceInner as Context, PollIngressSingleResult, PollResult,
};

pub use self::route::{Route, RouteTableFull, Routes};

pub use self::socket_set::{SocketHandle, SocketSet, SocketStorage};
