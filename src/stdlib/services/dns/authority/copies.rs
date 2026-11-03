//! Learned copies of real zones, each served at its real servers'
//! addresses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::Request;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name};
use fictionet::sync::Mutex;

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::super::zone::{Learned, ZoneData};
use super::{Authority, ServerConfig, Step, Zones};

/// The [learned](Learned) copies of real zones, one per apex, shared by
/// every address that serves the zone, and the zones each address serves.
///
/// At each address it answers as [`Zones`] over the copies of the zones
/// the address serves, looking up what they lack at the address itself.
/// A world notes which address serves which zone with
/// [`serves`](Copies::serves), such as at the addresses a referral's glue
/// gives. A real server may also serve a zone below one it was noted for,
/// as the root servers serve `arpa`: it answers for the child's names from
/// the child's data, never with a referral to it. When a lookup's
/// response shows that ([`Learned::child_answering`]), the address is
/// noted as serving the child, and the response is filed into the child's
/// copy.
#[derive(Default)]
pub struct Copies {
    /// Each zone's copy, by apex.
    zones: Mutex<HashMap<LowerName, Arc<Learned>>>,
    /// The zones each address serves.
    served: Mutex<HashMap<IpAddr, Vec<LowerName>>>,
}

impl Copies {
    /// Copies of no zone, served nowhere.
    pub fn new() -> Copies {
        Copies::default()
    }

    /// Notes that `addr` serves the zone at `zone`.
    pub fn serves(&self, addr: IpAddr, zone: &LowerName) {
        let mut served = self.served.lock();
        let zones = served.entry(addr).or_default();
        if !zones.contains(zone) {
            zones.push(zone.clone());
        }
    }

    /// The copy of the zone at `apex`, made empty the first time.
    fn copy(&self, apex: &LowerName) -> Arc<Learned> {
        self.zones
            .lock()
            .entry(apex.clone())
            .or_insert_with(|| Arc::new(Learned::new(&Name::from(apex))))
            .clone()
    }

    /// The copies of the zones `addr` serves.
    fn zones_at(&self, addr: IpAddr) -> Vec<Arc<dyn ZoneData>> {
        let apexes = self.served.lock().get(&addr).cloned().unwrap_or_default();
        apexes
            .iter()
            .map(|apex| self.copy(apex) as Arc<dyn ZoneData>)
            .collect()
    }
}

impl Authority for Copies {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        Zones::new(self.zones_at(local.ip())).respond(req, local, server, client)
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        let Looked::Response(response) = looked else {
            return;
        };
        let mut learned = self.copy(&lookup.zone);
        if let Some(child) = learned.child_answering(&lookup.question, response) {
            self.serves(lookup.server.ip(), &child);
            learned = self.copy(&child);
        }
        learned.file(generation, &lookup.question, response);
    }

    fn advance(&self, generation: Generation) {
        let zones: Vec<Arc<Learned>> = self.zones.lock().values().cloned().collect();
        for learned in zones {
            learned.advance(generation);
        }
    }
}
