use crate::wire::icmpv4;

use crate::wire::icmpv6;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Repr<'a> {
    Ipv4(icmpv4::Repr<'a>),

    Ipv6(icmpv6::Repr<'a>),
}

impl<'a> From<icmpv4::Repr<'a>> for Repr<'a> {
    fn from(s: icmpv4::Repr<'a>) -> Self {
        Repr::Ipv4(s)
    }
}

impl<'a> From<icmpv6::Repr<'a>> for Repr<'a> {
    fn from(s: icmpv6::Repr<'a>) -> Self {
        Repr::Ipv6(s)
    }
}
