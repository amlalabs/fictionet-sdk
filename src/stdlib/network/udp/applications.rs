use super::*;
use fictionet::stdlib::layer::{Children, Datagrams};
use fictionet::stdlib::services::stack::Boxed;

type Application = Boxed<Datagrams<SocketAddr>>;
pub(super) type ApplicationEvent = MuxEvent<Datagrams<SocketAddr>, Control, (Application, Budget)>;
type ApplicationsLayer = Children<Application, Control, (Application, Budget)>;

pub(super) type Applications = super::super::applications::Applications<ApplicationsLayer>;

pub(super) fn new(fcx: &Cx) -> Applications {
    let children = Children::new(4096, 1, |_, (application, _), _| Some(application))
        .close_finished()
        .budgets(|_, (_, budget): &(Application, Budget), _| budget.clone());
    Applications::new(fcx, children)
}
