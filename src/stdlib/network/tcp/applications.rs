use super::*;
use fictionet::stdlib::layer::Children;
use fictionet::stdlib::services::stack::Boxed;

type Make = dyn Fn(TcpOpening, GoneWatch, &Budget) -> Option<Boxed> + Send + Sync;
type SelectBudget = dyn Fn(&TcpOpening, &GoneWatch) -> Budget + Send + Sync;

pub(crate) struct Application {
    pub(crate) make: Arc<Make>,
    pub(crate) budget: Arc<SelectBudget>,
}

type Opening = (TcpOpening, Arc<Application>);
pub(super) type ApplicationEvent = MuxEvent<ByteStream, Messages<TcpNotice, TcpControl>, Opening>;
type ChildrenLayer = Children<Boxed, Messages<TcpNotice, TcpControl>, Opening>;

pub(super) type Applications = super::super::applications::Applications<ChildrenLayer>;

pub(super) fn new(fcx: &Cx, shared: &Arc<Shared>) -> Applications {
    let factory = shared.clone();
    let budgets = shared.clone();
    let children = Children::new(
        4096,
        16 * 1024,
        move |id, (opening, application): Opening, budget| {
            let socket = GoneWatch {
                shared: factory.clone(),
                id,
            };
            (application.make)(opening, socket, budget)
        },
    )
    .close_finished()
    .budgets(move |id, (opening, application), _| {
        (application.budget)(
            opening,
            &GoneWatch {
                shared: budgets.clone(),
                id,
            },
        )
    });
    Applications::new(fcx, children)
}
