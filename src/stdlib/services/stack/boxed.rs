use std::any::Any;
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::layer::{Admit, ByteStream, CommandOf, Env, EventOf, Layer, Port, Top};
use fictionet::time::Instant;

use super::Job;

/// A report of a boxed stack.
pub struct BoxReport {
    inner: Box<dyn core::fmt::Debug + Send>,
    bytes: Option<usize>,
}

impl core::fmt::Debug for BoxReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}
/// Why a boxed stack gave up.
pub type BoxError = Box<dyn core::error::Error + Send + Sync>;
/// The result of a boxed stack's work: the allocation its work was in.
pub type BoxDone = Box<dyn Any + Send>;

/// A boxed stack's work: a job erased once, in one allocation, which its
/// result comes back in. Boxing it again allocates nothing.
pub struct BoxWork(Option<Box<dyn ErasedJob>>);

impl BoxWork {
    pub(super) fn new<J: Job>(boxing: Boxing<J>) -> BoxWork
    where
        J::Done: Send + 'static,
    {
        BoxWork(Some(Box::new(boxing)))
    }
}

impl Job for BoxWork {
    type Done = BoxDone;

    fn cancelled(&self) -> bool {
        self.0.as_ref().is_some_and(|job| job.cancelled())
    }

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<BoxDone> {
        let job = self
            .0
            .as_mut()
            .expect("boxed work is polled until it is done, not after");
        std::task::ready!(job.poll(fcx, cx));
        Poll::Ready(self.0.take().expect("the job that just finished").finish())
    }

    fn erase(self) -> BoxWork {
        self
    }

    fn claim(done: BoxDone) -> Result<BoxDone, BoxDone> {
        Ok(done)
    }
}

/// What [`BoxWork`] needs of a job.
trait ErasedJob: Send {
    fn cancelled(&self) -> bool;
    /// Moves the work on. Once it is ready, its result waits inside.
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<()>;
    /// The result, in this allocation.
    fn finish(self: Box<Self>) -> BoxDone;
}

/// A stack's work, then its result, in one allocation.
pub(super) struct Boxing<J: Job> {
    /// The work, until it is done.
    job: Option<J>,
    /// Its result, until it is claimed.
    pub(super) done: Option<J::Done>,
}

impl<J: Job> Boxing<J> {
    pub(super) fn new(job: J) -> Boxing<J> {
        Boxing {
            job: Some(job),
            done: None,
        }
    }
}

impl<J: Job> ErasedJob for Boxing<J>
where
    J::Done: Send + 'static,
{
    fn cancelled(&self) -> bool {
        self.job.as_ref().is_some_and(Job::cancelled)
    }

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<()> {
        let Some(job) = &mut self.job else {
            return Poll::Ready(());
        };
        let done = std::task::ready!(job.poll(fcx, cx));
        // Released as soon as it is done, as the work's contract asks.
        self.job = None;
        self.done = Some(done);
        Poll::Ready(())
    }

    fn finish(self: Box<Self>) -> BoxDone {
        self
    }
}

/// Any stack between ports `Lo` and `Up` behind one type: for whatever
/// picks a stack at run time from an open set, such as the server that
/// answers a name on a shared TLS port.
///
/// Its reports, work, results and errors are boxed, and its timers are the
/// boxed stack's own: it names one, its earliest, and fires that one when
/// it comes due. A stack chosen from a closed set needs no box: a
/// [`Side`](fictionet::stdlib::layer::Side) of the choices is a layer.
pub struct Boxed<Lo: Port = ByteStream, Up: Port = Top> {
    inner: Box<dyn Erased<Lo, Up>>,
}

impl<Lo: Port, Up: Port> Boxed<Lo, Up> {
    /// `stack`, boxed.
    pub fn new<L>(stack: L) -> Boxed<Lo, Up>
    where
        L: Layer<Lower = Lo, Upper = Up> + Send + 'static,
        L::Report: core::fmt::Debug + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Done: Send + 'static,
        L::Error: Into<BoxError> + Send + Sync + 'static,
    {
        assert!(
            stack.depth() < fictionet::stdlib::layer::MAX_DEPTH,
            "composition is too deep"
        );
        Boxed {
            inner: Box::new(stack),
        }
    }
}

/// What [`Boxed`] needs of a stack, with its types boxed.
trait Erased<Lo: Port, Up: Port>: Send {
    fn depth(&self) -> usize;
    fn is_terminal(&self) -> bool;
    fn on_event(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        event: EventOf<Lo>,
    ) -> Result<Admit<EventOf<Lo>>, BoxError>;
    fn on_command(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        command: CommandOf<Up>,
    ) -> Result<Admit<CommandOf<Up>>, BoxError>;
    fn on_timer(&mut self, env: &mut Env<'_, BoxReport>) -> Result<(), BoxError>;
    fn on_done(&mut self, env: &mut Env<'_, BoxReport>, done: BoxDone) -> Result<(), BoxError>;
    fn advance(&mut self, env: &mut Env<'_, BoxReport>) -> Result<bool, BoxError>;
    fn take_command(&mut self, env: &mut Env<'_, BoxReport>) -> Option<CommandOf<Lo>>;
    fn take_event(&mut self) -> Option<EventOf<Up>>;
    fn take_urgent(&mut self) -> Option<EventOf<Up>>;
    fn take_work(&mut self) -> Option<BoxWork>;
    fn deadline(&self) -> Option<Instant>;
}

fn boxed<L: Layer>(report: L::Report) -> BoxReport
where
    L::Report: core::fmt::Debug + Send + 'static,
{
    let bytes =
        L::report_bytes(&report).and_then(|n| n.checked_add(std::mem::size_of::<L::Report>()));
    BoxReport {
        inner: Box::new(report),
        bytes,
    }
}

fn error<E: Into<BoxError>>(e: E) -> BoxError {
    e.into()
}

impl<L, Lo: Port, Up: Port> Erased<Lo, Up> for L
where
    L: Layer<Lower = Lo, Upper = Up> + Send,
    L::Report: core::fmt::Debug + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Done: Send + 'static,
    L::Error: Into<BoxError> + Send + Sync + 'static,
{
    fn depth(&self) -> usize {
        Layer::depth(self)
    }
    fn is_terminal(&self) -> bool {
        Layer::is_terminal(self)
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        event: EventOf<Lo>,
    ) -> Result<Admit<EventOf<Lo>>, BoxError> {
        env.scoped(boxed::<L>, |env| Layer::on_event(self, env, event))
            .map_err(error)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        command: CommandOf<Up>,
    ) -> Result<Admit<CommandOf<Up>>, BoxError> {
        env.scoped(boxed::<L>, |env| Layer::on_command(self, env, command))
            .map_err(error)
    }

    fn on_timer(&mut self, env: &mut Env<'_, BoxReport>) -> Result<(), BoxError> {
        let Some((_, timer)) = Layer::deadline(self) else {
            return Ok(());
        };
        env.scoped(boxed::<L>, |env| Layer::on_timer(self, env, timer))
            .map_err(error)
    }

    fn on_done(&mut self, env: &mut Env<'_, BoxReport>, done: BoxDone) -> Result<(), BoxError> {
        // Only this stack's own work comes back here.
        let Ok(done) = <L::Work as Job>::claim(done) else {
            return Ok(());
        };
        env.scoped(boxed::<L>, |env| Layer::on_done(self, env, done))
            .map_err(error)
    }

    fn advance(&mut self, env: &mut Env<'_, BoxReport>) -> Result<bool, BoxError> {
        env.scoped(boxed::<L>, |env| Layer::advance(self, env))
            .map_err(error)
    }

    fn take_command(&mut self, env: &mut Env<'_, BoxReport>) -> Option<CommandOf<Lo>> {
        env.scoped(boxed::<L>, |env| Layer::take_command(self, env))
    }

    fn take_event(&mut self) -> Option<EventOf<Up>> {
        Layer::take_event(self)
    }

    fn take_urgent(&mut self) -> Option<EventOf<Up>> {
        Layer::take_urgent(self)
    }

    fn take_work(&mut self) -> Option<BoxWork> {
        Layer::take_work(self).map(Job::erase)
    }

    fn deadline(&self) -> Option<Instant> {
        Layer::deadline(self).map(|(at, _)| at)
    }
}

impl<J: Job + ?Sized> Job for Box<J> {
    type Done = J::Done;

    fn cancelled(&self) -> bool {
        (**self).cancelled()
    }

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<J::Done> {
        (**self).poll(fcx, cx)
    }
}

impl<Lo: Port, Up: Port> Layer for Boxed<Lo, Up> {
    type Lower = Lo;
    type Upper = Up;
    type Report = BoxReport;
    fn report_bytes(report: &BoxReport) -> Option<usize> {
        report.bytes
    }
    type Timer = ();
    type Work = BoxWork;
    type Done = BoxDone;
    type Error = BoxError;

    fn depth(&self) -> usize {
        1 + self.inner.depth()
    }
    fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        event: EventOf<Lo>,
    ) -> Result<Admit<EventOf<Lo>>, BoxError> {
        self.inner.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, BoxReport>,
        command: CommandOf<Up>,
    ) -> Result<Admit<CommandOf<Up>>, BoxError> {
        self.inner.on_command(env, command)
    }

    fn on_timer(&mut self, env: &mut Env<'_, BoxReport>, _: ()) -> Result<(), BoxError> {
        self.inner.on_timer(env)
    }

    fn on_done(&mut self, env: &mut Env<'_, BoxReport>, done: BoxDone) -> Result<(), BoxError> {
        self.inner.on_done(env, done)
    }

    fn advance(&mut self, env: &mut Env<'_, BoxReport>) -> Result<bool, BoxError> {
        self.inner.advance(env)
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<Lo>> {
        self.inner.take_command(env)
    }

    fn take_event(&mut self) -> Option<EventOf<Up>> {
        self.inner.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<Up>> {
        self.inner.take_urgent()
    }

    fn take_work(&mut self) -> Option<BoxWork> {
        self.inner.take_work()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.inner.deadline().map(|at| (at, ()))
    }
}
