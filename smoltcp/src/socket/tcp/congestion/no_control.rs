use super::Controller;

#[derive(Debug)]
pub struct NoControl;

impl Controller for NoControl {
    fn window(&self) -> usize {
        usize::MAX
    }
}
