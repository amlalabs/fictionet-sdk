/// Ends a test world and cancels its tasks.
#[derive(Debug)]
pub struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

/// Requires a region to end with Done and preserves every other error.
pub fn ended_with_done(result: fictionet::Result) -> fictionet::Result {
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => Ok(()),
        Err(e) => Err(e),
        Ok(()) => Err(fictionet::Error::msg("the region should end with Done")),
    }
}
