//! What a caller hands a long operation: where its progress goes and how to stop it.

use decovery_plugin::{CancelToken, Progress};

use crate::FacadeError;

/// Progress sink and cancel token of one long operation (`build`, `link`, `analyze`, the bridge calls).
///
/// Cancellation is cooperative: the operation checks the token before compiling, hands it to every runner and
/// bridge request (the plugin host sends `$/cancel`), checks it after compiling and before recording. Recording
/// itself is never interrupted; a cancel that arrives during it takes effect after it.
#[non_exhaustive]
pub struct Control<'a> {
    pub progress: &'a dyn Fn(Progress),
    pub cancel: CancelToken,
}

impl<'a> Control<'a> {
    pub fn new(progress: &'a dyn Fn(Progress), cancel: CancelToken) -> Control<'a> {
        Control { progress, cancel }
    }

    /// A control that reports to `progress` and is never cancelled from outside.
    pub fn progress_only(progress: &dyn Fn(Progress)) -> Control<'_> {
        Control {
            progress,
            cancel: CancelToken::new(),
        }
    }

    /// Reports `p`.
    pub fn report(&self, p: Progress) {
        (self.progress)(p);
    }

    /// Whether a cancel was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// A cancellation point: [`FacadeError::Cancelled`] when a cancel was requested.
    pub fn check(&self) -> Result<(), FacadeError> {
        if self.is_cancelled() {
            Err(FacadeError::Cancelled)
        } else {
            Ok(())
        }
    }
}
