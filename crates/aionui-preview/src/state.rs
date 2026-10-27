use std::sync::Arc;

use crate::service::PreviewService;

#[derive(Clone)]
pub struct PreviewRouterState {
    pub service: Arc<PreviewService>,
}
