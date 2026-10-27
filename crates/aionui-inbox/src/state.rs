use std::sync::Arc;

use crate::service::InboxService;

#[derive(Clone)]
pub struct InboxRouterState {
    pub service: Arc<InboxService>,
}
