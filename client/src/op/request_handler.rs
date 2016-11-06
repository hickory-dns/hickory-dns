use ::op::Message;

/// Trait for handling incoming requests, and providing a message response.
///
/// *note* this probably belongs in the server crate and may move there in the future.
pub trait RequestHandler {
  /// Determine's what needs to happen given the type of request, i.e. Query or Update.
  ///
  /// # Arguments
  ///
  /// * `request` - the requested action to perform.
  ///
  /// # Returns
  ///
  /// The derived response to the the request
  fn handle_request(&self, request: &Message) -> Message;
}
