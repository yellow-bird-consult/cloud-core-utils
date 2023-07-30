//! Defines the runtime state which enables you to configure the type of response you want a function to have.


/// Defines the possible runtime states.
/// 
/// # Fields
/// * `Live` - The live runtime state and should be used when fused with a server.
/// * `MockPass` - The mock pass runtime state and should be used when you want to mock a function that should pass.
/// * `MockFail` - The mock fail runtime state and should be used when you want to mock a function that should fail.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuntimeState {
    Live,
    MockPass,
    MockFail
}


pub trait EstablishRuntime {

    /// Yields the runtime state.
    /// 
    /// # Returns
    /// * `RuntimeState` - The runtime state.
    fn yield_runtime_state() -> RuntimeState;

}


/// To be used in live runtimes.
pub struct LiveRuntime;

impl EstablishRuntime for LiveRuntime {

    fn yield_runtime_state() -> RuntimeState {
        RuntimeState::Live
    }

}


/// To be used when you want to mock a function that should pass.
pub struct MockPassRuntime;

impl EstablishRuntime for MockPassRuntime {

    fn yield_runtime_state() -> RuntimeState {
        RuntimeState::MockPass
    }

}


/// To be used when you want to mock a function that should fail.
pub struct MockFailRuntime;

impl EstablishRuntime for MockFailRuntime {

    fn yield_runtime_state() -> RuntimeState {
        RuntimeState::MockFail
    }

}


#[cfg(test)]
mod tests {

    use super::*;

    fn mock_function<X: EstablishRuntime>() -> RuntimeState {
        X::yield_runtime_state()
    }

    #[test]
    fn test_mock_pass() {
        assert_eq!(mock_function::<MockPassRuntime>(), RuntimeState::MockPass);
    }

    #[test]
    fn test_mock_fail() {
        assert_eq!(mock_function::<MockFailRuntime>(), RuntimeState::MockFail);
    }

    #[test]
    fn test_live() {
        assert_eq!(mock_function::<LiveRuntime>(), RuntimeState::Live);
    }

}
