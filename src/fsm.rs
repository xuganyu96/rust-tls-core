/// Traits for implementing finite state machine

pub trait FiniteStateMachine
where Self: Sized {
    type State;

    fn transition(self: Self) -> Self {
        return self;
    }
}
