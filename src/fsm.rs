/// Traits for implementing finite state machine

pub trait FiniteStateMachine
where
    Self: Sized,
{
    type State;

    fn transition(self: Self) -> Self {
        return self;
    }

    /// Return true if the FSM has halted and cannot transition further
    fn is_halt(self: &Self) -> bool;
}
