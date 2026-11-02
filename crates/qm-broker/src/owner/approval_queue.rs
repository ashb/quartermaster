use std::{
    collections::VecDeque,
    sync::{Arc, Weak},
};

pub(super) const CAPACITY: usize = 32;

pub(super) struct Ticket;

#[derive(Default)]
pub(super) struct Queue {
    entries: VecDeque<Weak<Ticket>>,
}

impl Queue {
    pub(super) fn enqueue(&mut self) -> Option<Arc<Ticket>> {
        self.entries.retain(|ticket| ticket.strong_count() != 0);
        if self.entries.len() >= CAPACITY {
            return None;
        }
        let ticket = Arc::new(Ticket);
        self.entries.push_back(Arc::downgrade(&ticket));
        Some(ticket)
    }

    pub(super) fn contains(&self, ticket: &Arc<Ticket>) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.ptr_eq(&Arc::downgrade(ticket)))
    }

    pub(super) fn is_front(&mut self, ticket: &Arc<Ticket>) -> bool {
        self.entries.retain(|ticket| ticket.strong_count() != 0);
        self.entries
            .front()
            .is_some_and(|entry| entry.ptr_eq(&Arc::downgrade(ticket)))
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrivals_wait_in_order_and_dropping_a_waiter_does_not_skip_the_active_review() {
        let mut queue = Queue::default();
        let first = queue.enqueue().unwrap();
        let abandoned = queue.enqueue().unwrap();
        let third = queue.enqueue().unwrap();
        assert!(queue.is_front(&first));
        assert!(!queue.is_front(&third));
        drop(abandoned);
        assert!(queue.is_front(&first));
        drop(first);
        assert!(queue.is_front(&third));
    }

    #[test]
    fn capacity_counts_live_tickets_and_invalidated_tickets_cannot_resume() {
        let mut queue = Queue::default();
        let tickets: Vec<_> = (0..CAPACITY).map(|_| queue.enqueue().unwrap()).collect();
        assert!(queue.enqueue().is_none());
        let old = tickets[0].clone();
        queue.clear();
        let new = queue.enqueue().unwrap();
        assert!(!queue.contains(&old));
        assert!(!queue.is_front(&old));
        assert!(queue.is_front(&new));
        drop(tickets);
        assert!(queue.is_front(&new));
    }
}
