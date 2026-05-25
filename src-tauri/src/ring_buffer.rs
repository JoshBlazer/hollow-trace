use std::collections::VecDeque;
use crate::parser::types::LogEntry;

pub struct RingBuffer {
    inner: VecDeque<LogEntry>,
    capacity: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, entry: LogEntry) {
        if self.inner.len() >= self.capacity {
            self.inner.pop_front();
        }
        self.inner.push_back(entry);
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.inner.iter()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new(100_000)
    }
}
