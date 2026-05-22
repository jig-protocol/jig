//! Telemetry and metrics export hooks
//!
//! This module provides optional telemetry hooks for exporting execution metrics
//! to external monitoring systems (feature-gated).

use std::sync::Arc;
use std::sync::Mutex;

/// Telemetry event types
#[derive(Debug, Clone)]
pub enum TelemetryEvent {
    /// Execution started
    ExecutionStarted {
        block_id: Option<String>,
        wasm_size: usize,
    },

    /// Execution completed
    ExecutionCompleted {
        block_id: Option<String>,
        fuel_used: u64,
        duration_ns: u64,
        success: bool,
    },

    /// Fuel consumption checkpoint
    FuelConsumed {
        block_id: Option<String>,
        fuel_used: u64,
        fuel_remaining: u64,
    },

    /// Capability call recorded
    CapabilityInvoked {
        capability: String,
        operation: String,
        fuel_cost: u64,
    },

    /// Limit exceeded
    LimitExceeded {
        limit_type: String, // "fuel", "memory", "timeout"
        limit_value: u64,
        actual_value: u64,
    },
}

/// Telemetry hook trait
///
/// Implement this trait to receive telemetry events from the runtime.
pub trait TelemetryHook: Send + Sync {
    /// Handle a telemetry event
    fn on_event(&self, event: TelemetryEvent);
}

/// Simple stdout telemetry hook for debugging
#[derive(Debug, Default)]
pub struct StdoutTelemetryHook;

impl TelemetryHook for StdoutTelemetryHook {
    fn on_event(&self, event: TelemetryEvent) {
        println!("[TELEMETRY] {event:?}");
    }
}

/// In-memory telemetry collector for testing
#[derive(Debug, Default, Clone)]
pub struct MemoryTelemetryCollector {
    events: Arc<Mutex<Vec<TelemetryEvent>>>,
}

impl MemoryTelemetryCollector {
    /// Create a new memory collector
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get collected events
    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Clear collected events
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Get event count
    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl TelemetryHook for MemoryTelemetryCollector {
    fn on_event(&self, event: TelemetryEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// Telemetry registry for managing hooks
#[derive(Default)]
pub struct TelemetryRegistry {
    hooks: Arc<Mutex<Vec<Arc<dyn TelemetryHook>>>>,
}

impl TelemetryRegistry {
    /// Create a new telemetry registry
    pub fn new() -> Self {
        Self {
            hooks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a telemetry hook
    pub fn register(&self, hook: Arc<dyn TelemetryHook>) {
        self.hooks.lock().unwrap().push(hook);
    }

    /// Emit a telemetry event to all registered hooks
    pub fn emit(&self, event: TelemetryEvent) {
        let hooks = self.hooks.lock().unwrap();
        for hook in hooks.iter() {
            hook.on_event(event.clone());
        }
    }

    /// Get number of registered hooks
    pub fn hook_count(&self) -> usize {
        self.hooks.lock().unwrap().len()
    }
}

impl Clone for TelemetryRegistry {
    fn clone(&self) -> Self {
        Self {
            hooks: Arc::clone(&self.hooks),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_collector() {
        let collector = MemoryTelemetryCollector::new();

        collector.on_event(TelemetryEvent::ExecutionStarted {
            block_id: Some("test".to_string()),
            wasm_size: 1024,
        });

        assert_eq!(collector.count(), 1);

        let events = collector.events();
        assert_eq!(events.len(), 1);

        match &events[0] {
            TelemetryEvent::ExecutionStarted {
                block_id,
                wasm_size,
            } => {
                assert_eq!(block_id, &Some("test".to_string()));
                assert_eq!(*wasm_size, 1024);
            }
            _ => panic!("Wrong event type"),
        }

        collector.clear();
        assert_eq!(collector.count(), 0);
    }

    #[test]
    fn test_telemetry_registry() {
        let registry = TelemetryRegistry::new();
        let collector = Arc::new(MemoryTelemetryCollector::new());

        registry.register(collector.clone());
        assert_eq!(registry.hook_count(), 1);

        registry.emit(TelemetryEvent::FuelConsumed {
            block_id: None,
            fuel_used: 1000,
            fuel_remaining: 4000,
        });

        assert_eq!(collector.count(), 1);

        let events = collector.events();
        match &events[0] {
            TelemetryEvent::FuelConsumed {
                fuel_used,
                fuel_remaining,
                ..
            } => {
                assert_eq!(*fuel_used, 1000);
                assert_eq!(*fuel_remaining, 4000);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_multiple_hooks() {
        let registry = TelemetryRegistry::new();
        let collector1 = Arc::new(MemoryTelemetryCollector::new());
        let collector2 = Arc::new(MemoryTelemetryCollector::new());

        registry.register(collector1.clone());
        registry.register(collector2.clone());

        registry.emit(TelemetryEvent::ExecutionCompleted {
            block_id: Some("multi".to_string()),
            fuel_used: 500,
            duration_ns: 1000,
            success: true,
        });

        assert_eq!(collector1.count(), 1);
        assert_eq!(collector2.count(), 1);
    }
}
