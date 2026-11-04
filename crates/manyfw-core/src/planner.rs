//! Public planner namespace retained separately from backend DTO definitions.
pub use crate::backend::{
    AddressFamily, BackendCapabilities, BackendCapabilityObservation, BackendKind, BackendMode,
    BackendObservation, BackendObservationSet, BlockReason, CapabilityState, DiagnosticPlan, Hook,
    HookObservation, Ownership, OwnershipBoundary, PLAN_VERSION, PacketPath, PlanApplicability,
    PlanOperation, Planner, PlannerInput, Preconditions, ResourceObservation, plan,
};
