#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    Deny = 128,
    Allow = 64,
}

/// Matches one set with other set.
pub trait MatchContains {
    /// Checks if the **matching** set contains the **other** set.
    ///
    /// This matching verifies if the **other** is a **subset** of Self.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rfc_matcher = URN::from_str("urn:ietf:rfc:*")?;
    /// let urn_rfc = URN::from_str("urn:ietf:rfc:2648")?;
    ///
    /// assert!(rfc_matcher.match_contains(urn_rfc));
    /// ```
    fn match_contains(&self, other: &Self) -> bool;
}

pub trait IdentityPolicySolver {
    type Resource: MatchContains;
    type Action: PartialEq + Eq;

    fn effect(&self) -> Effect;
    fn actions(&self) -> &[Self::Action];
    fn resources(&self) -> &[Self::Resource];
}

pub trait ResourcePolicySolver {
    type Identity: MatchContains;
    type Action: PartialEq + Eq;

    fn effect(&self) -> Effect;
    fn actions(&self) -> &[Self::Action];
    fn identities(&self) -> &[Self::Identity];
}

pub trait Repository {
    type IdentityID;
    type ResourceID;
    type IdentityPolicy: IdentityPolicySolver;
    type ResourcePolicy: ResourcePolicySolver;

    /// Load all the Identity policies.
    ///
    /// Load the Identity policies directly attached and associated by groups
    /// that it participates.
    ///
    /// TODO: fetch policies in a performant way.
    /// Investigate possibility to use async iterator, require a specific
    /// ordering based on the algorithm, etc.
    fn load_identity_policies(
        &self,
        identity_id: &Self::IdentityID,
    ) -> Result<Vec<Self::IdentityPolicy>, ()>;

    fn load_resource_policies(
        &self,
        resource_id: &Self::ResourceID,
    ) -> Result<Vec<Self::ResourcePolicy>, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessResolution<R: ResourcePolicySolver, I: IdentityPolicySolver> {
    pub effect: Effect,
    /// Policy that resolved the access verification.
    pub policy: ResolutionPolicy<R, I>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionPolicy<R: ResourcePolicySolver, I: IdentityPolicySolver> {
    Resource(R),
    Identity(I),
    None,
}
