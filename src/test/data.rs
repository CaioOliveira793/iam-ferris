#![allow(dead_code)]

use crate::common::{Effect, IdentityPolicySolver, MatchContains, ResourcePolicySolver};

type ID = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    IAMUser,
    IAMPolicy,
    OrganizationNamespace,
    OrganizationChannel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    IdentityMultiFactorAuthEnabled(bool),
    ResourceMustHaveAttribute(ResourceAttribute),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAttribute {
    CreatedBy(ID),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Context {
    IAM,
    Organization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityType {
    User,
    Group,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    IAMCreateUser,
    IAMReadUser,
    IAMUpdateUser,
    IAMAttachUserPolice,
    IAMDeleteUser,
    OrganizationCreateNamespace,
    OrganizationDeleteNamespace,
    OrganizationCreateChannel,
    OrganizationDeleteChannel,
}

/// Resource path.
///
/// company:<account>:<context>:<resource-type>:<resource-id>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePath {
    pub account: Option<ID>,
    pub context: Option<Context>,
    pub resource_type: Option<Resource>,
    pub resource_id: Option<ID>,
}

fn match_contains<T: PartialEq + Eq>(matching: Option<&T>, matched: Option<&T>) -> bool {
    match (&matching, &matched) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(mting), Some(mted)) => mting == mted,
    }
}

impl MatchContains for ResourcePath {
    fn match_contains(&self, other: &Self) -> bool {
        match_contains(self.account.as_ref(), other.account.as_ref())
            && match_contains(self.context.as_ref(), other.context.as_ref())
            && match_contains(self.resource_type.as_ref(), other.resource_type.as_ref())
            && match_contains(self.resource_id.as_ref(), other.resource_id.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPath {
    pub account: Option<ID>,
    pub identity_type: Option<IdentityType>,
    pub identity_id: Option<ID>,
}

impl MatchContains for IdentityPath {
    fn match_contains(&self, other: &Self) -> bool {
        match_contains(self.account.as_ref(), other.account.as_ref())
            && match_contains(self.identity_type.as_ref(), other.identity_type.as_ref())
            && match_contains(self.identity_id.as_ref(), other.identity_id.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPolicy {
    pub id: u128,
    pub effect: Effect,
    pub resources: Vec<ResourcePath>,
    pub actions: Vec<Action>,
    pub conditions: Vec<Condition>,
}

impl IdentityPolicySolver for IdentityPolicy {
    type Resource = ResourcePath;
    type Action = Action;

    fn effect(&self) -> Effect {
        self.effect
    }

    fn actions(&self) -> &[Self::Action] {
        &self.actions
    }

    fn resources(&self) -> &[Self::Resource] {
        &self.resources
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    pub id: u128,
    pub effect: Effect,
    pub identities: Vec<IdentityPath>,
    pub actions: Vec<Action>,
    pub conditions: Vec<Condition>,
}

impl ResourcePolicySolver for ResourcePolicy {
    type Identity = IdentityPath;
    type Action = Action;

    fn effect(&self) -> Effect {
        self.effect
    }

    fn identities(&self) -> &[Self::Identity] {
        &self.identities
    }

    fn actions(&self) -> &[Self::Action] {
        &self.actions
    }
}

/*
# Resource crn (_company_ resource name)
- company:account-id:context:resource-type:resource-id/path
- company:account-id:context:resource-type/path

# User crn (_company_ resource name)
- company:account-id:identity-type:identity-id
*/
