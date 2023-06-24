use crate::common::*;

pub fn verify_access<Ident, Res, IdentPlc, ResPlc, Act, Repo>(
    requesting_identity: &Ident,
    requested_resource: &Res,
    required_actions: &[Act],
    repository: &Repo,
) -> Result<AccessResolution<ResPlc, IdentPlc>, ()>
where
    Ident: MatchContains,
    Res: MatchContains,
    IdentPlc: IdentityPolicySolver<Resource = Res, Action = Act> + Clone,
    ResPlc: ResourcePolicySolver<Identity = Ident, Action = Act> + Clone,
    Act: PartialEq + Eq,
    Repo: Repository<
        IdentityID = Ident,
        ResourceID = Res,
        IdentityPolicy = IdentPlc,
        ResourcePolicy = ResPlc,
    >,
{
    let identity_policies = repository.load_identity_policies(&requesting_identity)?;
    let resource_policies = repository.load_resource_policies(&requested_resource)?;

    // Deny
    for identity_policy in identity_policies
        .iter()
        .filter(|policy| policy.effect() == Effect::Deny)
    {
        let resolution =
            match_identity_policy(requested_resource, identity_policy, required_actions);
        match &resolution.policy {
            ResolutionPolicy::Resource(_) => unreachable!("resolving identity policy"),
            ResolutionPolicy::Identity(_) => return Ok(resolution),
            ResolutionPolicy::None => continue,
        }
    }

    for resource_policy in resource_policies
        .iter()
        .filter(|policy| policy.effect() == Effect::Deny)
    {
        let resolution =
            match_resource_policy(requesting_identity, resource_policy, required_actions);
        match &resolution.policy {
            ResolutionPolicy::Resource(_) => return Ok(resolution),
            ResolutionPolicy::Identity(_) => unreachable!("resolving resource policy"),
            ResolutionPolicy::None => continue,
        }
    }

    // Allow
    for identity_policy in identity_policies
        .iter()
        .filter(|policy| policy.effect() == Effect::Allow)
    {
        let resolution =
            match_identity_policy(requested_resource, identity_policy, required_actions);
        match &resolution.policy {
            ResolutionPolicy::Resource(_) => unreachable!("resolving identity policy"),
            ResolutionPolicy::Identity(_) => return Ok(resolution),
            ResolutionPolicy::None => continue,
        }
    }

    for resource_policy in resource_policies
        .iter()
        .filter(|policy| policy.effect() == Effect::Allow)
    {
        let resolution =
            match_resource_policy(requesting_identity, resource_policy, required_actions);
        match &resolution.policy {
            ResolutionPolicy::Resource(_) => return Ok(resolution),
            ResolutionPolicy::Identity(_) => unreachable!("resolving resource policy"),
            ResolutionPolicy::None => continue,
        }
    }

    Ok(AccessResolution {
        effect: Effect::Deny,
        policy: ResolutionPolicy::None,
    })
}

pub fn match_identity_policy<Res, ResPlc, IdentPlc, Act>(
    requested_resource: &Res,
    identity_policy: &IdentPlc,
    required_actions: &[Act],
) -> AccessResolution<ResPlc, IdentPlc>
where
    Res: MatchContains,
    ResPlc: ResourcePolicySolver<Action = Act>,
    IdentPlc: IdentityPolicySolver<Resource = Res, Action = Act> + Clone,
    Act: PartialEq + Eq,
{
    let action_matched = required_actions.iter().all(|required_action| {
        identity_policy
            .actions()
            .iter()
            .any(|action| action == required_action)
    });
    let resource_matched = identity_policy
        .resources()
        .iter()
        .any(|res| res.match_contains(&requested_resource));

    if action_matched && resource_matched {
        return AccessResolution {
            effect: identity_policy.effect(),
            policy: ResolutionPolicy::Identity(identity_policy.clone()),
        };
    }

    AccessResolution {
        effect: Effect::Deny,
        policy: ResolutionPolicy::None,
    }
}

pub fn match_resource_policy<Ident, ResPlc, IdentPlc, Act>(
    requesting_identity: &Ident,
    resource_policy: &ResPlc,
    required_actions: &[Act],
) -> AccessResolution<ResPlc, IdentPlc>
where
    Ident: MatchContains,
    ResPlc: ResourcePolicySolver<Identity = Ident, Action = Act> + Clone,
    IdentPlc: IdentityPolicySolver<Action = Act>,
    Act: PartialEq + Eq,
{
    let action_matched = required_actions.iter().all(|required_action| {
        resource_policy
            .actions()
            .iter()
            .any(|action| action == required_action)
    });
    let resource_matched = resource_policy
        .identities()
        .iter()
        .any(|res| res.match_contains(&requesting_identity));

    if action_matched && resource_matched {
        return AccessResolution {
            effect: resource_policy.effect(),
            policy: ResolutionPolicy::Resource(resource_policy.clone()),
        };
    }

    AccessResolution {
        effect: Effect::Deny,
        policy: ResolutionPolicy::None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::data::*;

    struct TestRepository {
        identity_policies: Vec<IdentityPolicy>,
        resource_policies: Vec<ResourcePolicy>,
    }

    impl TestRepository {
        fn new(
            identity_policies: Vec<IdentityPolicy>,
            resource_policies: Vec<ResourcePolicy>,
        ) -> Self {
            Self {
                identity_policies,
                resource_policies,
            }
        }
    }

    impl Repository for TestRepository {
        type IdentityID = IdentityPath;
        type ResourceID = ResourcePath;
        type IdentityPolicy = IdentityPolicy;
        type ResourcePolicy = ResourcePolicy;

        fn load_identity_policies(
            &self,
            _: &Self::IdentityID,
        ) -> Result<Vec<Self::IdentityPolicy>, ()> {
            Ok(self.identity_policies.clone())
        }

        fn load_resource_policies(
            &self,
            _: &Self::ResourceID,
        ) -> Result<Vec<Self::ResourcePolicy>, ()> {
            Ok(self.resource_policies.clone())
        }
    }

    #[test]
    fn verify_identity_policy() {
        let resolution_policy = IdentityPolicy {
            id: 1,
            effect: Effect::Allow,
            resources: vec![ResourcePath {
                account: Some(100),
                context: None,
                resource_type: None,
                resource_id: None,
            }],
            actions: vec![Action::OrganizationDeleteChannel],
            conditions: vec![],
        };
        let repository = TestRepository::new(vec![resolution_policy.clone()], vec![]);

        let requesting_identity = IdentityPath {
            account: Some(100),
            identity_type: Some(IdentityType::User),
            identity_id: Some(1),
        };
        let requested_resource = ResourcePath {
            account: Some(100),
            context: Some(Context::Organization),
            resource_type: Some(Resource::OrganizationChannel),
            resource_id: Some(1),
        };

        let resolution = verify_access(
            &requesting_identity,
            &requested_resource,
            &[Action::OrganizationDeleteChannel],
            &repository,
        )
        .unwrap();

        assert_eq!(
            resolution,
            AccessResolution {
                effect: Effect::Allow,
                policy: ResolutionPolicy::Identity(resolution_policy)
            }
        )
    }
}
