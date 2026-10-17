use super::*;

const LIMITS: KdfLimits = KdfLimits {
    pbkdf2_iterations: 2,
    argon2_iterations: 2,
    argon2_memory_mib: 8,
    argon2_parallelism: 2,
};
const PASSWORD: &[u8] = b"quartermaster-dummy-master-password";
const ARGON: KdfParameters = KdfParameters {
    algorithm: KdfAlgorithm::Argon2id,
    iterations: 1,
    memory_mib: Some(1),
    parallelism: Some(1),
};

#[test]
fn bounded_pbkdf2_derivation_matches_the_independent_dummy_vector() {
    let parameters = KdfParameters {
        algorithm: KdfAlgorithm::Pbkdf2,
        iterations: 1,
        memory_mib: None,
        parallelism: None,
    };
    let checked = parameters.validate(&LIMITS).unwrap();

    let identity = checked.derive(" DUMMY@example.invalid ", PASSWORD).unwrap();

    assert_eq!(identity.email(), "dummy@example.invalid");
    assert_eq!(
        identity.identity.keys.enc_key(),
        [
            4, 180, 152, 132, 241, 184, 239, 39, 90, 142, 57, 0, 55, 41, 30, 221, 61, 39, 105, 47,
            39, 198, 157, 99, 186, 227, 221, 174, 98, 169, 6, 100
        ]
    );
    assert_eq!(
        identity.identity.keys.mac_key(),
        [
            122, 243, 56, 53, 90, 91, 184, 140, 97, 134, 202, 89, 111, 71, 111, 39, 50, 17, 101,
            42, 0, 6, 250, 81, 177, 46, 240, 104, 136, 92, 125, 0
        ]
    );
}

#[test]
fn malformed_argon_parameters_are_rejected_before_the_panicking_dependency_api() {
    let permissive = KdfLimits {
        pbkdf2_iterations: u32::MAX,
        argon2_iterations: u32::MAX,
        argon2_memory_mib: u32::MAX,
        argon2_parallelism: u32::MAX,
    };
    for parameters in [
        KdfParameters {
            iterations: 0,
            ..ARGON
        },
        KdfParameters {
            memory_mib: None,
            ..ARGON
        },
        KdfParameters {
            parallelism: None,
            ..ARGON
        },
        KdfParameters {
            memory_mib: Some(0),
            ..ARGON
        },
        KdfParameters {
            parallelism: Some(0),
            ..ARGON
        },
        KdfParameters {
            memory_mib: Some(u32::MAX),
            ..ARGON
        },
        KdfParameters {
            parallelism: Some(u32::MAX),
            ..ARGON
        },
        KdfParameters {
            memory_mib: Some(131072),
            parallelism: Some(0x0100_0000),
            ..ARGON
        },
        KdfParameters {
            parallelism: Some(129),
            ..ARGON
        },
    ] {
        assert!(
            matches!(
                parameters.validate(&permissive),
                Err(CredentialError::InvalidKdfParameters)
            ),
            "{parameters:?}"
        );
    }
}

#[test]
fn caller_limits_reject_excessive_kdf_costs() {
    for parameters in [
        KdfParameters {
            iterations: 3,
            ..ARGON
        },
        KdfParameters {
            memory_mib: Some(9),
            ..ARGON
        },
        KdfParameters {
            parallelism: Some(3),
            ..ARGON
        },
        KdfParameters {
            algorithm: KdfAlgorithm::Pbkdf2,
            iterations: 3,
            memory_mib: None,
            parallelism: None,
        },
    ] {
        assert!(matches!(
            parameters.validate(&LIMITS),
            Err(CredentialError::InvalidKdfParameters)
        ));
    }
}

#[test]
fn pbkdf2_rejects_zero_iterations_and_argon_only_fields() {
    for (iterations, memory_mib, parallelism) in
        [(0, None, None), (1, Some(1), None), (1, None, Some(1))]
    {
        let parameters = KdfParameters {
            algorithm: KdfAlgorithm::Pbkdf2,
            iterations,
            memory_mib,
            parallelism,
        };
        assert!(matches!(
            parameters.validate(&LIMITS),
            Err(CredentialError::InvalidKdfParameters)
        ));
    }
}

#[test]
fn costs_equal_to_the_limits_are_accepted_for_both_algorithms() {
    for parameters in [
        KdfParameters {
            algorithm: KdfAlgorithm::Pbkdf2,
            iterations: LIMITS.pbkdf2_iterations,
            memory_mib: None,
            parallelism: None,
        },
        KdfParameters {
            iterations: LIMITS.argon2_iterations,
            memory_mib: Some(LIMITS.argon2_memory_mib),
            parallelism: Some(LIMITS.argon2_parallelism),
            ..ARGON
        },
    ] {
        parameters
            .validate(&LIMITS)
            .unwrap()
            .derive("dummy@example.invalid", PASSWORD)
            .unwrap();
    }
}
