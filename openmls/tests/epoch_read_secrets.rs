//! The epoch read secrets: when the getters have them, and how
//! `PublicGroup::process_message_with_epoch_secrets` reads with them.
#![cfg(feature = "epoch-read-secrets")]

use openmls::{
    messages::group_info::VerifiableGroupInfo,
    prelude::{test_utils::new_credential, *},
    treesync::RatchetTree,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use tls_codec::{Deserialize as _, Serialize as _};

struct Member<P> {
    provider: P,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

fn member<P: OpenMlsProvider + Default>(ciphersuite: Ciphersuite, name: &[u8]) -> Member<P> {
    let provider = P::default();
    let (credential, signer) = new_credential(&provider, name, ciphersuite.signature_algorithm());
    Member {
        provider,
        signer,
        credential,
    }
}

fn protocol_message(message: &MlsMessageOut) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

fn group_info(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    signer: &SignatureKeyPair,
) -> VerifiableGroupInfo {
    let message = group.export_group_info(crypto, signer, false).unwrap();
    let MlsMessageBodyIn::GroupInfo(group_info) =
        MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap())
            .unwrap()
            .extract()
    else {
        panic!("not a GroupInfo")
    };
    group_info
}

fn view<P: OpenMlsProvider + Default>(
    group_info: VerifiableGroupInfo,
    tree: RatchetTree,
) -> PublicGroup {
    let provider = P::default();
    PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        tree.into(),
        group_info,
        ProposalStore::new(),
    )
    .unwrap()
    .0
}

/// Alice and Bob in epoch 1, created with `ciphersuite`.
fn alice_and_bob<P: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
) -> (Member<P>, Member<P>, MlsGroup, MlsGroup) {
    let alice = member::<P>(ciphersuite, b"Alice");
    let bob = member::<P>(ciphersuite, b"Bob");
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();
    let mut alice_group = MlsGroup::new(
        &alice.provider,
        &alice.signer,
        &config,
        alice.credential.clone(),
    )
    .unwrap();
    let bob_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            &bob.provider,
            &bob.signer,
            bob.credential.clone(),
        )
        .unwrap()
        .key_package()
        .clone();
    let (_, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::from(welcome).extract() else {
        panic!("not a Welcome")
    };
    let bob_group = StagedWelcome::new_from_welcome(
        &bob.provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob.provider)
    .unwrap();
    (alice, bob, alice_group, bob_group)
}

/// The group's getter ends with the epoch's first message, sent or received,
/// and stays gone after a reload. A staged commit has the next epoch's
/// secrets, the same the group has once it is merged.
#[openmls_test]
fn the_getters() {
    let (alice, bob, mut alice_group, mut bob_group) = alice_and_bob::<Provider>(ciphersuite);
    assert!(alice_group.epoch_read_secrets().is_some());
    let message = bob_group
        .create_message(&bob.provider, &bob.signer, b"hi")
        .unwrap();
    assert!(bob_group.epoch_read_secrets().is_none());
    alice_group
        .process_message(&alice.provider, protocol_message(&message))
        .unwrap();
    assert!(alice_group.epoch_read_secrets().is_none());
    let reloaded = MlsGroup::load(alice.provider.storage(), alice_group.group_id())
        .unwrap()
        .unwrap();
    assert!(reloaded.epoch_read_secrets().is_none());

    alice_group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let staged = alice_group
        .pending_commit()
        .unwrap()
        .epoch_read_secrets()
        .unwrap();
    assert_eq!(staged.epoch(), GroupEpoch::from(2));
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let merged = alice_group.epoch_read_secrets().unwrap();
    assert_eq!(
        serde_json::to_vec(&staged).unwrap(),
        serde_json::to_vec(&merged).unwrap()
    );
}

/// A message reads once with the same secrets, and again with a clone.
#[openmls_test]
fn a_message_reads_once() {
    let (alice, bob, alice_group, mut bob_group) = alice_and_bob::<Provider>(ciphersuite);
    let mut secrets = bob_group.epoch_read_secrets().unwrap();
    let reader = view::<Provider>(
        group_info(&alice_group, alice.provider.crypto(), &alice.signer),
        alice_group.export_ratchet_tree(),
    );
    let message = bob_group
        .create_message(&bob.provider, &bob.signer, b"once")
        .unwrap();
    let mut clone = secrets.clone();
    reader
        .process_message_with_epoch_secrets(
            alice.provider.crypto(),
            protocol_message(&message),
            &mut secrets,
            LeafNodeLifetimePolicy::Skip,
        )
        .unwrap();
    assert!(reader
        .process_message_with_epoch_secrets(
            alice.provider.crypto(),
            protocol_message(&message),
            &mut secrets,
            LeafNodeLifetimePolicy::Skip,
        )
        .is_err());
    reader
        .process_message_with_epoch_secrets(
            alice.provider.crypto(),
            protocol_message(&message),
            &mut clone,
            LeafNodeLifetimePolicy::Skip,
        )
        .unwrap();
}

/// Secrets used with one view and then another view of the same epoch are
/// bound to the other view anew: a message that does not verify against it
/// is refused, as it is with fresh secrets.
#[openmls_test]
fn secrets_bind_to_the_view_they_are_used_with() {
    let (alice, _bob, mut alice_group, _bob_group) = alice_and_bob::<Provider>(ciphersuite);
    alice_group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let secrets = alice_group
        .pending_commit()
        .unwrap()
        .epoch_read_secrets()
        .unwrap();
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let real = view::<Provider>(
        group_info(&alice_group, alice.provider.crypto(), &alice.signer),
        alice_group.export_ratchet_tree(),
    );

    // Another group with the same id, ciphersuite and epoch, run by Alice.
    let other_provider = Provider::default();
    let carol = member::<Provider>(ciphersuite, b"Carol");
    let mut other = MlsGroup::builder()
        .with_group_id(alice_group.group_id().clone())
        .ciphersuite(ciphersuite)
        .build(&other_provider, &alice.signer, alice.credential.clone())
        .unwrap();
    let carol_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            &carol.provider,
            &carol.signer,
            carol.credential.clone(),
        )
        .unwrap()
        .key_package()
        .clone();
    other
        .add_members(&other_provider, &alice.signer, &[carol_key_package])
        .unwrap();
    other.merge_pending_commit(&other_provider).unwrap();
    other
        .self_update(
            &other_provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    other.merge_pending_commit(&other_provider).unwrap();
    let wrong = view::<Provider>(
        group_info(&other, other_provider.crypto(), &alice.signer),
        other.export_ratchet_tree(),
    );
    assert_eq!(wrong.group_context().epoch(), real.group_context().epoch());

    let first = alice_group
        .create_message(&alice.provider, &alice.signer, b"first")
        .unwrap();
    let second = alice_group
        .create_message(&alice.provider, &alice.signer, b"second")
        .unwrap();
    let crypto = alice.provider.crypto();
    let mut fresh = secrets.clone();
    assert!(wrong
        .process_message_with_epoch_secrets(
            crypto,
            protocol_message(&second),
            &mut fresh,
            LeafNodeLifetimePolicy::Skip
        )
        .is_err());
    let mut used = secrets;
    real.process_message_with_epoch_secrets(
        crypto,
        protocol_message(&first),
        &mut used,
        LeafNodeLifetimePolicy::Skip,
    )
    .unwrap();
    assert!(wrong
        .process_message_with_epoch_secrets(
            crypto,
            protocol_message(&second),
            &mut used,
            LeafNodeLifetimePolicy::Skip
        )
        .is_err());
    real.process_message_with_epoch_secrets(
        crypto,
        protocol_message(&second),
        &mut used,
        LeafNodeLifetimePolicy::Skip,
    )
    .unwrap();
}

/// Messages of one sender read in reverse: beyond the default out-of-order
/// tolerance with the default configuration, all of them with a wider one.
#[openmls_test]
fn the_sender_ratchet_configuration_is_the_readers() {
    let (alice, bob, alice_group, mut bob_group) = alice_and_bob::<Provider>(ciphersuite);
    let secrets = bob_group.epoch_read_secrets().unwrap();
    let reader = view::<Provider>(
        group_info(&alice_group, alice.provider.crypto(), &alice.signer),
        alice_group.export_ratchet_tree(),
    );
    let mut messages: Vec<_> = (0..8)
        .map(|i| {
            bob_group
                .create_message(&bob.provider, &bob.signer, format!("m{i}").as_bytes())
                .unwrap()
        })
        .collect();
    messages.reverse();
    let read_all = |mut secrets: EpochReadSecrets| {
        messages.iter().all(|message| {
            reader
                .process_message_with_epoch_secrets(
                    alice.provider.crypto(),
                    protocol_message(message),
                    &mut secrets,
                    LeafNodeLifetimePolicy::Skip,
                )
                .is_ok()
        })
    };
    assert!(!read_all(secrets.clone()));
    let mut wide = secrets;
    wide.set_sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 1000));
    assert!(read_all(wide));
}

/// Secrets of another group, or with a secret of the wrong length, do not
/// bind.
#[openmls_test]
fn secrets_that_do_not_fit_are_refused() {
    let (alice, bob, alice_group, mut bob_group) = alice_and_bob::<Provider>(ciphersuite);
    let secrets = bob_group.epoch_read_secrets().unwrap();
    let reader = view::<Provider>(
        group_info(&alice_group, alice.provider.crypto(), &alice.signer),
        alice_group.export_ratchet_tree(),
    );
    let message = bob_group
        .create_message(&bob.provider, &bob.signer, b"x")
        .unwrap();
    let refused = |mut secrets: EpochReadSecrets| {
        matches!(
            reader.process_message_with_epoch_secrets(
                alice.provider.crypto(),
                protocol_message(&message),
                &mut secrets,
                LeafNodeLifetimePolicy::Skip,
            ),
            Err(PublicProcessMessageError::EpochSecretsMismatch)
        )
    };

    let (_, _, _, other_bob_group) = alice_and_bob::<Provider>(ciphersuite);
    assert!(refused(other_bob_group.epoch_read_secrets().unwrap()));

    // The encryption secret cut to one byte in the serialized form.
    fn cut(value: &mut serde_json::Value) -> bool {
        let Some(object) = value.as_object_mut() else {
            return false;
        };
        let mut cut_any = false;
        for (key, field) in object.iter_mut() {
            if key == "encryption_secret" {
                for pointer in ["/value/vec", "/value"] {
                    if let Some(bytes) = field.pointer_mut(pointer).and_then(|v| v.as_array_mut()) {
                        bytes.truncate(1);
                        cut_any = true;
                        break;
                    }
                }
            }
            cut_any |= cut(field);
        }
        cut_any
    }
    let mut json = serde_json::to_value(&secrets).unwrap();
    assert!(cut(&mut json), "no encryption secret in {json}");
    assert!(refused(serde_json::from_value(json).unwrap()));
    assert!(!refused(secrets));
}
