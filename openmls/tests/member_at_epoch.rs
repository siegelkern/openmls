//! `MlsGroup::member_at_epoch` reads the tree of the given epoch.

use openmls::prelude::{test_utils::new_credential, *};
use openmls_test::openmls_test;

/// Carol takes Bob's former leaf. Epoch 1 still has Bob there, the current
/// tree has Carol, and an epoch the group does not keep has nobody.
#[openmls_test]
fn member_at_epoch_reads_the_epochs_tree() {
    let alice_provider = Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(5))
        .build();
    let mut alice =
        MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential).unwrap();

    let key_package = |name: &[u8]| {
        let provider = Provider::default();
        let (credential, signer) =
            new_credential(&provider, name, ciphersuite.signature_algorithm());
        KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential)
            .unwrap()
            .key_package()
            .clone()
    };

    alice
        .add_members(&alice_provider, &alice_signer, &[key_package(b"Bob")])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();
    let leaf = LeafNodeIndex::new(1);
    alice
        .remove_members(&alice_provider, &alice_signer, &[leaf])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();
    alice
        .add_members(&alice_provider, &alice_signer, &[key_package(b"Carol")])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();
    assert_eq!(alice.epoch(), GroupEpoch::from(3));

    let in_epoch_1 = alice.member_at_epoch(GroupEpoch::from(1), leaf).unwrap();
    assert_eq!(in_epoch_1.credential.serialized_content(), b"Bob");
    assert!(alice.member_at_epoch(GroupEpoch::from(2), leaf).is_none());
    let now = alice.member_at_epoch(alice.epoch(), leaf).unwrap();
    assert_eq!(now.credential.serialized_content(), b"Carol");
    assert_eq!(Some(now), alice.member_at(leaf));
    assert!(alice.member_at_epoch(GroupEpoch::from(4), leaf).is_none());
}
