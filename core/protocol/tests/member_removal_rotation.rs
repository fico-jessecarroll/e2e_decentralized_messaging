//! Member removal with sender-key rotation — forward-secure post-removal.
//!
//! Anchors PLAN.md Phase 7 acceptance criteria:
//!  - Remaining members can decrypt messages sent after rotation
//!  - Negative (primary case): a removed member cannot decrypt any message sent after their removal, even with the old key

use crypto::identity::IdentityKeyPair;
use protocol::group::{GroupSession, GroupMember};

#[test]
fn remaining_members_can_decrypt_messages_sent_after_rotation() {
    let sender = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();

    let group = GroupSession::new(sender.public())
        .add_member(GroupMember(alice.public()))
        .add_member(GroupMember(bob.public()))
        .rotate_sender_key();

    let ciphertext = group.encrypt_as(&sender, b"after rotation").expect("encrypt");

    let plain_a = group.decrypt_as(&alice, &ciphertext).expect("alice decrypts");
    let plain_b = group.decrypt_as(&bob, &ciphertext).expect("bob decrypts");
    assert_eq!(plain_a, b"after rotation");
    assert_eq!(plain_b, b"after rotation");
}

#[test]
fn removed_member_cannot_decrypt_messages_sent_after_their_removal() {
    let sender = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let eve = IdentityKeyPair::generate();

    let mut group = GroupSession::new(sender.public())
        .add_member(GroupMember(alice.public()))
        .add_member(GroupMember(bob.public()))
        .add_member(GroupMember(eve.public()));

    // Capture Eve's old sender-key copy before removal so we can attempt
    // a post-removal decrypt using it explicitly.
    let old_eve_key = group.sender_key_copy_for(&eve);

    // Remove Eve and rotate the sender key.
    group = group.remove_member(GroupMember(eve.public()));
    group = group.rotate_sender_key();

    let ciphertext = group.encrypt_as(&sender, b"eve is gone, this is private").expect("encrypt");

    // Eve with the OLD key cannot decrypt.
    let result_old = group.try_decrypt_with_sender_key(&old_eve_key, &ciphertext);
    assert!(
        result_old.is_err(),
        "removed member with OLD sender key must NOT decrypt post-removal message, got: {result_old:?}"
    );

    // Eve with any identity cannot decrypt via the live group state either.
    let result_live = group.decrypt_as(&eve, &ciphertext);
    assert!(
        result_live.is_err(),
        "removed member must NOT decrypt post-removal message, got: {result_live:?}"
    );
}
