//! Member add with sender-key distribution — new member reads forward only.
//!
//! Anchors PLAN.md Phase 7 acceptance criteria:
//!  - Newly added member can decrypt messages sent after joining
//!  - Negative: newly added member cannot decrypt messages sent before joining

use crypto::identity::IdentityKeyPair;
use protocol::group::{GroupMember, GroupSession};

#[test]
fn newly_added_member_can_decrypt_messages_sent_after_joining() {
    let sender = IdentityKeyPair::generate();
    let original = IdentityKeyPair::generate();

    let mut group = GroupSession::new(sender.public()).add_member(GroupMember(original.public()));

    // A new member is added.
    let new_member = IdentityKeyPair::generate();
    group = group.add_member(GroupMember(new_member.public()));

    let ciphertext_after = group
        .encrypt_as(&sender, b"hello, new member!")
        .expect("encrypt");

    let plain = group
        .decrypt_as(&new_member, &ciphertext_after)
        .expect("new member decrypts post-join");
    assert_eq!(plain, b"hello, new member!");
}

#[test]
fn newly_added_member_cannot_decrypt_messages_sent_before_joining() {
    let sender = IdentityKeyPair::generate();
    let original = IdentityKeyPair::generate();

    let mut group = GroupSession::new(sender.public()).add_member(GroupMember(original.public()));

    // Message is sent BEFORE the new member joins.
    let ciphertext_before = group
        .encrypt_as(&sender, b"old message, before you joined")
        .expect("encrypt");

    // Now the new member is added.
    let new_member = IdentityKeyPair::generate();
    group = group.add_member(GroupMember(new_member.public()));

    // The new member must NOT be able to decrypt the prior ciphertext.
    let result = group.decrypt_as(&new_member, &ciphertext_before);
    assert!(
        result.is_err(),
        "newly added member must NOT decrypt messages sent before they joined, got: {result:?}"
    );
}
