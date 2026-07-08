//! Sender Keys group encrypt/decrypt — all members decrypt; non-members cannot.
//!
//! Anchors PLAN.md Phase 7 acceptance criteria:
//!  - All group members can decrypt a message encrypted with the sender's group key
//!  - Negative: a non-member cannot decrypt a group message

use crypto::identity::IdentityKeyPair;
use protocol::group::{GroupMember, GroupSession, NonMember};

#[test]
fn all_group_members_can_decrypt_a_group_message() {
    let sender = IdentityKeyPair::generate();
    let member_a = IdentityKeyPair::generate();
    let member_b = IdentityKeyPair::generate();

    let group = GroupSession::new(sender.public())
        .add_member(GroupMember(member_a.public()))
        .add_member(GroupMember(member_b.public()));

    let ciphertext = group
        .encrypt_as(&sender, b"group chat message")
        .expect("encrypt");

    let plain_a = group
        .decrypt_as(&member_a, &ciphertext)
        .expect("member a decrypts");
    let plain_b = group
        .decrypt_as(&member_b, &ciphertext)
        .expect("member b decrypts");
    assert_eq!(plain_a, b"group chat message");
    assert_eq!(plain_b, b"group chat message");
}

#[test]
fn non_member_cannot_decrypt_a_group_message() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();
    let outsider = IdentityKeyPair::generate();

    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

    let ciphertext = group
        .encrypt_as(&sender, b"private to the group")
        .expect("encrypt");

    let result = group.decrypt_as(&NonMember(outsider.public()), &ciphertext);
    assert!(
        result.is_err(),
        "non-member must NOT be able to decrypt the group message, got: {result:?}"
    );
}
