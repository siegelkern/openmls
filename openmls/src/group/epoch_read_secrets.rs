//! Read access to a single epoch.
//!
//! [`StagedCommit::epoch_read_secrets`] and [`MlsGroup::epoch_read_secrets`]
//! hand out an epoch's `sender_data_secret` and `encryption_secret`, and
//! [`PublicGroup::process_message_with_epoch_secrets`] decrypts the epoch's
//! PrivateMessages with them. Together they let an application read an epoch
//! on a client that did not take part in it.
//!
//! ☣️ Whoever holds an epoch's read secrets can do with the epoch's
//! PrivateMessages what a member of the epoch can:
//!
//! - decrypt all of them, including those whose keys the members have
//!   already deleted, so keeping the secrets gives up forward secrecy for the
//!   epoch;
//! - encrypt a message it decrypted again under another generation, and
//!   derive keys of later generations, which members accept as long as they
//!   still accept messages of the epoch. Hand out an epoch's read secrets only
//!   once the epoch has ended, and keep the window for late messages short.
//!
//! Membership and confirmation tags cannot be computed from them, and they
//! say nothing about other epochs.

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as _;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::Secret,
    error::LibraryError,
    framing::{
        errors::MessageDecryptionError, DecryptedMessage, ProcessedMessage, ProtocolMessage,
    },
    group::{
        GroupContext, GroupEpoch, GroupId, LeafNodeLifetimePolicy, MlsGroup, PublicGroup,
        PublicProcessMessageError, StagedCommit, ValidationError,
    },
    schedule::{
        message_secrets::{DecryptionSecrets, MessageSecrets},
        EncryptionSecret, SenderDataSecret,
    },
    tree::{secret_tree::SecretTree, sender_ratchet::SenderRatchetConfiguration},
};

/// Read access to one epoch of a group: its `sender_data_secret` and
/// `encryption_secret`.
///
/// Get it with [`StagedCommit::epoch_read_secrets`] or
/// [`MlsGroup::epoch_read_secrets`] and use it with
/// [`PublicGroup::process_message_with_epoch_secrets`]. It serializes the two
/// secrets together with the group ID, the epoch and the ciphersuite, and has
/// no accessor for the raw secrets. A clone starts reading the epoch from the
/// beginning.
#[derive(Serialize, Deserialize)]
pub struct EpochReadSecrets {
    group_id: GroupId,
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    sender_data_secret: Secret,
    encryption_secret: Secret,
    #[serde(skip)]
    configuration: SenderRatchetConfiguration,
    #[serde(skip)]
    state: Option<ReadState>,
}

/// The secrets bound to a view of the epoch, with the secret tree that
/// consumes its keys as messages are read.
struct ReadState {
    sender_data_secret: SenderDataSecret,
    serialized_context: Vec<u8>,
    secret_tree: SecretTree,
}

impl DecryptionSecrets for ReadState {
    fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    fn serialized_context(&self) -> &[u8] {
        &self.serialized_context
    }

    fn secret_tree_mut(&mut self) -> &mut SecretTree {
        &mut self.secret_tree
    }
}

impl Clone for EpochReadSecrets {
    fn clone(&self) -> Self {
        Self {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            ciphersuite: self.ciphersuite,
            sender_data_secret: self.sender_data_secret.clone(),
            encryption_secret: self.encryption_secret.clone(),
            configuration: self.configuration,
            state: None,
        }
    }
}

impl std::fmt::Debug for EpochReadSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochReadSecrets")
            .field("group_id", &self.group_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl EpochReadSecrets {
    /// The group these secrets belong to.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// The epoch these secrets belong to.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Sets how far a sender's messages may be out of order or apart when they
    /// are read, by default [`SenderRatchetConfiguration::default`]. A reader
    /// gains no forward secrecy from tight limits, so an archive that is not in
    /// strict order can use wider ones. The setting is not serialized.
    pub fn set_sender_ratchet_configuration(&mut self, configuration: SenderRatchetConfiguration) {
        self.configuration = configuration;
    }

    /// The read secrets of the epoch `group_context` describes, if its secret
    /// tree has not derived anything yet.
    fn from_message_secrets(
        group_context: &GroupContext,
        message_secrets: &MessageSecrets,
    ) -> Option<Self> {
        Some(Self {
            group_id: group_context.group_id().clone(),
            epoch: group_context.epoch(),
            ciphersuite: group_context.ciphersuite(),
            sender_data_secret: message_secrets.sender_data_secret().secret().clone(),
            encryption_secret: message_secrets.encryption_secret()?.clone(),
            configuration: SenderRatchetConfiguration::default(),
            state: None,
        })
    }

    /// Binds the secrets to `view`, which must be the group at exactly their
    /// epoch, and returns the state for decrypting. The state is kept while
    /// the secrets are used with the same view, and built anew for another one.
    fn bind(&mut self, view: &PublicGroup) -> Result<&mut ReadState, PublicProcessMessageError> {
        let hash_length = self.ciphersuite.hash_length();
        if &self.group_id != view.group_id()
            || self.epoch != view.group_context().epoch()
            || self.ciphersuite != view.ciphersuite()
            || self.sender_data_secret.as_slice().len() != hash_length
            || self.encryption_secret.as_slice().len() != hash_length
        {
            return Err(PublicProcessMessageError::EpochSecretsMismatch);
        }
        let serialized_context = view
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let state = match self.state.take() {
            Some(state) if state.serialized_context == serialized_context => state,
            _ => {
                // No leaf belongs to the reader. An index one past the last
                // leaf gives every leaf a decryption ratchet.
                let secret_tree = SecretTree::new(
                    EncryptionSecret::from_secret(self.encryption_secret.clone()),
                    view.tree_size(),
                    LeafNodeIndex::new(view.tree_size().leaf_count()),
                );
                ReadState {
                    sender_data_secret: SenderDataSecret::from_secret(
                        self.sender_data_secret.clone(),
                    ),
                    serialized_context,
                    secret_tree,
                }
            }
        };
        Ok(self.state.insert(state))
    }
}

impl StagedCommit {
    /// The read secrets of the epoch this commit starts.
    ///
    /// Available on every member's staged commit, own pending commits
    /// included, so a member can collect the read secrets of each epoch before
    /// the epoch has a message. `None` for a commit staged by a
    /// [`PublicGroup`], which has no secrets.
    ///
    /// ☣️ These are the secrets of an epoch that has just begun. See
    /// [`EpochReadSecrets`] for what they allow and when to hand them out.
    pub fn epoch_read_secrets(&self) -> Option<EpochReadSecrets> {
        let (group_context, message_secrets) = self.member_message_secrets()?;
        EpochReadSecrets::from_message_secrets(group_context, message_secrets)
    }
}

impl MlsGroup {
    /// The read secrets of the current epoch.
    ///
    /// They are available from the start of the epoch, when the group is
    /// created or joined or a commit is merged, until the first message of the
    /// epoch is encrypted or decrypted. After that this returns `None`, since
    /// the group no longer holds the epoch's `encryption_secret`.
    /// [`StagedCommit::epoch_read_secrets`] has them for every epoch a commit
    /// starts.
    ///
    /// ☣️ These are the secrets of the current epoch. See [`EpochReadSecrets`]
    /// for what they allow and when to hand them out.
    pub fn epoch_read_secrets(&self) -> Option<EpochReadSecrets> {
        EpochReadSecrets::from_message_secrets(
            self.public_group().group_context(),
            self.message_secrets(),
        )
    }
}

impl PublicGroup {
    /// Like [`Self::process_message_with_lifetime_policy`], but decrypts a
    /// PrivateMessage with `secrets`, which must belong to this group's
    /// current epoch. Other messages are processed as usual.
    ///
    /// Commits come back staged and can be merged with
    /// [`Self::merge_commit`], application messages come back as
    /// [`ProcessedMessageContent::ApplicationMessage`]. `secrets` keeps the
    /// state of the epoch's secret tree. A message's key is consumed once the
    /// message has been processed, so each message can be read once.
    ///
    /// [`ProcessedMessageContent::ApplicationMessage`]: crate::framing::ProcessedMessageContent::ApplicationMessage
    pub fn process_message_with_epoch_secrets(
        &self,
        crypto: &impl OpenMlsCrypto,
        message: impl Into<ProtocolMessage>,
        secrets: &mut EpochReadSecrets,
        lifetime_policy: LeafNodeLifetimePolicy,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        let protocol_message = message.into();
        let ProtocolMessage::PrivateMessage(private_message) = protocol_message else {
            return self.process_message_with_lifetime_policy(
                crypto,
                protocol_message,
                lifetime_policy,
            );
        };
        // The secrets open exactly one epoch, so older application messages
        // are not accepted here.
        if private_message.group_id() != self.group_id() {
            return Err(ValidationError::WrongGroupId.into());
        }
        if private_message.epoch() != self.group_context().epoch() {
            return Err(ValidationError::WrongEpoch.into());
        }
        let ciphersuite = self.ciphersuite();
        let configuration = secrets.configuration;
        let state = secrets.bind(self)?;
        let (decrypted_message, ratchet_update) =
            DecryptedMessage::from_inbound_ciphertext_with_read_secrets(
                private_message,
                crypto,
                ciphersuite,
                state,
                &configuration,
            )?;
        let unverified_message = self
            .parse_message(decrypted_message, None)
            .map_err(PublicProcessMessageError::from)?;
        let processed =
            self.process_unverified_message(crypto, unverified_message, lifetime_policy)?;
        state
            .secret_tree
            .apply_decryption_update(ratchet_update, &configuration)
            .map_err(|e| ValidationError::from(MessageDecryptionError::from(e)))?;
        Ok(processed)
    }
}
