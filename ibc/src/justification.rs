use codec::{Decode, Encode};
use finality_grandpa::{voter_set::VoterSet, Error as GrandpaError};
use sp_finality_grandpa::{AuthorityId, AuthoritySignature, RoundNumber, SetId};
use sp_runtime::{
    traits::{Block as BlockT, Header as HeaderT, NumberFor},
    RuntimeDebug,
};
use sp_std::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    prelude::*,
};

type Message<Block> = finality_grandpa::Message<<Block as BlockT>::Hash, NumberFor<Block>>;

type Commit<Block> = finality_grandpa::Commit<
    <Block as BlockT>::Hash,
    NumberFor<Block>,
    AuthoritySignature,
    AuthorityId,
>;

#[derive(Encode, Decode, RuntimeDebug)]
pub struct GrandpaJustification<Block: BlockT> {
    round: u64,
    commit: Commit<Block>,
    votes_ancestries: Vec<Block::Header>,
}

impl<Block: BlockT> GrandpaJustification<Block> {
    pub fn verify(&self, set_id: SetId, voters: &VoterSet<AuthorityId>) -> Result<(), Error>
    where
        NumberFor<Block>: finality_grandpa::BlockNumberOps,
    {
        use finality_grandpa::Chain;

        let ancestry_chain = AncestryChain::<Block>::new(&self.votes_ancestries);
        match finality_grandpa::validate_commit(&self.commit, voters, &ancestry_chain) {
            Ok(ref result) if result.ghost().is_some() => {}
            _ => {
                return Err(Error::BadJustification);
            }
        }

        let mut buf = Vec::new();
        let mut visited_hashes = BTreeSet::new();
        for signed in self.commit.precommits.iter() {
            if let Err(_) = check_message_sig_with_buffer::<Block>(
                &finality_grandpa::Message::Precommit(signed.precommit.clone()),
                &signed.id,
                &signed.signature,
                self.round,
                set_id,
                &mut buf,
            ) {
                return Err(Error::BadJustification.into());
            }

            if self.commit.target_hash == signed.precommit.target_hash {
                continue;
            }

            match ancestry_chain.ancestry(self.commit.target_hash, signed.precommit.target_hash) {
                Ok(route) => {
                    // ancestry starts from parent hash but the precommit target hash has been visited
                    visited_hashes.insert(signed.precommit.target_hash);
                    for hash in route {
                        visited_hashes.insert(hash);
                    }
                }
                _ => {
                    return Err(Error::BadJustification.into());
                }
            }
        }
        let ancestry_hashes = self
            .votes_ancestries
            .iter()
            .map(|h: &Block::Header| h.hash())
            .collect();

        if visited_hashes != ancestry_hashes {
            return Err(Error::BadJustification.into());
        }

        Ok(())
    }
}

fn check_message_sig_with_buffer<Block: BlockT>(
    message: &Message<Block>,
    id: &AuthorityId,
    signature: &AuthoritySignature,
    round: RoundNumber,
    set_id: SetId,
    buf: &mut Vec<u8>,
) -> Result<(), ()> {
    use sp_runtime::RuntimeAppPublic;
    let as_public = id.clone();
    localized_payload_with_buffer(round, set_id, message, buf);

    if as_public.verify(buf, signature) {
        Ok(())
    } else {
        // debug!(target: "afg", "Bad signature on message from {:?}", id);
        Err(())
    }
}

fn localized_payload_with_buffer<E: Encode>(
    round: RoundNumber,
    set_id: SetId,
    message: &E,
    buf: &mut Vec<u8>,
) {
    buf.clear();
    (message, round, set_id).encode_to(buf)
}

#[derive(RuntimeDebug)]
pub enum Error {
    /// Invalid authorities set received from the runtime.
    InvalidAuthoritiesSet,
    /// Could not get runtime version.
    VersionInvalid,
    /// Genesis config is invalid.
    GenesisInvalid,
    /// Error decoding header justification.
    JustificationDecode,
    /// Justification for header is correctly encoded, but invalid.
    BadJustification,
    /// Invalid calculated state root on block import.
    InvalidStateRoot,
}

struct AncestryChain<Block: BlockT> {
    ancestry: BTreeMap<Block::Hash, Block::Header>,
}

impl<Block: BlockT> AncestryChain<Block> {
    fn new(ancestry: &[Block::Header]) -> AncestryChain<Block> {
        let ancestry: BTreeMap<_, _> = ancestry
            .iter()
            .cloned()
            .map(|h: Block::Header| (h.hash(), h))
            .collect();

        AncestryChain { ancestry }
    }
}

impl<Block: BlockT> finality_grandpa::Chain<Block::Hash, NumberFor<Block>> for AncestryChain<Block>
where
    NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
    fn ancestry(
        &self,
        base: Block::Hash,
        block: Block::Hash,
    ) -> Result<Vec<Block::Hash>, GrandpaError> {
        let mut route = Vec::new();
        let mut current_hash = block;
        loop {
            if current_hash == base {
                break;
            }
            match self.ancestry.get(&current_hash) {
                Some(current_header) => {
                    current_hash = *current_header.parent_hash();
                    route.push(current_hash);
                }
                _ => return Err(GrandpaError::NotDescendent),
            }
        }
        route.pop(); // remove the base

        Ok(route)
    }

    fn best_chain_containing(
        &self,
        _block: Block::Hash,
    ) -> Option<(Block::Hash, NumberFor<Block>)> {
        None
    }
}
