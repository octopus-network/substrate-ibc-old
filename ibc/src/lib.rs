// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod handler;
mod routing;

use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage, dispatch::Result, ensure, weights::SimpleDispatchInfo,
};
use sp_core::H256;
use sp_runtime::{generic, RuntimeDebug};
use sp_std::prelude::*;
use system::ensure_signed;

#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug)]
pub enum Datagram {
    ClientUpdate {
        identifier: H256,
        header: generic::Header<u32, sp_runtime::traits::BlakeTwo256>, // TODO
    },
    ClientMisbehaviour {
        identifier: H256,
        evidence: Vec<u8>,
    },
}

#[derive(Encode, Decode)]
pub enum ConnectionState {
    None,
    Init,
    TryOpen,
    Open,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Default, Encode, Decode)]
pub struct ConnectionEnd {
    state: ConnectionState,
    counterparty_connection_identifier: H256,
    counterparty_prefix: Vec<u8>,
    client_identifier: H256,
    counterparty_client_identifier: H256,
    version: Vec<u8>,
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct Client {
    client_state: Vec<u8>,
    pub consensus_state: ConsensusState,
    typ: u32,
    connections: Vec<H256>, // TODO: fixme! O(n)
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ConsensusState {
    pub height: u32,
    validity_predicate: Vec<u8>,
    misbehaviour_predicate: Vec<u8>,
}

/// Our module's configuration trait. All our types and constants go in here. If the
/// module is dependent on specific other modules, then their configuration traits
/// should be added to our implied traits list.
///
/// `system::Trait` should always be included in our implied traits.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    // A macro for the Storage trait, and its implementation, for this module.
    // This allows for type-safe usage of the Substrate storage database, so you can
    // keep things around between blocks.
    trait Store for Module<T: Trait> as Ibc {
        Something get(fn something): Option<u32>;
        Clients: map H256 => Client;
        Connections: map H256 => ConnectionEnd;
    }
}

decl_event!(
    /// Events are a simple means of reporting specific conditions and
    /// circumstances that have happened that users, Dapps and/or chain explorers would find
    /// interesting and otherwise difficult to detect.
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        SomethingStored(u32, AccountId),
        ClientCreated,
        ClientUpdated,
        ClientMisbehaviourReceived,
        ConnectionInit,
    }
);

decl_module! {
    // Simple declaration of the `Module` type. Lets the macro know what its working on.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        /// Deposit one of this module's events by using the default implementation.
        /// It is also possible to provide a custom implementation.
        /// For non-generic events, the generic parameter just needs to be dropped, so that it
        /// looks like: `fn deposit_event() = default;`.
        fn deposit_event() = default;
        /// This is your public interface. Be extremely careful.
        /// This is just a simple example of how to interact with the module from the external
        /// world.
        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn recv_packet(origin, packet: Vec<u8>, proof: Vec<Vec<u8>>, proof_height: T::BlockNumber) -> Result {
            let _sender = ensure_signed(origin)?;
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn submit_datagram(origin, datagram: Datagram) -> Result {
            let _sender = ensure_signed(origin)?;
            Self::handle_datagram(datagram)
        }

        // The signature could also look like: `fn on_initialize()`.
        // This function could also very well have a weight annotation, similar to any other. The
        // only difference being that if it is not annotated, the default is
        // `SimpleDispatchInfo::zero()`, which resolves into no weight.
        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn on_initialize(_n: T::BlockNumber) {
            // Anything that needs to be done at the start of the block.
            // We don't do anything here.
        }

        // The signature could also look like: `fn on_finalize()`
        #[weight = SimpleDispatchInfo::FixedNormal(2000)]
        fn on_finalize(_n: T::BlockNumber) {
            // Anything that needs to be done at the end of the block.
            // We just kill our dummy storage item.
            // <Dummy<T>>::kill();
        }

        // A runtime code run after every block and have access to extended set of APIs.
        //
        // For instance you can generate extrinsics for the upcoming produced block.
        fn offchain_worker(_n: T::BlockNumber) {
            // We don't do anything here.
            // but we could dispatch extrinsic (transaction/unsigned/inherent) using
            // runtime_io::submit_extrinsic
        }
    }
}

impl<T: Trait> Module<T> {
    pub fn create_client(identifier: H256) -> Result {
        ensure!(
            !Clients::exists(&identifier),
            "Client identifier already exists"
        );
        let client = Client {
            client_state: vec![],
            consensus_state: ConsensusState {
                height: 0,
                validity_predicate: vec![],
                misbehaviour_predicate: vec![],
            },
            typ: 0,
            connections: vec![],
        };
        Clients::insert(&identifier, client);
        Self::deposit_event(RawEvent::ClientCreated);
        Ok(())
    }

    pub fn conn_open_init(
        identifier: H256,
        desired_counterparty_connection_identifier: H256,
        client_identifier: H256,
        counterparty_client_identifier: H256,
    ) -> Result {
        // abortTransactionUnless(validateConnectionIdentifier(identifier))
        ensure!(
            Clients::exists(&client_identifier),
            "Client identifier not exists"
        );
        // TODO: ensure!(!client.connections.exists(&identifier)))
        ensure!(
            !Connections::exists(&identifier),
            "Connection identifier already exists"
        );
        let connection_end = ConnectionEnd {
            state: ConnectionState::Init,
            counterparty_connection_identifier: desired_counterparty_connection_identifier,
            counterparty_prefix: vec![],
            client_identifier,
            counterparty_client_identifier,
            version: vec![], // getCompatibleVersions()
        };

        Connections::insert(&identifier, connection_end);
        // addConnectionToClient(clientIdentifier, identifier)
        Clients::mutate(&client_identifier, |client| {
            (*client).connections.push(identifier);
        });
        Self::deposit_event(RawEvent::ConnectionInit);
        Ok(())
    }

    pub fn handle_datagram(datagram: Datagram) -> Result {
        match datagram {
            Datagram::ClientUpdate { identifier, header } => {
                ensure!(Clients::exists(&identifier), "Client not found");
                let client = Clients::get(&identifier);
                ensure!(
                    client.consensus_state.height < header.number,
                    "Client already updated"
                );
                // TODO: verify header using validity_predicate
                Clients::mutate(&identifier, |client| {
                    (*client).consensus_state.height = header.number;
                });
                Self::deposit_event(RawEvent::ClientUpdated);
            }
            Datagram::ClientMisbehaviour {
                identifier,
                evidence,
            } => {
                Self::deposit_event(RawEvent::ClientMisbehaviourReceived);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
