// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod handler;
mod routing;

use codec::{Decode, Encode};
use rstd::prelude::*;
use sp_runtime::RuntimeDebug;
use support::{
    decl_event, decl_module, decl_storage, dispatch::Result, weights::SimpleDispatchInfo,
};
use system::ensure_signed;

type Identifier = u32;

#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug)]
pub enum Datagram<Header> {
    ClientUpdate {
        identifier: Identifier,
        header: Header,
    },
    ClientMisbehaviour {
        identifier: Identifier,
        evidence: Vec<u8>,
    },
}

#[derive(Encode, Decode, Default)]
struct Client {
    client_state: Vec<u8>,
    consensus_state: Vec<u8>,
    typ: u32,
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
        Clients: map Vec<u8> => Client;
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
        fn update_client(origin, id: u32, header: Vec<u8>) -> Result {
            let _sender = ensure_signed(origin)?;
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn recv_packet(origin, packet: Vec<u8>, proof: Vec<Vec<u8>>, proof_height: T::BlockNumber) -> Result {
            let _sender = ensure_signed(origin)?;
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn submit_datagram(origin, datagram: Datagram<<T as system::Trait>::Header>) -> Result {
            let _sender = ensure_signed(origin)?;
            Self::handle_datagram(datagram);
            Ok(())
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
    pub fn create_client() {
        let client = Client {
            client_state: vec![],
            consensus_state: vec![],
            typ: 0,
        };
        Clients::insert(b"123".to_vec(), client);
        Self::deposit_event(RawEvent::ClientCreated);
    }

    pub fn handle_datagram<Header>(datagram: Datagram<Header>) {
        match datagram {
            Datagram::ClientUpdate { identifier, header } => {
                Self::deposit_event(RawEvent::ClientUpdated);
            }
            Datagram::ClientMisbehaviour {
                identifier,
                evidence,
            } => {
                Self::deposit_event(RawEvent::ClientMisbehaviourReceived);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
