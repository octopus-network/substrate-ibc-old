// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod handler;
mod routing;

use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    weights::SimpleDispatchInfo,
};
use sp_core::H256;
use sp_runtime::{generic, RuntimeDebug};
use sp_std::prelude::*;
use system::ensure_signed;

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub enum Datagram {
    ClientUpdate {
        identifier: H256,
        header: generic::Header<u32, sp_runtime::traits::BlakeTwo256>, // TODO
    },
    ClientMisbehaviour {
        identifier: H256,
        evidence: Vec<u8>,
    },
    ConnOpenTry {
        desired_identifier: H256,
        counterparty_connection_identifier: H256,
        counterparty_client_identifier: H256,
        client_identifier: H256,
        version: Vec<u8>,
        counterparty_version: Vec<u8>,
        proof_init: Vec<u8>,
        proof_consensus: Vec<u8>,
        proof_height: u32,
        consensus_height: u32,
    },
    ConnOpenAck {
        identifier: H256,
        version: Vec<u8>,
        proof_try: Vec<u8>,
        proof_consensus: Vec<u8>,
        proof_height: u32,
        consensus_height: u32,
    },
    ConnOpenConfirm {
        identifier: H256,
        proof_ack: Vec<u8>,
        proof_height: u32,
    },
    ChanOpenTry {
        order: ChannelOrder,
        connection_hops: Vec<H256>,
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        counterparty_port_identifier: Vec<u8>,
        counterparty_channel_identifier: H256,
        version: Vec<u8>,
        counterparty_version: Vec<u8>,
        proof_init: Vec<u8>,
        proof_height: u32,
    },
    ChanOpenAck {
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        version: Vec<u8>,
        proof_try: Vec<u8>,
        proof_height: u32,
    },
    ChanOpenConfirm {
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        proof_ack: Vec<u8>,
        proof_height: u32,
    },
}

#[derive(Clone, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum ConnectionState {
    None,
    Init,
    TryOpen,
    Open,
    Closed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ConnectionEnd {
    pub state: ConnectionState,
    pub counterparty_connection_identifier: H256,
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
    pub connections: Vec<H256>, // TODO: fixme! O(n)
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ConsensusState {
    pub height: u32,
    validity_predicate: Vec<u8>,
    misbehaviour_predicate: Vec<u8>,
}

#[derive(Clone, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum ChannelState {
    None,
    Init,
    TryOpen,
    Open,
    Closed,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub enum ChannelOrder {
    Ordered,
    Unordered,
}

impl Default for ChannelOrder {
    fn default() -> Self {
        Self::Ordered
    }
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ChannelEnd {
    pub state: ChannelState,
    pub ordering: ChannelOrder,
    pub counterparty_port_identifier: Vec<u8>,
    pub counterparty_channel_identifier: H256,
    pub connection_hops: Vec<H256>,
    pub version: Vec<u8>,
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
        Ports: map Vec<u8> => u8;
        Channels: map (Vec<u8>, H256) => ChannelEnd; // ports/{portIdentifier}/channels/{channelIdentifier}
        NextSequenceSend: map(Vec<u8>, H256) => u32;
        NextSequenceRecv: map(Vec<u8>, H256) => u32;
        ChannelKeys: Vec<(Vec<u8>, H256)>; // TODO
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
        ConnOpenInitReceived,
        ConnOpenTryReceived,
        ConnOpenAckReceived,
        ConnOpenConfirmReceived,
        PortBound(u8),
        PortReleased,
        ChanOpenInitReceived,
        ChanOpenTryReceived,
        ChanOpenAckReceived,
        ChanOpenConfirmReceived,
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
        fn submit_datagram(origin, datagram: Datagram) -> DispatchResult {
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
    pub fn create_client(identifier: H256) -> DispatchResult {
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
    ) -> DispatchResult {
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
        Self::deposit_event(RawEvent::ConnOpenInitReceived);
        Ok(())
    }

    pub fn bind_port(identifier: Vec<u8>, module_index: u8) -> DispatchResult {
        // abortTransactionUnless(validatePortIdentifier(id))
        ensure!(
            !Ports::exists(&identifier),
            "Port identifier already exists"
        );
        Ports::insert(&identifier, module_index);
        Self::deposit_event(RawEvent::PortBound(module_index));
        Ok(())
    }

    pub fn release_port(identifier: Vec<u8>, module_index: u8) -> DispatchResult {
        ensure!(
            Ports::get(&identifier) == module_index,
            "Port identifier not found"
        );
        Ports::remove(&identifier);
        Self::deposit_event(RawEvent::PortReleased);
        Ok(())
    }

    pub fn chan_open_init(
        module_index: u8,
        order: ChannelOrder,
        connection_hops: Vec<H256>,
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        counterparty_port_identifier: Vec<u8>,
        counterparty_channel_identifier: H256,
        version: Vec<u8>,
    ) -> DispatchResult {
        // abortTransactionUnless(validateChannelIdentifier(portIdentifier, channelIdentifier))
        ensure!(
            connection_hops.len() == 1,
            "only allow 1 hop for v1 of the IBC protocol"
        );

        ensure!(
            !Channels::exists((port_identifier.clone(), channel_identifier)),
            "channel identifier already exists"
        );
        ensure!(
            Connections::exists(&connection_hops[0]),
            "connection identifier not exists"
        );

        // optimistic channel handshakes are allowed
        let connection = Connections::get(&connection_hops[0]);
        ensure!(
            connection.state != ConnectionState::Closed,
            "connection has been closed"
        );
        // abortTransactionUnless(authenticate(privateStore.get(portPath(portIdentifier))))
        ensure!(
            Ports::get(&port_identifier) == module_index,
            "Port identifier not match"
        );
        let channel_end = ChannelEnd {
            state: ChannelState::Init,
            ordering: order,
            counterparty_port_identifier,
            counterparty_channel_identifier,
            connection_hops,
            version: vec![],
        };
        Channels::insert((port_identifier.clone(), channel_identifier), channel_end);
        // key = generate()
        // provableStore.set(channelCapabilityPath(portIdentifier, channelIdentifier), key)
        NextSequenceSend::insert((port_identifier.clone(), channel_identifier), 1);
        NextSequenceRecv::insert((port_identifier.clone(), channel_identifier), 1);
        // return key
        ChannelKeys::mutate(|keys| {
            (*keys).push((port_identifier.clone(), channel_identifier));
        });
        Self::deposit_event(RawEvent::ChanOpenInitReceived);
        Ok(())
    }

    pub fn handle_datagram(datagram: Datagram) -> DispatchResult {
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
            Datagram::ConnOpenTry {
                desired_identifier,
                counterparty_connection_identifier,
                counterparty_client_identifier,
                client_identifier,
                version,
                counterparty_version,
                proof_init,
                proof_consensus,
                proof_height,
                consensus_height,
            } => {
                ensure!(Clients::exists(&client_identifier), "Client not found");
                ensure!(
                    !Connections::exists(&desired_identifier),
                    "Connection identifier already exists"
                );
                // abortTransactionUnless(validateConnectionIdentifier(desiredIdentifier))
                // abortTransactionUnless(consensusHeight <= getCurrentHeight())
                // expectedConsensusState = getConsensusState(consensusHeight)
                // expected = ConnectionEnd{INIT, desiredIdentifier, getCommitmentPrefix(), counterpartyClientIdentifier,
                //                          clientIdentifier, counterpartyVersions}
                // version = pickVersion(counterpartyVersions)
                let connection = ConnectionEnd {
                    state: ConnectionState::TryOpen,
                    counterparty_connection_identifier,
                    counterparty_prefix: vec![],
                    client_identifier,
                    counterparty_client_identifier,
                    version: vec![],
                };
                // abortTransactionUnless(connection.verifyConnectionState(proofHeight, proofInit, counterpartyConnectionIdentifier, expected))
                // abortTransactionUnless(connection.verifyClientConsensusState(proofHeight, proofConsensus, counterpartyClientIdentifier, expectedConsensusState))
                // previous = provableStore.get(connectionPath(desiredIdentifier))
                // abortTransactionUnless(
                //   (previous === null) ||
                //   (previous.state === INIT &&
                //     previous.counterpartyConnectionIdentifier === counterpartyConnectionIdentifier &&
                //     previous.counterpartyPrefix === counterpartyPrefix &&
                //     previous.clientIdentifier === clientIdentifier &&
                //     previous.counterpartyClientIdentifier === counterpartyClientIdentifier &&
                //     previous.version === version))
                let identifier = desired_identifier;
                Connections::insert(&identifier, connection);
                // addConnectionToClient(clientIdentifier, identifier)
                Clients::mutate(&client_identifier, |client| {
                    (*client).connections.push(identifier);
                });
                Self::deposit_event(RawEvent::ConnOpenTryReceived);
            }
            Datagram::ConnOpenAck {
                identifier,
                version,
                proof_try,
                proof_consensus,
                proof_height,
                consensus_height,
            } => {
                ensure!(Connections::exists(&identifier), "Connection not found");
                // abortTransactionUnless(consensusHeight <= getCurrentHeight())
                // connection = provableStore.get(connectionPath(identifier))
                // abortTransactionUnless(connection.state === INIT || connection.state === TRYOPEN)
                // expectedConsensusState = getConsensusState(consensusHeight)
                // expected = ConnectionEnd{TRYOPEN, identifier, getCommitmentPrefix(),
                //                          connection.counterpartyClientIdentifier, connection.clientIdentifier,
                //                          version}
                // abortTransactionUnless(connection.verifyConnectionState(proofHeight, proofTry, connection.counterpartyConnectionIdentifier, expected))
                // abortTransactionUnless(connection.verifyClientConsensusState(proofHeight, proofConsensus, connection.counterpartyClientIdentifier, expectedConsensusState))
                Connections::mutate(&identifier, |connection| {
                    (*connection).state = ConnectionState::Open;
                });
                // abortTransactionUnless(getCompatibleVersions().indexOf(version) !== -1)
                // connection.version = version
                // provableStore.set(connectionPath(identifier), connection)
                Self::deposit_event(RawEvent::ConnOpenAckReceived);
            }
            Datagram::ConnOpenConfirm {
                identifier,
                proof_ack,
                proof_height,
            } => {
                ensure!(Connections::exists(&identifier), "Connection not found");
                // connection = provableStore.get(connectionPath(identifier))
                // abortTransactionUnless(connection.state === TRYOPEN)
                // expected = ConnectionEnd{OPEN, identifier, getCommitmentPrefix(), connection.counterpartyClientIdentifier,
                //                          connection.clientIdentifier, connection.version}
                // abortTransactionUnless(connection.verifyConnectionState(proofHeight, proofAck, connection.counterpartyConnectionIdentifier, expected))
                Connections::mutate(&identifier, |connection| {
                    (*connection).state = ConnectionState::Open;
                });
                // provableStore.set(connectionPath(identifier), connection)
                Self::deposit_event(RawEvent::ConnOpenConfirmReceived);
            }
            Datagram::ChanOpenTry {
                order,
                connection_hops,
                port_identifier,
                channel_identifier,
                counterparty_port_identifier,
                counterparty_channel_identifier,
                version,
                counterparty_version,
                proof_init,
                proof_height,
            } => {
                // abortTransactionUnless(validateChannelIdentifier(portIdentifier, channelIdentifier))
                ensure!(
                    connection_hops.len() == 1,
                    "only allow 1 hop for v1 of the IBC protocol"
                );
                // ???
                // previous = provableStore.get(channelPath(portIdentifier, channelIdentifier))
                // abortTransactionUnless(
                //   (previous === null) ||
                //   (previous.state === INIT &&
                //    previous.order === order &&
                //    previous.counterpartyPortIdentifier === counterpartyPortIdentifier &&
                //    previous.counterpartyChannelIdentifier === counterpartyChannelIdentifier &&
                //    previous.connectionHops === connectionHops &&
                //    previous.version === version)
                //   )
                ensure!(
                    !Channels::exists((port_identifier.clone(), channel_identifier)),
                    "channel identifier already exists"
                );
                // abortTransactionUnless(authenticate(privateStore.get(portPath(portIdentifier))))
                ensure!(
                    Connections::exists(&connection_hops[0]),
                    "connection identifier not exists"
                );
                let connection = Connections::get(&connection_hops[0]);
                ensure!(
                    connection.state == ConnectionState::Open,
                    "connection has been closed"
                );
                // expected = ChannelEnd{INIT, order, portIdentifier,
                //                       channelIdentifier, connectionHops.reverse(), counterpartyVersion}
                // abortTransactionUnless(connection.verifyChannelState(
                //   proofHeight,
                //   proofInit,
                //   counterpartyPortIdentifier,
                //   counterpartyChannelIdentifier,
                //   expected
                // ))
                let channel_end = ChannelEnd {
                    state: ChannelState::TryOpen,
                    ordering: order,
                    counterparty_port_identifier,
                    counterparty_channel_identifier,
                    connection_hops,
                    version,
                };
                Channels::insert((port_identifier.clone(), channel_identifier), channel_end);
                // key = generate()
                // provableStore.set(channelCapabilityPath(portIdentifier, channelIdentifier), key)
                NextSequenceSend::insert((port_identifier.clone(), channel_identifier), 1);
                NextSequenceRecv::insert((port_identifier.clone(), channel_identifier), 1);
                // return key
                ChannelKeys::mutate(|keys| {
                    (*keys).push((port_identifier.clone(), channel_identifier));
                });
                Self::deposit_event(RawEvent::ChanOpenTryReceived);
            }
            Datagram::ChanOpenAck {
                port_identifier,
                channel_identifier,
                version,
                proof_try,
                proof_height,
            } => {
                ensure!(
                    Channels::exists((port_identifier.clone(), channel_identifier)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((port_identifier.clone(), channel_identifier));
                ensure!(
                    channel.state == ChannelState::Init || channel.state == ChannelState::TryOpen,
                    "channel is not ready"
                );
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(portIdentifier, channelIdentifier))))
                ensure!(
                    Connections::exists(&channel.connection_hops[0]),
                    "connection identifier not exists"
                );
                let connection = Connections::get(&channel.connection_hops[0]);
                ensure!(
                    connection.state == ConnectionState::Open,
                    "connection has been closed"
                );
                // expected = ChannelEnd{TRYOPEN, channel.order, portIdentifier,
                //                       channelIdentifier, channel.connectionHops.reverse(), counterpartyVersion}
                // abortTransactionUnless(connection.verifyChannelState(
                //   proofHeight,
                //   proofTry,
                //   channel.counterpartyPortIdentifier,
                //   channel.counterpartyChannelIdentifier,
                //   expected
                // ))
                // channel.version = counterpartyVersion
                Channels::mutate((port_identifier, channel_identifier), |channel| {
                    (*channel).state = ChannelState::Open;
                });
                Self::deposit_event(RawEvent::ChanOpenAckReceived);
            }
            Datagram::ChanOpenConfirm {
                port_identifier,
                channel_identifier,
                proof_ack,
                proof_height,
            } => {
                ensure!(
                    Channels::exists((port_identifier.clone(), channel_identifier)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((port_identifier.clone(), channel_identifier));
                ensure!(
                    channel.state == ChannelState::TryOpen,
                    "channel is not ready"
                );
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(portIdentifier, channelIdentifier))))
                ensure!(
                    Connections::exists(&channel.connection_hops[0]),
                    "connection identifier not exists"
                );
                let connection = Connections::get(&channel.connection_hops[0]);
                ensure!(
                    connection.state == ConnectionState::Open,
                    "connection has been closed"
                );
                // expected = ChannelEnd{OPEN, channel.order, portIdentifier,
                //                       channelIdentifier, channel.connectionHops.reverse(), channel.version}
                // abortTransactionUnless(connection.verifyChannelState(
                //   proofHeight,
                //   proofAck,
                //   channel.counterpartyPortIdentifier,
                //   channel.counterpartyChannelIdentifier,
                //   expected
                // ))
                Channels::mutate((port_identifier, channel_identifier), |channel| {
                    (*channel).state = ChannelState::Open;
                });
                Self::deposit_event(RawEvent::ChanOpenConfirmReceived);
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
