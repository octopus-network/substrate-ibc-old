// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod handler;
mod justification;
mod routing;
mod state_machine;

use codec::{Decode, Encode};
use frame_support::{
    debug, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    weights::SimpleDispatchInfo,
};
use sp_core::H256;
use sp_finality_grandpa::{AuthorityList, SetId, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::{
    generic, traits::BlakeTwo256, OpaqueExtrinsic as UncheckedExtrinsic, RuntimeDebug,
};
use sp_std::prelude::*;
use state_machine::{read_proof_check, StorageProof};
use system::ensure_signed;

type BlockNumber = u32;
type Block = generic::Block<generic::Header<BlockNumber, BlakeTwo256>, UncheckedExtrinsic>;

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct Packet {
    pub sequence: u64,
    pub timeout_height: u32,
    pub source_port: Vec<u8>,
    pub source_channel: H256,
    pub dest_port: Vec<u8>,
    pub dest_channel: H256,
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub enum Datagram {
    ClientUpdate {
        identifier: H256,
        header: Header,
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
        proof_init: Vec<Vec<u8>>,
        proof_consensus: Vec<Vec<u8>>,
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
    PacketRecv {
        packet: Packet,
        proof: Vec<u8>,
        proof_height: u32,
    },
    PacketAcknowledgement {
        packet: Packet,
        acknowledgement: Vec<u8>,
        proof: Vec<u8>,
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
pub struct ClientState {
    frozen: bool,
    pub latest_height: u32,
    pub connections: Vec<H256>, // TODO: fixme! O(n)
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ConsensusState {
    set_id: SetId,
    authorities: AuthorityList,
    commitment_root: H256,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct Header {
    pub height: u32,
    pub block_hash: H256,
    pub commitment_root: H256,
    pub justification: Vec<u8>,
    pub authorities_proof: Vec<Vec<u8>>,
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

        Clients: map hasher(blake2_128_concat) H256 => ClientState; // client_identifier => ClientState
        ConsensusStates: map hasher(blake2_128_concat) (H256, u32) => ConsensusState; // (client_identifier, height) => ConsensusState
        Connections: map hasher(blake2_128_concat) H256 => ConnectionEnd; // connection_identifier => ConnectionEnd

        Ports: map hasher(blake2_128_concat) Vec<u8> => u8;
        Channels: map hasher(blake2_128_concat) (Vec<u8>, H256) => ChannelEnd; // ports/{portIdentifier}/channels/{channelIdentifier}
        NextSequenceSend: map hasher(blake2_128_concat) (Vec<u8>, H256) => u64;
        NextSequenceRecv: map hasher(blake2_128_concat) (Vec<u8>, H256) => u64;
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
        SendPacket(u64, Vec<u8>, u32, Vec<u8>, H256, Vec<u8>, H256),
        RecvPacket(u64, Vec<u8>, u32, Vec<u8>, H256, Vec<u8>, H256),
        PacketRecvReceived,
        PacketAcknowledgementReceived,
    }
);

decl_module! {
    // Simple declaration of the `Module` type. Lets the macro know what its working on.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin
    {
        /// Deposit one of this module's events by using the default implementation.
        /// It is also possible to provide a custom implementation.
        /// For non-generic events, the generic parameter just needs to be dropped, so that it
        /// looks like: `fn deposit_event() = default;`.
        fn deposit_event() = default;
        /// This is your public interface. Be extremely careful.
        /// This is just a simple example of how to interact with the module from the external
        /// world.
        #[weight = SimpleDispatchInfo::FixedNormal(1000)]
        fn submit_datagram(origin, datagram: Datagram) -> DispatchResult
        {
            debug::RuntimeLogger::init();
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
    pub fn create_client(
        identifier: H256,
        height: u32,
        commitment_root: H256,
        set_id: SetId,
        authorities: AuthorityList,
    ) -> DispatchResult {
        ensure!(
            !Clients::contains_key(&identifier),
            "Client identifier already exists"
        );

        let client_state = ClientState {
            frozen: false,
            latest_height: height,
            connections: vec![],
        };
        Clients::insert(&identifier, client_state);

        let consensus_state = ConsensusState {
            set_id,
            authorities,
            commitment_root,
        };
        ConsensusStates::insert((identifier, height), consensus_state);
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
            Clients::contains_key(&client_identifier),
            "Client identifier not exists"
        );
        // TODO: ensure!(!client.connections.exists(&identifier)))
        ensure!(
            !Connections::contains_key(&identifier),
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

        debug::native::print!("connection inserted: {:?}", identifier);
        Connections::insert(&identifier, connection_end);
        // addConnectionToClient(clientIdentifier, identifier)
        Clients::mutate(&client_identifier, |client_state| {
            (*client_state).connections.push(identifier);
        });
        Self::deposit_event(RawEvent::ConnOpenInitReceived);
        Ok(())
    }

    pub fn bind_port(identifier: Vec<u8>, module_index: u8) -> DispatchResult {
        // abortTransactionUnless(validatePortIdentifier(id))
        ensure!(
            !Ports::contains_key(&identifier),
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
            !Channels::contains_key((port_identifier.clone(), channel_identifier)),
            "channel identifier already exists"
        );
        ensure!(
            Connections::contains_key(&connection_hops[0]),
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

    pub fn send_packet(packet: Packet) -> DispatchResult {
        let channel = Channels::get((packet.source_port.clone(), packet.source_channel));
        // optimistic sends are permitted once the handshake has started
        ensure!(
            channel.state != ChannelState::Closed,
            "channel has been closed"
        );

        // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(packet.sourcePort, packet.sourceChannel))))
        ensure!(
            packet.dest_port == channel.counterparty_port_identifier,
            "port not match"
        );
        ensure!(
            packet.dest_channel == channel.counterparty_channel_identifier,
            "channel not match"
        );
        let connection = Connections::get(&channel.connection_hops[0]);
        ensure!(
            connection.state != ConnectionState::Closed,
            "connection has been closed"
        );

        // consensusState = provableStore.get(consensusStatePath(connection.clientIdentifier))
        // abortTransactionUnless(consensusState.getHeight() < packet.timeoutHeight)

        let mut next_sequence_send =
            NextSequenceSend::get((packet.source_port.clone(), packet.source_channel));
        ensure!(
            packet.sequence == next_sequence_send,
            "send sequence not match"
        );

        // all assertions passed, we can alter state
        next_sequence_send = next_sequence_send + 1;
        NextSequenceSend::insert(
            (packet.source_port.clone(), packet.source_channel),
            next_sequence_send,
        );
        // provableStore.set(packetCommitmentPath(packet.sourcePort, packet.sourceChannel, packet.sequence), hash(packet.data, packet.timeout))

        // log that a packet has been sent
        Self::deposit_event(RawEvent::SendPacket(
            packet.sequence,
            packet.data,
            packet.timeout_height,
            packet.source_port,
            packet.source_channel,
            packet.dest_port,
            packet.dest_channel,
        ));
        Ok(())
    }

    pub fn handle_datagram(datagram: Datagram) -> DispatchResult {
        match datagram {
            Datagram::ClientUpdate { identifier, header } => {
                ensure!(Clients::contains_key(&identifier), "Client not found");
                let client_state = Clients::get(&identifier);
                ensure!(
                    client_state.latest_height < header.height,
                    "Client already updated"
                );
                ensure!(
                    ConsensusStates::contains_key((identifier, client_state.latest_height)),
                    "ConsensusState not found"
                );
                let consensus_state =
                    ConsensusStates::get((identifier, client_state.latest_height));
                // TODO: verify header using validity_predicate
                let justification = justification::GrandpaJustification::<Block>::decode(
                    &mut &*header.justification,
                );
                debug::native::print!(
                    "consensus_state: {:?}, header: {:?}",
                    consensus_state,
                    header,
                );
                if let Ok(justification) = justification {
                    let result = justification.verify(
                        consensus_state.set_id,
                        &consensus_state.authorities.iter().cloned().collect(),
                    );
                    debug::native::print!("verify result: {:?}", result);
                    if result.is_ok() {
                        debug::native::print!("block_hash: {:?}", header.block_hash);
                        assert_eq!(header.block_hash, justification.commit.target_hash);
                        Clients::mutate(&identifier, |client_state| {
                            (*client_state).latest_height = header.height;
                        });
                        let new_consensus_state = ConsensusState {
                            set_id: consensus_state.set_id,
                            authorities: consensus_state.authorities.clone(),
                            commitment_root: header.commitment_root,
                        };
                        debug::native::print!(
                            "consensus_state inserted: {:?}, {}",
                            identifier,
                            header.height
                        );
                        ConsensusStates::insert((identifier, header.height), new_consensus_state);

                        let result = read_proof_check::<BlakeTwo256>(
                            header.commitment_root,
                            StorageProof::new(header.authorities_proof),
                            &GRANDPA_AUTHORITIES_KEY.to_vec(),
                        );
                        // TODO
                        let result = result.unwrap().unwrap();
                        let new_authorities: AuthorityList =
                            VersionedAuthorityList::decode(&mut &*result)
                                .unwrap()
                                .into();
                        debug::native::print!("new_authorities: {:?}", new_authorities);
                        if new_authorities != consensus_state.authorities {
                            ConsensusStates::mutate(
                                (identifier, header.height),
                                |consensus_state| {
                                    (*consensus_state).set_id += 1;
                                    (*consensus_state).authorities = new_authorities;
                                },
                            );
                        }
                        Self::deposit_event(RawEvent::ClientUpdated);
                    }
                }
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
                ensure!(
                    Clients::contains_key(&client_identifier),
                    "Client not found"
                );
                ensure!(
                    !Connections::contains_key(&desired_identifier),
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
                debug::native::print!(
                    "query consensus_state: {:?}, {}",
                    client_identifier,
                    proof_height
                );
                ensure!(
                    ConsensusStates::contains_key((client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let consensus_state = ConsensusStates::get((client_identifier, proof_height));
                let key = Connections::hashed_key_for(counterparty_connection_identifier);
                debug::native::print!(
                    "commitment_root: {:?}, counterparty_connection_identifier: {:?}, key: {:?}",
                    consensus_state.commitment_root,
                    counterparty_connection_identifier,
                    key
                );
                let result = read_proof_check::<BlakeTwo256>(
                    consensus_state.commitment_root,
                    StorageProof::new(proof_init),
                    &key,
                );
                let result = result.unwrap().unwrap();
                let connection_end = ConnectionEnd::decode(&mut &*result).unwrap();
                debug::native::print!(
                    "connecion_end: {:?}, counterparty_connection_identifier: {:?}",
                    connection_end,
                    counterparty_connection_identifier
                );

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
                Clients::mutate(&client_identifier, |client_state| {
                    (*client_state).connections.push(identifier);
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
                ensure!(
                    Connections::contains_key(&identifier),
                    "Connection not found"
                );
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
                ensure!(
                    Connections::contains_key(&identifier),
                    "Connection not found"
                );
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
                    !Channels::contains_key((port_identifier.clone(), channel_identifier)),
                    "channel identifier already exists"
                );
                // abortTransactionUnless(authenticate(privateStore.get(portPath(portIdentifier))))
                ensure!(
                    Connections::contains_key(&connection_hops[0]),
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
                    Channels::contains_key((port_identifier.clone(), channel_identifier)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((port_identifier.clone(), channel_identifier));
                ensure!(
                    channel.state == ChannelState::Init || channel.state == ChannelState::TryOpen,
                    "channel is not ready"
                );
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(portIdentifier, channelIdentifier))))
                ensure!(
                    Connections::contains_key(&channel.connection_hops[0]),
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
                    Channels::contains_key((port_identifier.clone(), channel_identifier)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((port_identifier.clone(), channel_identifier));
                ensure!(
                    channel.state == ChannelState::TryOpen,
                    "channel is not ready"
                );
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(portIdentifier, channelIdentifier))))
                ensure!(
                    Connections::contains_key(&channel.connection_hops[0]),
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
            Datagram::PacketRecv {
                packet,
                proof,
                proof_height,
            } => {
                ensure!(
                    Channels::contains_key((packet.dest_port.clone(), packet.dest_channel)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((packet.dest_port.clone(), packet.dest_channel));
                ensure!(channel.state == ChannelState::Open, "channel is not ready");
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(packet.destPort, packet.destChannel))))
                ensure!(
                    packet.source_port == channel.counterparty_port_identifier,
                    "source port not match"
                );
                ensure!(
                    packet.source_channel == channel.counterparty_channel_identifier,
                    "source channel not match"
                );

                ensure!(
                    Connections::contains_key(&channel.connection_hops[0]),
                    "connection identifier not exists"
                );
                let connection = Connections::get(&channel.connection_hops[0]);
                ensure!(
                    connection.state == ConnectionState::Open,
                    "connection has been closed"
                );

                // abortTransactionUnless(getConsensusHeight() < packet.timeoutHeight)

                // abortTransactionUnless(connection.verifyPacketCommitment(
                //   proofHeight,
                //   proof,
                //   packet.sourcePort,
                //   packet.sourceChannel,
                //   packet.sequence,
                //   hash(packet.data, packet.timeout)
                // ))

                // all assertions passed (except sequence check), we can alter state

                // if (acknowledgement.length > 0 || channel.order === UNORDERED)
                //   provableStore.set(
                //     packetAcknowledgementPath(packet.destPort, packet.destChannel, packet.sequence),
                //     hash(acknowledgement)
                //   )

                if channel.ordering == ChannelOrder::Ordered {
                    let mut next_sequence_recv =
                        NextSequenceRecv::get((packet.dest_port.clone(), packet.dest_channel));
                    ensure!(
                        packet.sequence == next_sequence_recv,
                        "recv sequence not match"
                    );
                    next_sequence_recv = next_sequence_recv + 1;
                    NextSequenceRecv::insert(
                        (packet.dest_port.clone(), packet.dest_channel),
                        next_sequence_recv,
                    );
                }

                // log that a packet has been received & acknowledged
                // emitLogEntry("recvPacket", {sequence: packet.sequence, timeout: packet.timeout, data: packet.data, acknowledgement})
                Self::deposit_event(RawEvent::RecvPacket(
                    packet.sequence,
                    packet.data,
                    packet.timeout_height,
                    packet.source_port,
                    packet.source_channel,
                    packet.dest_port,
                    packet.dest_channel,
                ));

                // return transparent packet
                // return packet
            }
            Datagram::PacketAcknowledgement {
                packet,
                acknowledgement,
                proof,
                proof_height,
            } => {
                // abort transaction unless that channel is open, calling module owns the associated port, and the packet fields match
                ensure!(
                    Channels::contains_key((packet.source_port.clone(), packet.source_channel)),
                    "channel identifier not exists"
                );
                let channel = Channels::get((packet.source_port.clone(), packet.source_channel));
                ensure!(channel.state == ChannelState::Open, "channel is not ready");
                // abortTransactionUnless(authenticate(privateStore.get(channelCapabilityPath(packet.sourcePort, packet.sourceChannel))))
                ensure!(
                    packet.source_channel == channel.counterparty_channel_identifier,
                    "source channel not match"
                );

                ensure!(
                    Connections::contains_key(&channel.connection_hops[0]),
                    "connection identifier not exists"
                );
                let connection = Connections::get(&channel.connection_hops[0]);
                ensure!(
                    connection.state == ConnectionState::Open,
                    "connection has been closed"
                );
                ensure!(
                    packet.source_port == channel.counterparty_port_identifier,
                    "source port not match"
                );

                // verify we sent the packet and haven't cleared it out yet
                // abortTransactionUnless(provableStore.get(packetCommitmentPath(packet.sourcePort, packet.sourceChannel, packet.sequence))
                //        === hash(packet.data, packet.timeout))

                // abort transaction unless correct acknowledgement on counterparty chain
                // abortTransactionUnless(connection.verifyPacketAcknowledgement(
                //   proofHeight,
                //   proof,
                //   packet.destPort,
                //   packet.destChannel,
                //   packet.sequence,
                //   hash(acknowledgement)
                // ))

                // all assertions passed, we can alter state

                // delete our commitment so we can't "acknowledge" again
                // provableStore.delete(packetCommitmentPath(packet.sourcePort, packet.sourceChannel, packet.sequence))

                // return transparent packet
                // return packet
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
