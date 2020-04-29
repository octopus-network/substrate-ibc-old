// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod clients;
mod handler;
mod justification;
mod routing;
mod state_machine;

use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure, weights::Weight,
};
use sp_core::H256;
use sp_finality_grandpa::{AuthorityList, SetId, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::{
    generic,
    traits::{BlakeTwo256, Hash},
    OpaqueExtrinsic as UncheckedExtrinsic, RuntimeDebug,
};
use sp_std::{if_std, prelude::*};
use sp_trie::StorageProof;
use state_machine::read_proof_check;
use system::ensure_signed;

pub use clients::ClientType;

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
        proof_init: StorageProof,
        proof_consensus: StorageProof,
        proof_height: u32,
        consensus_height: u32,
    },
    ConnOpenAck {
        identifier: H256,
        version: Vec<u8>,
        proof_try: StorageProof,
        proof_consensus: StorageProof,
        proof_height: u32,
        consensus_height: u32,
    },
    ConnOpenConfirm {
        identifier: H256,
        proof_ack: StorageProof,
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
        proof_init: StorageProof,
        proof_height: u32,
    },
    ChanOpenAck {
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        version: Vec<u8>,
        proof_try: StorageProof,
        proof_height: u32,
    },
    ChanOpenConfirm {
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        proof_ack: StorageProof,
        proof_height: u32,
    },
    PacketRecv {
        packet: Packet,
        proof: StorageProof,
        proof_height: u32,
    },
    PacketAcknowledgement {
        packet: Packet,
        acknowledgement: Vec<u8>,
        proof: StorageProof,
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
    pub latest_height: u32,
    frozen_height: Option<u32>,
    pub connections: Vec<H256>, // TODO: fixme! O(n)
    pub channels: Vec<(Vec<u8>, H256)>,
}

#[derive(Clone, Default, Encode, Decode, RuntimeDebug)]
pub struct ConsensusState {
    pub set_id: SetId,
    pub authorities: AuthorityList,
    pub commitment_root: H256,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct Header {
    pub height: u32,
    pub block_hash: H256,
    pub commitment_root: H256,
    pub justification: Vec<u8>,
    pub authorities_proof: StorageProof,
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
        Clients: map hasher(blake2_128_concat) H256 => ClientState; // client_identifier => ClientState
        ConsensusStates: map hasher(blake2_128_concat) (H256, u32) => ConsensusState; // (client_identifier, height) => ConsensusState
        Connections: map hasher(blake2_128_concat) H256 => ConnectionEnd; // connection_identifier => ConnectionEnd
        Ports: map hasher(blake2_128_concat) Vec<u8> => u8; // port_identifier => module_index
        Channels: map hasher(blake2_128_concat) (Vec<u8>, H256) => ChannelEnd; // (port_identifier, channel_identifier) => ChannelEnd
        NextSequenceSend: map hasher(blake2_128_concat) (Vec<u8>, H256) => u64; // (port_identifier, channel_identifier) => Sequence
        NextSequenceRecv: map hasher(blake2_128_concat) (Vec<u8>, H256) => u64; // (port_identifier, channel_identifier) => Sequence
        NextSequenceAck: map hasher(blake2_128_concat) (Vec<u8>, H256) => u64; // (port_identifier, channel_identifier) => Sequence
        Packets: map hasher(blake2_128_concat) (Vec<u8>, H256, u64) => H256; // (port_identifier, channel_identifier, sequence) => Hash
        Acknowledgements: map hasher(blake2_128_concat) (Vec<u8>, H256, u64) => H256; // (port_identifier, channel_identifier, sequence) => Hash
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
        RecvPacket(u64, Vec<u8>, u32, Vec<u8>, H256, Vec<u8>, H256, Vec<u8>),
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
            #[weight = 0]
        fn submit_datagram(origin, datagram: Datagram) -> DispatchResult
        {
            let _sender = ensure_signed(origin)?;
            Self::handle_datagram(datagram)
        }

        // The signature could also look like: `fn on_initialize()`.
        // This function could also very well have a weight annotation, similar to any other. The
        // only difference being that if it is not annotated, the default is
        // `SimpleDispatchInfo::zero()`, which resolves into no weight.
        fn on_initialize(_n: T::BlockNumber) -> Weight {
            // Anything that needs to be done at the start of the block.
            // We don't do anything here.

                  0
        }

        // The signature could also look like: `fn on_finalize()`
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
            // sp_io::submit_extrinsic
        }
    }
}

impl<T: Trait> Module<T> {
    pub fn create_client(
        identifier: H256,
        client_type: clients::ClientType,
        height: u32,
        consensus_state: ConsensusState,
    ) -> DispatchResult {
        ensure!(
            !Clients::contains_key(&identifier),
            "Client identifier already exists"
        );

        ConsensusStates::insert((identifier, height), consensus_state);
        let client_state = ClientState {
            latest_height: height,
            frozen_height: None,
            connections: vec![],
            channels: vec![],
        };
        Clients::insert(&identifier, client_state);

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

        if_std! {
            println!("connection inserted: {:?}", identifier);
        }
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
        NextSequenceAck::insert((port_identifier.clone(), channel_identifier), 1);
        // return key
        Clients::mutate(&connection.client_identifier, |client_state| {
            (*client_state)
                .channels
                .push((port_identifier.clone(), channel_identifier));
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
        let timeout_height = packet.timeout_height.encode();
        let hash = BlakeTwo256::hash_of(&[&packet.data[..], &timeout_height[..]].concat());

        Packets::insert(
            (
                packet.source_port.clone(),
                packet.source_channel,
                packet.sequence,
            ),
            hash,
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
                if_std! {
                    println!(
                        "consensus_state: {:?}, header: {:?}",
                        consensus_state,
                        header,
                    );
                }
                if let Ok(justification) = justification {
                    let result = justification.verify(
                        consensus_state.set_id,
                        &consensus_state.authorities.iter().cloned().collect(),
                    );
                    if_std! {
                        println!("verify result: {:?}", result);
                    }
                    if result.is_ok() {
                        if_std! {
                            println!("block_hash: {:?}", header.block_hash);
                        }
                        assert_eq!(header.block_hash, justification.commit.target_hash);
                        Clients::mutate(&identifier, |client_state| {
                            (*client_state).latest_height = header.height;
                        });
                        let new_consensus_state = ConsensusState {
                            set_id: consensus_state.set_id,
                            authorities: consensus_state.authorities.clone(),
                            commitment_root: header.commitment_root,
                        };
                        if_std! {
                            println!(
                                "consensus_state inserted: {:?}, {}",
                                identifier,
                                header.height
                            );
                        }
                        ConsensusStates::insert((identifier, header.height), new_consensus_state);

                        let result = read_proof_check::<BlakeTwo256>(
                            header.commitment_root,
                            header.authorities_proof,
                            &GRANDPA_AUTHORITIES_KEY.to_vec(),
                        );
                        // TODO
                        let result = result.unwrap().unwrap();
                        let new_authorities: AuthorityList =
                            VersionedAuthorityList::decode(&mut &*result)
                                .unwrap()
                                .into();
                        if_std! {
                            println!("new_authorities: {:?}", new_authorities);
                        }
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
                if_std! {
                    println!(
                        "query consensus_state: {:?}, {}",
                        client_identifier,
                        proof_height
                    );
                }
                ensure!(
                    ConsensusStates::contains_key((client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_connection_state(
                    client_identifier,
                    proof_height,
                    counterparty_connection_identifier,
                    proof_init,
                );
                ensure!(value.is_some(), "verify connection state failed");
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
                let connection = Connections::get(&identifier);
                ensure!(
                    connection.state == ConnectionState::Init
                        || connection.state == ConnectionState::TryOpen,
                    "connection state error"
                );
                // expectedConsensusState = getConsensusState(consensusHeight)
                // expected = ConnectionEnd{TRYOPEN, identifier, getCommitmentPrefix(),
                //                          connection.counterpartyClientIdentifier, connection.clientIdentifier,
                //                          version}
                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_connection_state(
                    connection.client_identifier,
                    proof_height,
                    connection.counterparty_connection_identifier,
                    proof_try,
                );
                ensure!(value.is_some(), "verify connection state failed");
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
                let connection = Connections::get(&identifier);
                ensure!(
                    connection.state == ConnectionState::TryOpen,
                    "connection state error"
                );
                // abortTransactionUnless(connection.state === TRYOPEN)
                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_connection_state(
                    connection.client_identifier,
                    proof_height,
                    connection.counterparty_connection_identifier,
                    proof_ack,
                );
                ensure!(value.is_some(), "verify connection state failed");
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

                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_channel_state(
                    connection.client_identifier,
                    proof_height,
                    counterparty_port_identifier.clone(),
                    counterparty_channel_identifier,
                    proof_init,
                );
                ensure!(value.is_some(), "verify channel state failed");
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
                Clients::mutate(&connection.client_identifier, |client_state| {
                    (*client_state)
                        .channels
                        .push((port_identifier.clone(), channel_identifier));
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
                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_channel_state(
                    connection.client_identifier,
                    proof_height,
                    channel.counterparty_port_identifier,
                    channel.counterparty_channel_identifier,
                    proof_try,
                );
                ensure!(value.is_some(), "verify channel state failed");
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
                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_channel_state(
                    connection.client_identifier,
                    proof_height,
                    channel.counterparty_port_identifier,
                    channel.counterparty_channel_identifier,
                    proof_ack,
                );
                ensure!(value.is_some(), "verify channel state failed");
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

                ensure!(
                    ConsensusStates::contains_key((connection.client_identifier, proof_height)),
                    "ConsensusState not found"
                );
                let value = Self::verify_packet_data(
                    connection.client_identifier,
                    proof_height,
                    proof,
                    packet.source_port.clone(),
                    packet.source_channel,
                    packet.sequence,
                );
                ensure!(value.is_some(), "verify packet data failed");
                let timeout_height = packet.timeout_height.encode();
                let hash = BlakeTwo256::hash_of(&[&packet.data[..], &timeout_height[..]].concat());
                ensure!(value.unwrap() == hash, "packet hash not match");
                // abortTransactionUnless(connection.verifyPacketCommitment(
                //   proofHeight,
                //   proof,
                //   packet.sourcePort,
                //   packet.sourceChannel,
                //   packet.sequence,
                //   hash(packet.data, packet.timeout)
                // ))

                // all assertions passed (except sequence check), we can alter state

                // for testing
                let acknowledgement: Vec<u8> = vec![1, 3, 3, 7];

                if acknowledgement.len() > 0 || channel.ordering == ChannelOrder::Unordered {
                    let hash = BlakeTwo256::hash_of(&acknowledgement);

                    Acknowledgements::insert(
                        (
                            packet.dest_port.clone(),
                            packet.dest_channel,
                            packet.sequence,
                        ),
                        hash,
                    );
                }

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
                    acknowledgement,
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
                    packet.dest_channel == channel.counterparty_channel_identifier,
                    "dest channel not match"
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
                    packet.dest_port == channel.counterparty_port_identifier,
                    "dest port not match"
                );

                // verify we sent the packet and haven't cleared it out yet
                // abortTransactionUnless(provableStore.get(packetCommitmentPath(packet.sourcePort, packet.sourceChannel, packet.sequence))
                //        === hash(packet.data, packet.timeout))
                let timeout_height = packet.timeout_height.encode();
                let expect_hash =
                    BlakeTwo256::hash_of(&[&packet.data[..], &timeout_height[..]].concat());

                let hash = Packets::get((
                    packet.source_port.clone(),
                    packet.source_channel,
                    packet.sequence,
                ));
                ensure!(expect_hash == hash, "packet hash not match");

                // abort transaction unless correct acknowledgement on counterparty chain
                // abortTransactionUnless(connection.verifyPacketAcknowledgement(
                //   proofHeight,
                //   proof,
                //   packet.destPort,
                //   packet.destChannel,
                //   packet.sequence,
                //   hash(acknowledgement)
                // ))
                let value = Self::verify_packet_acknowledgement(
                    connection.client_identifier,
                    proof_height,
                    proof,
                    packet.dest_port.clone(),
                    packet.dest_channel,
                    packet.sequence,
                );
                ensure!(value.is_some(), "verify packet acknowledgement failed");
                let hash = BlakeTwo256::hash_of(&acknowledgement);
                ensure!(
                    value.unwrap() == hash,
                    "packet acknowledgement hash not match"
                );

                // abort transaction unless acknowledgement is processed in order
                if channel.ordering == ChannelOrder::Ordered {
                    let mut next_sequence_ack =
                        NextSequenceAck::get((packet.dest_port.clone(), packet.dest_channel));
                    ensure!(
                        packet.sequence == next_sequence_ack,
                        "recv sequence not match"
                    );
                    next_sequence_ack = next_sequence_ack + 1;
                    NextSequenceAck::insert(
                        (packet.dest_port.clone(), packet.dest_channel),
                        next_sequence_ack,
                    );
                }

                // all assertions passed, we can alter state

                // delete our commitment so we can't "acknowledge" again
                Acknowledgements::remove((
                    packet.dest_port.clone(),
                    packet.dest_channel,
                    packet.sequence,
                ));

                // return transparent packet
                // return packet
            }
        }
        Ok(())
    }

    fn verify_connection_state(
        client_identifier: H256,
        proof_height: u32,
        connection_identifier: H256,
        proof: StorageProof,
    ) -> Option<ConnectionEnd> {
        let consensus_state = ConsensusStates::get((client_identifier, proof_height));
        let key = Connections::hashed_key_for(connection_identifier);
        let value = read_proof_check::<BlakeTwo256>(consensus_state.commitment_root, proof, &key);
        match value {
            Ok(value) => match value {
                Some(value) => {
                    let connection_end = ConnectionEnd::decode(&mut &*value);
                    match connection_end {
                        Ok(connection_end) => {
                            return Some(connection_end);
                        }
                        Err(error) => {
                            if_std! {
                                println!("trie value decode error: {:?}", error);
                            }
                        }
                    }
                }
                None => {
                    if_std! {
                        println!("read_proof_check error: value not exists");
                    }
                }
            },
            Err(error) => {
                if_std! {
                    println!("read_proof_check error: {:?}", error);
                }
            }
        }

        None
    }

    fn verify_channel_state(
        client_identifier: H256,
        proof_height: u32,
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        proof: StorageProof,
    ) -> Option<ChannelEnd> {
        let consensus_state = ConsensusStates::get((client_identifier, proof_height));
        let key = Channels::hashed_key_for((port_identifier, channel_identifier));
        let value = read_proof_check::<BlakeTwo256>(consensus_state.commitment_root, proof, &key);
        match value {
            Ok(value) => match value {
                Some(value) => {
                    let channel_end = ChannelEnd::decode(&mut &*value);
                    match channel_end {
                        Ok(channel_end) => {
                            return Some(channel_end);
                        }
                        Err(error) => {
                            if_std! {
                                println!("trie value decode error: {:?}", error);
                            }
                        }
                    }
                }
                None => {
                    if_std! {
                        println!("read_proof_check error: value not exists");
                    }
                }
            },
            Err(error) => {
                if_std! {
                    println!("read_proof_check error: {:?}", error);
                }
            }
        }

        None
    }

    fn verify_packet_data(
        client_identifier: H256,
        proof_height: u32,
        proof: StorageProof,
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        sequence: u64,
    ) -> Option<H256> {
        let consensus_state = ConsensusStates::get((client_identifier, proof_height));
        let key = Packets::hashed_key_for((port_identifier, channel_identifier, sequence));
        let value = read_proof_check::<BlakeTwo256>(consensus_state.commitment_root, proof, &key);
        match value {
            Ok(value) => match value {
                Some(value) => {
                    let hash = H256::decode(&mut &*value);
                    match hash {
                        Ok(hash) => {
                            return Some(hash);
                        }
                        Err(error) => {
                            if_std! {
                                println!("trie value decode error: {:?}", error);
                            }
                        }
                    }
                }
                None => {
                    if_std! {
                        println!("read_proof_check error: value not exists");
                    }
                }
            },
            Err(error) => {
                if_std! {
                    println!("read_proof_check error: {:?}", error);
                }
            }
        }

        None
    }

    fn verify_packet_acknowledgement(
        client_identifier: H256,
        proof_height: u32,
        proof: StorageProof,
        port_identifier: Vec<u8>,
        channel_identifier: H256,
        sequence: u64,
    ) -> Option<H256> {
        let consensus_state = ConsensusStates::get((client_identifier, proof_height));
        let key = Acknowledgements::hashed_key_for((port_identifier, channel_identifier, sequence));
        let value = read_proof_check::<BlakeTwo256>(consensus_state.commitment_root, proof, &key);
        match value {
            Ok(value) => match value {
                Some(value) => {
                    let hash = H256::decode(&mut &*value);
                    match hash {
                        Ok(hash) => {
                            return Some(hash);
                        }
                        Err(error) => {
                            if_std! {
                                println!("trie value decode error: {:?}", error);
                            }
                        }
                    }
                }
                None => {
                    if_std! {
                        println!("read_proof_check error: value not exists");
                    }
                }
            },
            Err(error) => {
                if_std! {
                    println!("read_proof_check error: {:?}", error);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
