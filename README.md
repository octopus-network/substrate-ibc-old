# frame
A collection of frames (a.k.a. pallet, paint, srml ...) used by Cdot.

## pallet-ibc (work in progress)
pallet-ibc is a substrate pallet which implements the standard [IBC protocol](https://github.com/cosmos/ics).</br>

The goal of this pallet is to allow the blockchains built on Substrate to gain the ability to cross-chain using IBC protocol, even interoperate with those chains built by Cosmos SDK.</br>
This project is currently in an early stage and will eventually be submitted to upstream.</br>
Here is a [test chain](https://github.com/en/ibc-demo/tree/master/node-template) that is using this library.</br>
And here is a [small package](https://github.com/en/ibc-demo/tree/master/node-template/calls) that allows an RPC client based on substrate-subxt to interact with the test chain through RPC.</br>
Also an implementation of [relayer process](https://github.com/en/ibc-demo/tree/master/node-template/relayer)(defined in [ICS 018](https://github.com/cosmos/ics/tree/master/spec/ics-018-relayer-algorithms)) and a [cli tool](https://github.com/en/ibc-demo/tree/master/node-template/cli) to make the cross-chain work.</br>

**All open source contributions are welcome!!!**
