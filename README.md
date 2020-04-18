# pallet-ibc (work in progress)
pallet-ibc is a substrate module which implements the standard [IBC protocol](https://github.com/cosmos/ics).</br>

The goal of this module is to allow the blockchains built on Substrate to gain the ability to interact with other chains in a trustless way via IBC protocol, no matter what consensus the counterpart chains use.</br>
This project is currently in an early stage and will eventually be submitted to upstream.</br>
Here is a [demo](https://github.com/en/ibc-demo/tree/master/node-template) for showing how to utilize this module.</br>
And here is a [small package](https://github.com/en/ibc-demo/tree/master/node-template/calls) that allows an RPC client based on substrate-subxt to interact with the test chain through RPC.</br>
The repository also includes implementation of [relayer process](https://github.com/en/ibc-demo/tree/master/node-template/relayer)(defined in [ICS 018](https://github.com/cosmos/ics/tree/master/spec/ics-018-relayer-algorithms)) and a [cli tool](https://github.com/en/ibc-demo/tree/master/node-template/cli) to make the cross-chain work.</br>

**All open source contributions are welcome!!!**
