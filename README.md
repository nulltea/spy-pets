# <h1 align="center">S𝛑PETs</h1>

Universal covert privacy-enhanced transactions for **ANY** public blockchain that supports ECDSA or Schnorr based on two-party computation (2PC) combined with adaptor signatures and verifiable timed commitments (VTC).

Read more details in the full paper - [S𝛑PETs: Sustainable Practically Indistinguishable Privacy-Enhanced Transactions](https://github.com/timoth-y/spy-pets/blob/main/paper/SpyPETs.pdf).


## Usage

### Network

By default, this library uses a local Ethereum node (http://localhost:8545). However, it also supports Mainnet and Goerli with the `--network` or `-n` flags.

> **Warning**: this is a prototype software. Its use on the live mainnet network haven't been tested and thus is not recommended.

### Setup wallet

First let's setup wallets, you'll need two - for Alice and Bob. You can generate them fresh new, recover from hex, or from BIP39 mnemonic. 

The following command will guide you through:
```bash
cargo run -- setup
```

### Run market-maker daemon

Bob will be market maker. He runs daemon with configured funded wallet and specifies target address where ETH will be transferred after swap.

**Usage:** &nbsp; `cargo run -- transfer [OPTIONS] -w <wallet> -a <server-address> -s <secondary-address>`

#### Example:
```bash
cargo run -- provide -w bob -p -t 3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
```

### Covert transfer

Alice will be market taker. She knows the URL of the Bob's daemon and runs client with specified target address where ETH will be transferred after swap and the amount of ETH she wishes to swap.

**Usage:** &nbsp; `cargo run -- transfer [OPTIONS] -w <wallet> -a <relay-address> [TARGET-ADDRESS] [AMOUNT]`

#### Example:
```bash
cargo run -- transfer -w alice -a http://127.0.0.1:8000 90F79bf6EB2c4f870365E785982E1f101E93b906 1.0
```

### Delayed withdrawals

Alice can ask Bob to withdraw after a certain delay using `--withdraw-delay` (`-d`) option.
This will make time/amount correlation attacks harder, since Alice's and Bob's withdraw transactions will be spread over multiple arbitrarily distant blocks.

> **Note**: to enforce delay, Alice will time-lock an intermediary value needed for Bob to complete his withdrawal. See section 4.1 of [the paper](https://github.com/timoth-y/spy-pets/blob/main/paper/SpyPETs.pdf) for more details.

#### Example:
```bash
cargo run -- transfer -w alice -a http://127.0.0.1:8000 -d 45s 90F79bf6EB2c4f870365E785982E1f101E93b906 1.0
```

### Swap ETH/ERC20 on Uniswap

**Usage:** &nbsp; `cargo run -- uniswap [OPTIONS] -w <wallet> -a <relay-address> [TARGET-ADDRESS] [AMOUNT] [ERC20]`

#### Example:
```bash
cargo run -- uniswap -w alice -a http://127.0.0.1:8000 90F79bf6EB2c4f870365E785982E1f101E93b906 1.0 USDC
```

### Purchase NFT from ChainSafe Marketplace

Head on to [ChainSafe Marketplace](https://marketplace.chainsafe.io/), choose NFT and view its technical data, use `nftContract` and `tokenId` in the command below.

**Usage:** &nbsp; `cargo run -- buy-nft [OPTIONS] -w <wallet> -a <relay-address> -c <nft-contract> -i <token-id> [TARGET-ADDRESS] [PRICE]`

#### Example:
```bash
cargo run -- buy-nft -w alice -a http://127.0.0.1:8000 --nft-contract 0x2c1867bc3026178a47a677513746dcc6822a137a --token-id 01559ae4021a392a727d4f5619b1689c29b1a951a4e5057f24064001 90F79bf6EB2c4f870365E785982E1f101E93b906 0.2
```

## Future work
- Currently timed commitments aren't verifiable:
  - Integrate [`zk-timelock`](https://github.com/timoth-y/zk-timelock) for [`tlock`](https://github.com/timoth-y/tlock-rs) verifiability
  - Implement VTC verification for HTLP approach
