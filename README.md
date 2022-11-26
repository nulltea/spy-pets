# spy-pets
This is a prototype of universal covert privacy-enhancing transactions (PETs) inspired by Gregory Maxwell's [CoinSwap](https://gist.github.com/chris-belcher/9144bd57a91c194e332fb5ca371d0964) design and Universal Atomic Swaps [\[TMM'21\]](https://eprint.iacr.org/2021/1612).

## Usage

### Setup wallet
First let's setup source wallet. You can generate new, recover from hex or from BIP39 mnemonic. Run following command:
```bash
cargo run -- setup
```

### Run market maker daemon
Bob will be market maker. He runs daemon with configured funded wallet and specifies target address where ETH will be transferred after swap.
```bash
cargo run -- provide -w bob -p -t 3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
```

### Covert transfer
Alice will be market taker. She knows the URL of the Bob's daemon and runs client with specified target address where ETH will be transferred after swap and the amount of ETH she wishes to swap.
```bash
cargo run -- transfer -w alice -m http://127.0.0.1:8000 -t 90F79bf6EB2c4f870365E785982E1f101E93b906 -a 1.0
```

## Known issues
- Time-locked locked commitments aren't verifiable
- Poor network fee estimation: +0.1ETH is sent to swap accounts.
