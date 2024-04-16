# Randomness Beacon Watcher

A simple client to watch ETF-PFG finality proofs and perform timelock encryption.

## Setup

First run a local ETF node. Once it is running and producing ETF blocks, generate metadata by running `./generate_metadata.sh` from the root directory. Finally, run

``` shell
cargo run
```

This will encrypt a message "this is a test" for the next upcoming block. It listens to justifications, extracts signatures, and then uses those to try to decrypt the message.

## Testing

TODO

## Generating metadata for the chain

``` shell
# clone and build the node
git clone git@github.com:ideal-lab5/etf.git
cd etf
cargo +stable build
# run a local node
./target/debug/node --tmp --dev --alice --unsafe-rpc-external --rpc-cors all
# use subxt to prepare metadata
cd /path/to/randomness-beacon-watcher/
mkdir artifacts
cargo install subxt-cli
# Download and save all of the metadata:
subxt metadata > ./artifacts/metadata.scale
```
