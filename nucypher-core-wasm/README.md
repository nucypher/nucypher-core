# nucypher-core-wasm

## Development

```bash
cargo test
make clean 
make 
cd examples/node && rm -rf node_modules/nucypher-core node_modules/umbral-pre && yarn install --check-files && yarn test
```