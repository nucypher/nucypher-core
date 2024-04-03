# nucypher-core-wasm

## Development

```bash
cargo test
make clean 
make 
cd examples/node && rm -rf node_modules/nucypher-core node_modules/umbral-pre && yarn install --check-files && yarn test
```

## Bundling and releasing

Bundling methods in the `Makefile` have been replaced by [`nucypher-core-wasm-bundler`](../nucypher-core-wasm-bundler/README.md). Use this new build process for updating the NPM package, `@nucypher/nucypher-core`. 
