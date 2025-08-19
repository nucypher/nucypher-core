# New version publishing instructions

Ideally it would be done by a CI action.
For now, it has to be done manually.


## Maintaining changelog and bumping the version

For every version, list the "Changed" items first (meaning backward incompatible changes), then "Added" (new features), then "Fixed" (bug fixes, or other improvements that do not change the API/ABI).
Rust has some specifics in what is considered a breaking change; refer to https://doc.rust-lang.org/cargo/reference/semver.html for the full list.
The version number part (major/minor/patch) that is bumped should correspond to whether there is something in "Changed" or "Added" categories.

## Ensure Correct Rust Version

Make sure you are using the correct Rust version specified in the `.github/workflows/nucypher-core.yml` file (MSRV). You can use [rustup](https://rustup.rs/) to manage and switch between Rust versions. To install the required version, run:
```bash
rustup install <version>
rustup override set <version>
```
Replace `<version>` with the relevant version.


## Build and Test

In the `nucypher-core` directory, run the following commands to ensure everything is working correctly:
- `cargo fmt --all` (to check formatting).
- `cargo build`
- `cargo test`


## Release commit

- Update `CHANGELOG.md` (replace `Unreleased` with the version and the release date).
- Use Python [Bumpversion](https://github.com/c4urself/bump2version/) to automatically update relevant version strings throughout the repo.
  - `bump2version <major/minor/patch> --new-version <major>.<minor>.<patch>`
- git push the commit and tag produced by `bump2version` to the `main` branch.
  - `git push upstream main && git push upstream <VERSION_TAG_NAME>`


## Rust crate

In `nucypher-core` directory, run:
- `cargo login <your_id>` (using your crates.io ID).
- `cargo publish -p nucypher-core --dry-run` (to check for errors).

If everything is fine, run the following command to publish the crate:
- `cargo publish -p nucypher-core`.

See https://doc.rust-lang.org/cargo/reference/publishing.html for more info on publishing.


## Python package

Gitub Actions are configured to take care of this automatically. If needed, it can be [manually triggered here](https://github.com/nucypher/nucypher-core/actions/workflows/wheels.yml) (manual mode has not been tested)

## NPM package

In `nucypher-core-wasm-bundler` directory:



```bash
npm install
npm run build
npm publish --access=public --dry-run
```

If everything is fine, run the following command to publish the package:
```bash
npm publish --access=public
```

See https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/packaging-and-publishing.html for more info on publishing.
