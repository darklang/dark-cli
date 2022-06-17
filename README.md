A cli for interacting with darklang - currently just for managing static assets.

# Cross-platform Build + Deploy Process using CI
We currently do not automate deploys when merging to master. Here's how to deploy so that devs can download the dark-cli linked from https://ops-documentation.builtwithdark.com/user-manual/static-assets#installation:

0. Make sure you have gcloud utilities installed locally (used by the deploy script):
    ```
    curl https://sdk.cloud.google.com | bash
    ```
    You also need permissions to upload to the dark-cli bucket in google cloud storage, and gcloud creds on your laptop. (If you use `gcp-authorize-kubectl` in the dark repo, you already have these creds; if not, run `gcloud init` to launch a browser and log in. This is a one-time setup step, does not need to be done each time.)
1. Make sure to bump the version number in `Cargo.toml`
2. Merge the branch into master and wait for CI to finish building.
3. Open the CI build job and the build-osx job (linked via the green circle next to the merge commit in github)
4. Switch to the Artifacts tab in CI and download the 3 binaries (2 from build and 1 from build-osx)
5. If the downloaded files end in "dms", remove that extension (probably macOS Safari-only problem)
6. Move the 3 binaries to the root of the dark-cli folder.
7. From inside that directory, run `./script/deploy`
8. (macOS only) A popup will tell you that the app can't be verified. Press `Cancel` and open System Preferences -> Security & Privacy -> General. Click "Allow Anyway" next to `"dark-cli-apple" was blocked from use because it is not from an identified developer`. Rerun `./script/deploy`. In the resulting verification popup there is now an Open button. Click it.

See `scripts/deploy` for more technical information.

# Building macOS locally (on non-macOS)
If you're building osx locally, you'll need to cd to osxcross, run
`build-osxcross-tarfile`, cd back to dark-cli, and run `tar --strip-components=1
-xf osxcross/target/osxcross-with-clang.tar.gz` to put the osx toolchain in bin.

On Ubuntu, you'll want:
`sudo apt install -y clang gcc-mingw-w64-x86-64 llvm-4.0-dev musl-tools`;
add deps here for other distros as needed.

On OSX with an ARM chip (M1/M2):
- brew install rustup
