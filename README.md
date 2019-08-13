A cli for interacting with darklang - currently just for managing static assets.

If you're building osx locally, you'll need to cd to osxcross, run
`build-osxcross-tarfile`, cd back to dark-cli, and run `tar --strip-components=1
-xf osxcross/target/osxcross-with-clang.tar.gz` to put the osx toolchain in bin.

On Ubuntu, you'll want:
`sudo apt install -y clang gcc-mingw-w64-x86-64 llvm-4.0-dev musl-tools`;
add deps here for other distros as needed.
