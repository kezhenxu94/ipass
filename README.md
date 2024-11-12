# ipass

A CLI to interact with Apple macOS Passwords (iCloud KeyChain).

## Demo

[![ipass demo](https://img.youtube.com/vi/de3bTuD5qxE/0.jpg)](https://www.youtube.com/watch?v=de3bTuD5qxE)

Some sample usages of the `ipass` CLI tool you might be interested in:

```shell
# login to docker hub
ipass pw get docker.com kezhenxu94 | jq '.entries[0].password' -r | docker login -u kezhenxu94 --password-stdin
```

## About The Project

This project basically rewrites the [`apw`](https://github.com/bendews/apw) project in Rust,
because the `apw` project doesn't run on my M3 macOS 15.0.1 for no reason.

It utilises a built in helper tool in macOS 14 and above to facilitate this
functionality.

## Installation

### Binary

Go to [release page](https://github.com/kezhenxu94/ipass/releases) to download the binary
according to you platform, and run `xattr -c ./ipass-aarch64-apple-darwin.tar.gz` (to avoid "unknown developer" warning).
Then extract the binary from the tarball:

```shell
tar -zxvf ./ipass-aarch64-apple-darwin.tar.gz
```

### Cargo

If you have `cargo` installed, you can easily install the binary using the
command:

```shell
cargo install --git https://github.com/kezhenxu94/ipass
```

## Usage

Ensure the daemon is running in the background, via `ipass start`.

To authenticate the daemon:

_This is required every time the daemon starts i.e on boot_

```shell
ipass auth
```

Query for available passwords for a specific domain:

```shell
ipass pw list google.com
```

View more commands & help:

```shell
ipass help                                             
```

## Building

This project uses Rust for development and compilation.
Make sure you have Rust installed on your system before proceeding.

### Running the Project

To run the project whilst developing:

```shell
cargo run -- start
```

### Building a release version

To build a statically compiled binary:

```shell
cargo build
```

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are **greatly
appreciated**.

If you have a suggestion that would make this better, please fork the repo and
create a pull request. You can also simply open an issue with the tag
"enhancement". Don't forget to give the project a star! Thanks again!

* Fork the Project
* Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
* Commit your Changes (`git commit -m 'feat: add some AmazingFeature'`)
* Push to the Branch (`git push origin feature/AmazingFeature`)
* Open a Pull Request

## License

Distributed under the GPL V3.0 License. See `LICENSE` for more information.

## Contact

[kezhenxu94](https://x.com/kezhenxu94)

Project Link: <https://github.com/kezhenxu94/ipass>

## Acknowledgments

* [Ben Dews - apw](https://github.com/bendews/apw).
