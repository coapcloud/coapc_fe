# coapc_fe

----

`coapc_fe` is the frontend server frontend server for CoAP.cloud and handles parsing requests and responses and routes logic to microservices. In the future it may support advanced use cases, like HTTP and other forms of proxying.

----

## Prerequisites

`coapc_fe` is based on [libcoap](https://github.com/obgm/libcoap) and has its own set of dependencies. Most POSIX should work and Windows _may_ work. macOS users - Brew is your friend. To build `libcoap`:

* `git clone https://github.com/coapcloud/coapc_fe` (this repo)

* `cd coapc_fe`

* `git submodule update --init --recursive` to fetch `libcoap`'s dependencies

* `./autogen.sh`

* `./configure --disable-documentation --disable-tests --enable-shared --enable-dtls`

* `make`

* `make install`

## Building

Currently this project assumes you are developing with Visual Studio Code and it uses VSC's task runner instead of a formal build system like autotools or CMake. This will likely improve in the future.

Included is a default Build task using GCC. Pressing `⇧⌘B` or `CTRL+SHIFT+B` with start the build task.

## Verifying

Start the server by running `./server`. In a new window, enter `coap-client coap://[::1]`. `coap-client` should have been installed when running `make install`.

## License

[Apache License 2.0](LICENSE)