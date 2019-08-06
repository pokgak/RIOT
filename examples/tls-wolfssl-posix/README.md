# tls-wolfssl example

This example shows how to use TLS with POSIX sockets and wolfSSL

## SOCK vs. Socket

This example is configured to use POSIX sockets (over LWIP).
It's possible to use socks interface, which gives a smaller footprint and
resource limited version of wolfSSL on RIOT-OS.

For more details, see `examples/dtls-wolfssl`


## Fast configuration (Between RIOT instances)

### Prepare the bridge interface linking two tuntap

```bash
    ./../../dist/tools/tapsetup/tapsetup --create 2
```

## Testing

### Run the server
```bash
$ make all; PORT=tap1 make term
> ip
```
*copy the server address*

```bash
> tlss
```
### Run the client
```bash
$ PORT=tap0 make term
> tlsc <IPv6's server address[%netif]>
```

### Certificate/key

This example uses fixed certificates and keys from `wolfssl/wolfssl/certs_test.h`.

### Testing against host endpoints

Riot-to-host can be tested against the TLS examples provided in the [wolfSSL-examples](https://github.com/wolfSSL/wolfssl-examples/tree/master) repository.

## Boards

This version of wolfSSL is 32-bit only, so non-32bit targets are blacklisted.

Boards that due to insufficient memory are not able to support LWIP, which is required for this example, are included
in the `BOARD_INSUFFICIENT_MEMORY`.
