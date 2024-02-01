# `dnssec-tests`

Test infrastructure for DNSSEC conformance tests.

## Design goals

- Test MUST not depend on external services like `1.1.1.1` or `8.8.8.8`
  - rationale: it must be possible to run tests locally, without internet access
- All nodes in the network must not be the subject under test. 
  - rationale: test inter-operability with other software like `unbound` and `nsd`
- All test input must be local files or constants
  - rationale: tests are self-contained
- 

## Minimally working DNSSEC-enabled network

- `.` domain
  - name server: `nsd` (`my.root-server.com`)
- TLD domain (`com.`)
  - name server: `nsd` (`ns.com`)
- target domain (`example.com.`)
  - name server: `nsd` (`ns.example.com`)
- recursive resolver: `unbound`
  - configured to use `my.root-server.com` as root server
  - configured with a trust anchor: the public key of `my.root-server.com`

each name server has
- a zone signing key pair
- a key signing key pair
- signed zone files

### exploration

#### `nsd` for root name server

run: `nsd -d`

- `/etc/nsd/nsd.conf`

``` text
remote-control:
  control-enable: no

zone:
  name: .
  zonefile: /etc/nsd/zones/root.zone
```

- `/etc/nsd/zones/root.zone`

``` text
$ORIGIN .
$TTL 1800
@       IN      SOA     primary.root-server.com.    admin.root-server.com. (
                        2014080301
                        3600
                        900
                        1209600
                        1800
                        )

```

#### `unbound` 

run `unbound -d`

- `/etc/unbound/unbound.conf`

ideally instead of `0.0.0.0`, it should only cover the `docker0` network interface. or disable docker containers' access to the internet

``` text
server:
    verbosity: 4
    use-syslog: no
    interface: 0.0.0.0
    access-control: 172.17.0.0/16 allow
    root-hints: /etc/unbound/root.hints

remote-control:
    control-enable: no
```

- `/etc/unbound/root.hints`. NOTE IP address of docker container

``` text
.                        3600000      NS    primary.root-server.com.
primary.root-server.com. 3600000      A     172.17.0.2
```

#### `client`

Container is `docker/client.Dockerfile`, build with: `docker build -t dnssec-tests-client -f docker/client.Dockerfile docker`, with `tshark`.

Run the client container with extra capabilities

```shell
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN dnssec-tests-client /bin/bash
```

Then run `tshark` inside the container:

```shell
tshark -f 'host 172.17.0.3' -O dns
```

to filter DNS messages for host `172.17.0.3` (`unbound`).
