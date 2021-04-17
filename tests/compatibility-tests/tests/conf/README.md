# Compatibility Tests Configuration

## Configuring bind

### Generating sig0 keys

Generate a new key

```console
$ dnssec-keygen -r /dev/urandom -C -a RSASHA256 -b 2048 -n HOST -T KEY update.example.com.
Generating key pair......+++ ..................................................+++
Kupdate.example.com.+008+12919
```

Copy data from Kupdate.example.com.+008+12919.key into zone file `bind-example.com`

### Generating tsig keys

Generate a new key

```console
$ tsig-keygen -a HMAC-SHA512 tsig-key > tsig.conf
$ cat tsig.conf | awk -e '$1 ~ /secret/ {gsub(/[";]/, ""); print $2}' | base64 -d > tsig.raw
```
