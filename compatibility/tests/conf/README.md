# Compatibility Tests Configuration

## Configuring bind

### Generating keys

Generate a new key

```console
$ dnssec-keygen -r /dev/urandom -C -a RSASHA256 -b 2048 -n HOST -T KEY update.example.com.
Generating key pair......+++ ..................................................+++
Kupdate.example.com.+008+12919
```

Copy data from Kupdate.example.com.+008+12919.key into zone file `bind-example.com`