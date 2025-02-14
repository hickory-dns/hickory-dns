#!/usr/bin/env python3

# This server loads records from a signed zone file and responds to A queries
# with an NXDOMAIN response, including an arbitrary NSEC3 record, and its
# RRSIG.

import binascii
import base64
import itertools
from typing import Self

import dnslib
from dnslib import (
    DNSError, DNSLabel, DNSQuestion, DNSRecord, QTYPE, RCODE, RD, RR,
)
from dnslib.buffer import Buffer
from dnslib.ranges import B, H
from dnslib.server import BaseResolver, DNSHandler, DNSServer

ZONE_FILE_PATH = "/etc/zones/main.zone"


class NSEC3(RD):
    hash_alg = B('hash_alg')
    flags = B('flags')
    iterations = H('iterations')
    salt: bytes
    types: set[int]

    @classmethod
    def parse(cls, buffer: Buffer, length: int) -> Self:
        try:
            start_offset = buffer.offset

            (hash_alg, flags, iterations, salt_length) = buffer.unpack("!BBHB")
            salt = buffer.get(salt_length)
            (hash_length,) = buffer.unpack("!B")
            next_hashed_owner_name = buffer.get(hash_length)

            types: set[int] = set()
            last_block_number = -1
            while buffer.offset < start_offset + length:
                (block_number, bitmap_length) = buffer.unpack("!BB")
                if block_number <= last_block_number:
                    raise DNSError(
                        "NSEC3 bitmap block numbers are not in ascending order"
                    )
                else:
                    last_block_number = block_number
                if bitmap_length > 32:
                    raise DNSError("Invalid NSEC3 bitmap length \
                                   [offset={buffer.offset}]: {bitmap_length}")
                bitmap = buffer.get(bitmap_length)
                for byte_index, bitmap_byte in enumerate(bitmap):
                    for bit_index in range(8):
                        if bitmap_byte & (0x80 >> bit_index):
                            types.add(
                                (block_number << 8) |
                                (byte_index * 8) |
                                bit_index
                            )

            return cls(
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                types,
            )
        except BufferError as e:
            raise DNSError(
                f"Error unpacking NSEC3 [offset={buffer.offset}]: {e}"
            )

    @classmethod
    def fromZone(cls, rd: list[str], origin: DNSLabel = None) -> Self:
        hash_alg = int(rd[0])
        flags = int(rd[1])
        iterations = int(rd[2])
        if rd[3] == "-":
            salt = b""
        else:
            salt = binascii.unhexlify(rd[3])
        next_hashed_owner_name = base64.b32hexdecode(rd[4], casefold=True)

        types: set[int] = set()
        for mnemonic in rd[5:]:
            types.add(QTYPE.__getattr__(mnemonic))

        return cls(
            hash_alg,
            flags,
            iterations,
            salt,
            next_hashed_owner_name,
            types,
        )

    def __init__(self,
                 hash_alg: int,
                 flags: int,
                 iterations: int,
                 salt: bytes,
                 next_hashed_owner_name: bytes,
                 types: set[int]):
        self.hash_alg = hash_alg
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.next_hashed_owner_name = next_hashed_owner_name
        self.types = types

    def pack(self, buffer: Buffer) -> None:
        buffer.pack(
            "!BBHB",
            self.hash_alg,
            self.flags,
            self.iterations,
            len(self.salt),
        )
        buffer.append(self.salt)
        buffer.pack("!B", len(self.next_hashed_owner_name))
        buffer.append(self.next_hashed_owner_name)

        blocks = sorted(
            (block_number, list(grouper))
            for block_number, grouper
            in itertools.groupby(self.types, lambda x: x >> 8)
        )
        for block_number, block_types in blocks:
            bitmap_length = (max(block_types) & 0xFF) // 8 + 1
            bitmap = bytearray(bitmap_length)
            for type_number in block_types:
                byte_index = (type_number & 0xFF) // 8
                bit_index = (type_number & 0xFF) % 8
                bitmap[byte_index] |= 0x80 >> bit_index
            buffer.pack("!BB", block_number, bitmap_length)
            buffer.append(bitmap)

    def __repr__(self) -> str:
        types = " ".join(QTYPE[t] for t in self.types)
        if len(self.salt) == 0:
            salt = "-"
        else:
            salt = binascii.hexlify(self.salt)
        return f"{self.hash_alg} {self.flags} {self.iterations} {salt} \
            {base64.b32hexencode(self.next_hashed_owner_name)} {types}"


class NSEC3PARAM(RD):
    @classmethod
    def parse(cls, buffer: Buffer, length: int) -> Self:
        try:
            (hash_alg, flags, iterations, salt_length) = buffer.unpack("!BBHB")
            salt = buffer.get(salt_length)
            return cls(hash_alg, flags, iterations, salt)
        except BufferError as e:
            raise DNSError(
                f"Error unpacking NSEC3PARAM [offset={buffer.offset}]: {e}"
            )

    @classmethod
    def fromZone(cls, rd: list[str], origin: DNSLabel = None) -> Self:
        hash_alg = int(rd[0])
        flags = int(rd[1])
        iterations = int(rd[2])
        if rd[3] == "-":
            salt = b""
        else:
            salt = binascii.unhexlify(rd[3])
        return cls(hash_alg, flags, iterations, salt)

    def __init__(self,
                 hash_alg: int,
                 flags: int,
                 iterations: int,
                 salt: bytes):
        self.hash_alg = hash_alg
        self.flags = flags
        self.iterations = iterations
        self.salt = salt

    def pack(self, buffer: Buffer) -> None:
        buffer.pack(
            "!BBHB",
            self.hash_alg,
            self.flags,
            self.iterations,
            len(self.salt),
        )
        buffer.append(self.salt)

    def __repr__(self) -> str:
        if len(self.salt) == 0:
            salt = "-"
        else:
            salt = binascii.hexlify(self.salt)
        return f"{self.hash_alg} {self.flags} {self.iterations} {salt}"


def monkeypatch():
    dnslib.dns.RDMAP["NSEC3"] = NSEC3
    dnslib.dns.RDMAP["NSEC3PARAM"] = NSEC3PARAM


class Resolver(BaseResolver):
    def __init__(self):
        zone_file = open(ZONE_FILE_PATH).read()
        records = RR.fromZone(zone_file)

        # Pick one NSEC3 record and its RRSIG record, then use it in all
        # NXDOMAIN responses. It should be the wrong record for most queries.
        self.nsec3 = next(r for r in records[::-1] if r.rtype == QTYPE.NSEC3)
        self.nsec3_rrsig = next(
            r for r in records
            if r.rtype == QTYPE.RRSIG and r.rname == self.nsec3.rname
        )

        # Look up other records from the zone file to be used in responses
        self.soa = next(r for r in records if r.rtype == QTYPE.SOA)
        self.soa_rrsig = next(
            r for r in records
            if r.rtype == QTYPE.RRSIG and r.rdata.covered == QTYPE.SOA
        )
        self.dnskeys = [r for r in records if r.rtype == QTYPE.DNSKEY]
        self.dnskey_rrsigs = [
            r for r in records
            if r.rtype == QTYPE.RRSIG and r.rdata.covered == QTYPE.DNSKEY
        ]

    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        if len(request.questions) != 1:
            print(f"Unsupported number of questions: {request.questions}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

        query: DNSQuestion = request.questions[0]

        if query.qtype == QTYPE.A:
            return self.handle_a(request)

        if query.qtype == QTYPE.DNSKEY:
            return self.handle_dnskey(request)

        print("No handler method for request")
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def handle_a(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_auth(self.soa)
        reply.add_auth(self.soa_rrsig)
        reply.add_auth(self.nsec3)
        reply.add_auth(self.nsec3_rrsig)
        return reply

    def handle_dnskey(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        for rr in self.dnskeys:
            reply.add_answer(rr)
        for rr in self.dnskey_rrsigs:
            reply.add_answer(rr)
        return reply


if __name__ == "__main__":
    monkeypatch()

    resolver = Resolver()
    udp_server = DNSServer(resolver, address="0.0.0.0", port=53)
    tcp_server = DNSServer(resolver, address="0.0.0.0", port=53, tcp=True)
    udp_server.start_thread()
    tcp_server.start()
