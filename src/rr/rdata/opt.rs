/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 // RFC 6891                   EDNS(0) Extensions                 April 2013
 //
 // 6.1.  OPT Record Definition
 //
 // 6.1.1.  Basic Elements
 //
 //    An OPT pseudo-RR (sometimes called a meta-RR) MAY be added to the
 //    additional data section of a request.
 //
 //    The OPT RR has RR type 41.
 //
 //    If an OPT record is present in a received request, compliant
 //    responders MUST include an OPT record in their respective responses.
 //
 //    An OPT record does not carry any DNS data.  It is used only to
 //    contain control information pertaining to the question-and-answer
 //    sequence of a specific transaction.  OPT RRs MUST NOT be cached,
 //    forwarded, or stored in or loaded from master files.
 //
 //    The OPT RR MAY be placed anywhere within the additional data section.
 //    When an OPT RR is included within any DNS message, it MUST be the
 //    only OPT RR in that message.  If a query message with more than one
 //    OPT RR is received, a FORMERR (RCODE=1) MUST be returned.  The
 //    placement flexibility for the OPT RR does not override the need for
 //    the TSIG or SIG(0) RRs to be the last in the additional section
 //    whenever they are present.
 //
 // 6.1.2.  Wire Format
 //
 //    An OPT RR has a fixed part and a variable set of options expressed as
 //    {attribute, value} pairs.  The fixed part holds some DNS metadata,
 //    and also a small collection of basic extension elements that we
 //    expect to be so popular that it would be a waste of wire space to
 //    encode them as {attribute, value} pairs.
 //
 //    The fixed part of an OPT RR is structured as follows:
 //
 //        +------------+--------------+------------------------------+
 //        | Field Name | Field Type   | Description                  |
 //        +------------+--------------+------------------------------+
 //        | NAME       | domain name  | MUST be 0 (root domain)      |
 //        | TYPE       | u_int16_t    | OPT (41)                     |
 //        | CLASS      | u_int16_t    | requestor's UDP payload size |
 //        | TTL        | u_int32_t    | extended RCODE and flags     |
 //        | RDLEN      | u_int16_t    | length of all RDATA          |
 //        | RDATA      | octet stream | {attribute,value} pairs      |
 //        +------------+--------------+------------------------------+
 //
 //                                OPT RR Format
 //
 //    The variable part of an OPT RR may contain zero or more options in
 //    the RDATA.  Each option MUST be treated as a bit field.  Each option
 //    is encoded as:
 //
 //                   +0 (MSB)                            +1 (LSB)
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //     0: |                          OPTION-CODE                          |
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //     2: |                         OPTION-LENGTH                         |
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //     4: |                                                               |
 //        /                          OPTION-DATA                          /
 //        /                                                               /
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //
 //    OPTION-CODE
 //       Assigned by the Expert Review process as defined by the DNSEXT
 //       working group and the IESG.
 //
 //    OPTION-LENGTH
 //       Size (in octets) of OPTION-DATA.
 //
 //    OPTION-DATA
 //       Varies per OPTION-CODE.  MUST be treated as a bit field.
 //
 //    The order of appearance of option tuples is not defined.  If one
 //    option modifies the behaviour of another or multiple options are
 //    related to one another in some way, they have the same effect
 //    regardless of ordering in the RDATA wire encoding.
 //
 //    Any OPTION-CODE values not understood by a responder or requestor
 //    MUST be ignored.  Specifications of such options might wish to
 //    include some kind of signaled acknowledgement.  For example, an
 //    option specification might say that if a responder sees and supports
 //    option XYZ, it MUST include option XYZ in its response.
 //
 // 6.1.3.  OPT Record TTL Field Use
 //
 //    The extended RCODE and flags, which OPT stores in the RR Time to Live
 //    (TTL) field, are structured as follows:
 //
 //                   +0 (MSB)                            +1 (LSB)
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //     0: |         EXTENDED-RCODE        |            VERSION            |
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //     2: | DO|                           Z                               |
 //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 //
 //    EXTENDED-RCODE
 //       Forms the upper 8 bits of extended 12-bit RCODE (together with the
 //       4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
 //       indicates that an unextended RCODE is in use (values 0 through
 //       15).
 //
 //    VERSION
 //       Indicates the implementation level of the setter.  Full
 //       conformance with this specification is indicated by version '0'.
 //       Requestors are encouraged to set this to the lowest implemented
 //       level capable of expressing a transaction, to minimise the
 //       responder and network load of discovering the greatest common
 //       implementation level between requestor and responder.  A
 //       requestor's version numbering strategy MAY ideally be a run-time
 //       configuration option.
 //       If a responder does not implement the VERSION level of the
 //       request, then it MUST respond with RCODE=BADVERS.  All responses
 //       MUST be limited in format to the VERSION level of the request, but
 //       the VERSION of each response SHOULD be the highest implementation
 //       level of the responder.  In this way, a requestor will learn the
 //       implementation level of a responder as a side effect of every
 //       response, including error responses and including RCODE=BADVERS.
 //
 // 6.1.4.  Flags
 //
 //    DO
 //       DNSSEC OK bit as defined by [RFC3225].
 //
 //    Z
 //       Set to zero by senders and ignored by receivers, unless modified
 //       in a subsequent specification.
