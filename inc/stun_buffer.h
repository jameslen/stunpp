// https://datatracker.ietf.org/doc/html/rfc5389
#pragma once

#include <array>
#include <bit>
#include <cassert>
#include <compare>
#include <expected>
#include <memory_resource>
#include <span>
#include <string>
#include <vector>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "network_order_storage.h"
#include "stun_error_category.h"

namespace stunpp
{
    using net_uint16_t = util::network_ordered<std::uint16_t>;
    using host_uint16_t = util::host_ordered<std::uint16_t>;

    using net_uint32_t = util::network_ordered<std::uint32_t>;
    using host_uint32_t = util::host_ordered<std::uint32_t>;

    constexpr host_uint32_t c_stun_magic_cookie = 0x2112A442;

    namespace detail
    {
        void xor_map_ipv6_address(
            std::span<std::uint32_t, 4> dst,
            std::span<const std::uint32_t, 4> src,
            std::span<const uint32_t, 3> id
        ) noexcept;

        template<typename T>
        std::byte* get_bytes_after(T* ptr)
        {
            return retinterpret_cast<std::byte*>(ptr) + sizeof(T);
        }

        template<typename T>
        const std::byte* get_bytes_after(const T* ptr)
        {
            return retinterpret_cast<const std::byte*>(ptr) + sizeof(T);
        }

        template<typename data_t, typename T>
        data_t* get_bytes_after_as(T* ptr)
        {
            return reinterpret_cast<data_t*>(get_bytes_after(ptr));
        }

        template<typename data_t, typename T>
        const data_t* get_bytes_after_as(const T* ptr)
        {
            return reinterpret_cast<const data_t*>(get_bytes_after(ptr));
        }
    }

    // THe method's type and method are not stored pre-converted to netowrk 
    // order because they have to be combined/parsed apart.
    enum class stun_method_type : std::uint16_t
    {
        request = 0x0000,
        success_response = 0x0100,
        error_response = 0x0110,
        indication = 0x0010,
    };

    enum class stun_method : std::uint16_t
    {
        // STUN RFC 5389
        reserved0 = 0x0000,
        binding = 0x0001,
        reserved1 = 0x0002,

        // TURN RFC 5766
        allocate = 0x0003,
        refresh = 0x0004,
        send = 0x0006,
        data = 0x0007,
        create_permissions = 0x0008,
        channel_bind = 0x0009,

        invalid = 0xFFFF
    };

    // These are pre-converted to network order to make storing/reading
    // easier
    enum class stun_attribute_type : std::uint16_t
    {
        // STUN RFC 5389 Required Range
        reserved0           = util::hton<std::uint16_t>(0x0000),
        mapped_address      = util::hton<std::uint16_t>(0x0001),
        reserved1           = util::hton<std::uint16_t>(0x0002),
        reserved2           = util::hton<std::uint16_t>(0x0003),
        reserved3           = util::hton<std::uint16_t>(0x0004),
        reserved4           = util::hton<std::uint16_t>(0x0005),
        username            = util::hton<std::uint16_t>(0x0006),
        reserved5           = util::hton<std::uint16_t>(0x0007),
        message_integrity   = util::hton<std::uint16_t>(0x0008),
        error_code          = util::hton<std::uint16_t>(0x0009),
        unknown_attributes  = util::hton<std::uint16_t>(0x000A),
        reserved6           = util::hton<std::uint16_t>(0x000B),
        realm               = util::hton<std::uint16_t>(0x0014),
        nonce               = util::hton<std::uint16_t>(0x0015),
        xor_mapped_address  = util::hton<std::uint16_t>(0x0020),

        // TURN RFC 5766
        channel_number      = util::hton<std::uint16_t>(0x000C),
        lifetime            = util::hton<std::uint16_t>(0x000D),
        reserved7           = util::hton<std::uint16_t>(0x0010),
        xor_peer_address    = util::hton<std::uint16_t>(0x0012),
        data                = util::hton<std::uint16_t>(0x0013),
        xor_relayed_address = util::hton<std::uint16_t>(0x0016),
        even_port           = util::hton<std::uint16_t>(0x0018),
        requested_transport = util::hton<std::uint16_t>(0x0019),
        dont_fragment       = util::hton<std::uint16_t>(0x001A),
        reserved8           = util::hton<std::uint16_t>(0x0021),
        reservation_token   = util::hton<std::uint16_t>(0x0022),

        // STUN RFC 5389 Optional Range
        software            = util::hton<std::uint16_t>(0x0022),
        alternate_server    = util::hton<std::uint16_t>(0x8023),
        fingerprint         = util::hton<std::uint16_t>(0x8028),

        invalid             = 0xFFFF
    };

    enum class address_family : std::uint8_t
    {
        ipv4 = 0x01,
        ipv6 = 0x02
    };

    enum class stun_error_code : std::uint32_t
    {
        try_alternate = 300,                  // The client should contact an alternate server for
                                              // this request.  This error response MUST only be sent if the
                                              // request included a USERNAME attribute and a valid MESSAGE-
                                              // INTEGRITY attribute; otherwise, it MUST NOT be sent and error
                                              // code 400 (Bad Request) is suggested.  This error response MUST
                                              // be protected with the MESSAGE-INTEGRITY attribute, and receivers
                                              // MUST validate the MESSAGE-INTEGRITY of this response before
                                              // redirecting themselves to an alternate server.
                                              
        bad_request = 400,                    // The request was malformed.  The client SHOULD NOT
                                              // retry the request without modification from the previous
                                              // attempt.  The server may not be able to generate a valid
                                              // MESSAGE-INTEGRITY for this error, so the client MUST NOT expect
                                              // a valid MESSAGE-INTEGRITY attribute on this response.
                                              
        unauthorized = 401,                   // The request did not contain the correct
                                              // credentials to proceed.  The client should retry the request
                                              // with proper credentials.
                                              
        forbidden = 403,                      // The request was valid but cannot be performed due
                                              // to administrative or similar restrictions.
                                              
        unknown_attribute = 420,              // The server received a STUN packet containing
                                              // a comprehension-required attribute that it did not understand.
                                              // The server MUST put this unknown attribute in the UNKNOWN-
                                              // ATTRIBUTE attribute of its error response.
                                              
        allocation_mistmatch = 437,           // A request was received by the server that
                                              // requires an allocation to be in place, but no allocation exists,
                                              // or a request was received that requires no allocation, but an
                                              // allocation exists.
                                              
        stale_nonce = 438,                    // The NONCE used by the client was no longer valid.
                                              // The client should retry, using the NONCE provided in the
                                              // response.
                                              
        wrong_credentials = 441,              // The credentials in the(non - Allocate)
                                              // request do not match those used to create the allocation.

        unsupported_transport_protocol = 442, // The Allocate request asked the
                                              // server to use a transport protocol between the serverand the peer
                                              // that the server does not support.NOTE: This does NOT refer to
                                              // the transport protocol used in the 5 - tuple.

        allocation_quota_reached = 486,       // No more allocations using this
                                              // username can be created at the present time.

        server_error = 500,                   // Server Error: The server has suffered a temporary error.  The
                                              // client should try again.

        insufficient_capacity = 508,          // The server is unable to carry out the
                                              // request due to some capacity limit being reached.In an Allocate
                                              // response, this could be due to the server having no more relayed
                                              // transport addresses available at that time, having none with the
                                              // requested properties, or the one that corresponds to the specified
                                              // reservation token is not available.
    };

    // All STUN messages MUST start with a 20 - byte header followed by zero
    // or more Attributes.The STUN header contains a STUN message type,
    // magic cookie, transaction ID, and message length.
    // 
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0 0|     STUN Message Type     |         Message Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Magic Cookie                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                     Transaction ID(96 bits)                   |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct stun_header
    {
        net_uint16_t message_type;
        net_uint16_t message_length;
        net_uint32_t magic_cookie;
        std::array<std::uint32_t, 3> transaction_id;

        stun_method get_method() const noexcept;
        stun_method_type get_method_type() const noexcept;
    };

    //constexpr auto size = sizeof(stun_header);

    // After the STUN header are zero or more attributes.Each attribute
    // MUST be TLV encoded, with a 16 - bit type, 16 - bit length, and value.
    // Each STUN attribute MUST end on a 32 - bit boundary.As mentioned
    // above, all fields in an attribute are transmitted most significant
    // bit first.
    // 
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         Type                  |            Length             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Value (variable)                ....
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct stun_attribute
    {
        stun_attribute_type type;
        net_uint16_t size;
    };

    struct string_view_attribute : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    struct data_base_attribute : stun_attribute
    {
    };

    template <typename data_t>
    struct data_view_attribute : data_base_attribute
    {
        std::span<const data_t> data() const noexcept
        {
            return { detail::get_bytes_after_as<const data_t>(this), static_cast<host_uint16_t>(size) };
        }
    };

    // The MAPPED - ADDRESS attribute indicates a reflexive transport address
    // of the client.It consists of an 8 - bit address family and a 16 - bit
    // port, followed by a fixed - length value representing the IP address.
    // If the address family is IPv4, the address MUST be 32 bits.If the
    // address family is IPv6, the address MUST be 128 bits.All fields
    // must be in network byte order.
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0 0 0 0 0 0 0 0|    Family     |           Port                |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                 Address (32 bits or 128 bits)                 |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct mapped_address_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::mapped_address;
        std::uint8_t zeros;
        address_family family;
        net_uint16_t port;
    };

    // Specific type for ipv4 addresses
    struct ipv4_mapped_address_attribute : mapped_address_attribute
    {
        std::array<std::byte, 4> address_bytes;

        SOCKADDR_IN address() const noexcept;
    };

    // Specific type for ipv6 addresses
    struct ipv6_mapped_address_attribute : mapped_address_attribute
    {
        std::array<std::byte, 16> address_bytes;

        SOCKADDR_IN6 address() const noexcept;
    };

    // The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
    // attribute, except that the reflexive transport address is obfuscated
    // through the XOR function.
    // 
    // The format of the XOR-MAPPED-ADDRESS is:
    // 
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |x x x x x x x x|    Family     |         X-Port                |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                X-Address (Variable)
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct xor_mapped_address_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_mapped_address;
        std::uint8_t zeros;
        address_family family;

        // X-Port is computed by taking the mapped port in host byte order,
        // XOR'ing it with the most significant 16 bits of the magic cookie, and
        // then the converting the result to network byte order.
        net_uint16_t port_bytes;

        net_uint16_t port() const noexcept;
    };

    // Specific type for ipv4 addresses
    struct ipv4_xor_mapped_address_attribute : xor_mapped_address_attribute
    {
        // Storing as a uint32_t to make xoring with the magic cookie efficient
        std::uint32_t address_bytes;

        SOCKADDR_IN address() const noexcept;
    };

    // Specific type for ipv6 addresses
    struct ipv6_xor_mapped_address_attribute : xor_mapped_address_attribute
    {
        // Storing as a uint32_t to make xoring with the magic cookie and id efficient
        std::array<std::uint32_t, 4> address_bytes;

        SOCKADDR_IN6 address(std::span<std::uint32_t, 3> message_id) const noexcept;
    };

    // The USERNAME attribute is used for message integrity.  It identifies
    // the username and password combination used in the message-integrity
    // check.
    // 
    // The value of USERNAME is a variable-length value.  It MUST contain a
    // UTF-8 [RFC3629] encoded sequence of less than 513 bytes, and MUST
    // have been processed using SASLprep [RFC4013].
    struct username_attribute : string_view_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::username;
    };

    // The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104] of
    // the STUN message.  The MESSAGE-INTEGRITY attribute can be present in
    // any STUN message type.  Since it uses the SHA1 hash, the HMAC will be
    // 20 bytes.  The text used as input to HMAC is the STUN message,
    // including the header, up to and including the attribute preceding the
    // MESSAGE-INTEGRITY attribute.  With the exception of the FINGERPRINT
    // attribute, which appears after MESSAGE-INTEGRITY, agents MUST ignore
    // all other attributes that follow MESSAGE-INTEGRITY.
    struct message_integrity_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::message_integrity;
        std::array<std::byte, 20> hmac_sha1;
    };

    // The FINGERPRINT attribute MAY be present in all STUN messages.  The
    // value of the attribute is computed as the CRC-32 of the STUN message
    // up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
    // the 32-bit value 0x5354554e (the XOR helps in cases where an
    // application packet is also using CRC-32 in it).  The 32-bit CRC is
    // the one defined in ITU V.42 [ITU.V42.2002], which has a generator
    // polynomial of x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1.
    // When present, the FINGERPRINT attribute MUST be the last attribute in
    // the message, and thus will appear after MESSAGE-INTEGRITY.
    struct fingerprint_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::fingerprint;
        net_uint32_t value;
    };

    // The ERROR-CODE attribute is used in error response messages.  It
    // contains a numeric error code value in the range of 300 to 699 plus a
    // textual reason phrase encoded in UTF-8 [RFC3629], and is consistent
    // in its code assignments and semantics with SIP [RFC3261] and HTTP
    // [RFC2616].  The reason phrase is meant for user consumption, and can
    // be anything appropriate for the error code.  Recommended reason
    // phrases for the defined error codes are included in the IANA registry
    // for error codes.  The reason phrase MUST be a UTF-8 [RFC3629] encoded
    // sequence of less than 128 characters (which can be as long as 763
    // bytes).
    // 
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Reserved, should be 0         |Class|     Number    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Reason Phrase (variable)                                ..
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct error_code_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::error_code;
        std::uint32_t zero_bits : 21;
        std::uint32_t class_bits : 3;
        std::uint32_t number : 8;

        stun_error_code error_code() const noexcept;
        std::string_view error_message() const noexcept;
    };

    // The REALM attribute may be present in requests and responses.  It
    // contains text that meets the grammar for "realm-value" as described
    // in RFC 3261 [RFC3261] but without the double quotes and their
    // surrounding whitespace.  That is, it is an unquoted realm-value (and
    // is therefore a sequence of qdtext or quoted-pair).  It MUST be a
    // UTF-8 [RFC3629] encoded sequence of less than 128 characters (which
    // can be as long as 763 bytes), and MUST have been processed using
    // SASLprep [RFC4013].
    // 
    // Presence of the REALM attribute in a request indicates that long-term
    // credentials are being used for authentication.  Presence in certain
    // error responses indicates that the server wishes the client to use a
    // long-term credential for authentication.
    struct realm_attribute : string_view_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::realm;
    };

    // The NONCE attribute may be present in requests and responses.  It
    // contains a sequence of qdtext or quoted-pair, which are defined in
    // RFC 3261 [RFC3261].  Note that this means that the NONCE attribute
    // will not contain actual quote characters.  See RFC 2617 [RFC2617],
    // Section 4.3, for guidance on selection of nonce values in a server.
    // 
    // It MUST be less than 128 characters (which can be as long as 763
    // bytes).
    struct nonce_attribute : string_view_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::nonce;
    };

    // The UNKNOWN-ATTRIBUTES attribute is present only in an error response
    // when the response code in the ERROR-CODE attribute is 420.
    // 
    // The attribute contains a list of 16-bit values, each of which
    // represents an attribute type that was not understood by the server.
    // 
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Attribute 1 Type           |     Attribute 2 Type        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Attribute 3 Type           |     Attribute 4 Type    ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct unknown_attribute_values : data_view_attribute<std::uint16_t>
    {
        inline static constexpr auto c_type = stun_attribute_type::unknown_attributes;
    };


    // The SOFTWARE attribute contains a textual description of the software
    // being used by the agent sending the message.  It is used by clients
    // and servers.  Its value SHOULD include manufacturer and version
    // number.  The attribute has no impact on operation of the protocol,
    // and serves only as a tool for diagnostic and debugging purposes.  The
    // value of SOFTWARE is variable length.  It MUST be a UTF-8 [RFC3629]
    // encoded sequence of less than 128 characters (which can be as long as
    // 763 bytes).
    struct software_attribute : string_view_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::software;
    };

    // The alternate server represents an alternate transport address
    // identifying a different STUN server that the STUN client should try.
    // 
    // It is encoded in the same way as MAPPED-ADDRESS, and thus refers to a
    // single server by IP address.  The IP address family MUST be identical
    // to that of the source IP address of the request.
    struct alternate_server_attribute : mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::alternate_server;
    };

    struct ipv4_alternate_server_attribute : ipv4_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::alternate_server;
    };

    struct ipv6_alternate_server_attribute : ipv6_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::alternate_server;
    };

    // The CHANNEL-NUMBER attribute contains the number of the channel.  The
    // value portion of this attribute is 4 bytes long and consists of a 16-
    // bit unsigned integer, followed by a two-octet RFFU (Reserved For
    // Future Use) field, which MUST be set to 0 on transmission and MUST be
    // ignored on reception.
    // 
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |        Channel Number         |         RFFU = 0              |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    struct channel_number_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::channel_number;

        net_uint16_t channel_number;
    };

    // The LIFETIME attribute represents the duration for which the server
    // will maintain an allocation in the absence of a refresh.  The value
    // portion of this attribute is 4-bytes long and consists of a 32-bit
    // unsigned integral value representing the number of seconds remaining
    // until expiration.
    struct lifetime_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::lifetime;

        net_uint32_t lifetime;
    };

    // The XOR-PEER-ADDRESS specifies the address and port of the peer as
    // seen from the TURN server.  (For example, the peer's server-reflexive
    // transport address if the peer is behind a NAT.)  It is encoded in the
    // same way as XOR-MAPPED-ADDRESS [RFC5389].
    struct xor_peer_address_attribute : xor_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_peer_address;
    };

    struct ipv4_xor_peer_address_attribute : ipv4_xor_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_peer_address;
    };

    struct ipv6_xor_peer_address_attribute : ipv6_xor_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_peer_address;
    };

    // The DATA attribute is present in all Send and Data indications.  The
    // value portion of this attribute is variable length and consists of
    // the application data (that is, the data that would immediately follow
    // the UDP header if the data was been sent directly between the client
    // and the peer).  If the length of this attribute is not a multiple of
    // 4, then padding must be added after this attribute.
    struct data_attribute : data_view_attribute<std::byte>
    {
        inline static constexpr auto c_type = stun_attribute_type::data;
    };

    // The XOR-RELAYED-ADDRESS is present in Allocate responses.  It
    // specifies the address and port that the server allocated to the
    // client.  It is encoded in the same way as XOR-MAPPED-ADDRESS
    // [RFC5389].
    struct xor_relayed_address_attribute : mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_relayed_address;
    };

    struct ipv4_xor_relayed_address_attribute : ipv4_xor_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_relayed_address;
    };

    struct ipv6_xor_relayed_address_attribute : ipv6_xor_mapped_address_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::xor_relayed_address;
    };

    // This attribute allows the client to request that the port in the
    // relayed transport address be even, and (optionally)that the server
    // reserve the next - higher port number.The value portion of this
    // attribute is 1 byte long.Its format is :
    // 
    //  0 1 2 3 4 5 6 7
    // +-+-+-+-+-+-+-+-+
    // |R|    RFFU     |
    // +-+-+-+-+-+-+-+-+
    // 
    // The value contains a single 1-bit flag:
    // 
    // R: If 1, the server is requested to reserve the next-higher port
    //    number (on the same IP address) for a subsequent allocation.  If
    //    0, no such reservation is requested.
    // 
    // The other 7 bits of the attribute's value must be set to zero on
    // transmission and ignored on reception.
    // 
    // Since the length of this attribute is not a multiple of 4, padding
    // must immediately follow this attribute.
    struct even_port_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::even_port;

        std::uint8_t flag;
    };

    // This attribute is used by the client to request a specific transport
    // protocol for the allocated transport address.  The value of this
    // attribute is 4 bytes with the following format:
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |    Protocol   |                    RFFU                       |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 
    // The Protocol field specifies the desired protocol.  The codepoints
    // used in this field are taken from those allowed in the Protocol field
    // in the IPv4 header and the NextHeader field in the IPv6 header
    // [Protocol-Numbers].  This specification only allows the use of
    // codepoint 17 (User Datagram Protocol).
    // 
    // The RFFU field MUST be set to zero on transmission and MUST be
    // ignored on reception.  It is reserved for future uses.
    struct requested_transport_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::requested_transport;

        std::uint8_t protocol;
    };

    // This attribute is used by the client to request that the server set
    // the DF (Don't Fragment) bit in the IP header when relaying the
    // application data onward to the peer.  This attribute has no value
    // part and thus the attribute length field is 0.
    struct dont_fragment_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::dont_fragment;
    };

    // The RESERVATION-TOKEN attribute contains a token that uniquely
    // identifies a relayed transport address being held in reserve by the
    // server.  The server includes this attribute in a success response to
    // tell the client about the token, and the client includes this
    // attribute in a subsequent Allocate request to request the server use
    // that relayed transport address for the allocation.
    // 
    // The attribute value is 8 bytes and contains the token value.
    struct reservation_token_attribute : stun_attribute
    {
        inline static constexpr auto c_type = stun_attribute_type::reservation_token;

        std::array<std::byte, 8> token;
    };

    struct message_builder
    {
        message_builder(
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_request(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_success_response(
            stun_method method,
            const std::array<std::uint32_t, 3>& transaction_id,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_error_response(
            stun_method method,
            const std::array<std::uint32_t, 3>& transaction_id,
            stun_error_code error,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_indication(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        template<typename attribute_t>
            requires std::is_base_of_v<string_view_attribute, attribute_t>
        message_builder& add_attribute(std::string_view value) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>(value.size());

            std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(attribute_t), value.data(), value.size());

            return *this;
        }

        template<typename attribute_t>
            requires std::is_base_of_v<ipv4_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(const SOCKADDR_IN& address) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv4;
            attr->port = address.sin_port;
            std::memcpy(attr->address_bytes.data(), &address.sin_addr, attr->address_bytes.size());

            return *this;
        }

        template<typename attribute_t>
            requires std::is_base_of_v<ipv6_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(const SOCKADDR_IN6& address) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv6;
            attr->port = address.sin6_port;
            std::memcpy(attr->address_bytes.data(), &address.sin6_addr, attr->address_bytes.size());

            return *this;
        }

        template<typename attribute_t>
            requires std::is_base_of_v<ipv4_xor_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(
            const SOCKADDR_IN& address
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv4;

            std::uint16_t xor_port = address.sin_port ^ util::hton(static_cast<std::uint16_t>(c_stun_magic_cookie >> 16));
            std::memcpy(attr->port_bytes.data(), &xor_port, attr->port_bytes.size());

            std::uint32_t xor_address = address.sin_addr.S_un.S_addr ^ util::hton(c_stun_magic_cookie);
            std::memcpy(attr->address_bytes.data(), &xor_address, attr->address_bytes.size());

            return *this;
        }

        template<typename attribute_t>
            requires std::is_base_of_v<ipv6_xor_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(
            const SOCKADDR_IN6& address
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv6;

            std::uint16_t xor_port = address.sin6_port ^ util::hton(static_cast<std::uint16_t>(c_stun_magic_cookie >> 16));
            std::memcpy(attr->port_bytes.data(), &xor_port, attr->port_bytes.size());

            constexpr net_uint32_t magic_cookie = c_stun_magic_cookie;

            auto src = reinterpret_cast<const std::array<const std::uint32_t, 4>*>(address.sin6_addr.u.Byte);
            
            auto& id = get_header().transaction_id;

            detail::xor_map_ipv6_address(attr->address_bytes, *src, id);

            return *this;
        }

        template<typename attribute_t, typename data_t>
        message_builder& add_attribute(
            std::span<const data_t> data
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>(data.size_bytes());

            std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), data.data(), data.size() * sizeof(data_t));

            return *this;
        }

        template<typename attribute_t, std::integral data_t>
        message_builder& add_attribute(
            data_t data
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>(sizeof(data_t));

            std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), &data, sizeof(data_t));

            return *this;
        }

        template<typename attribute_t>
            requires requires { 
                sizeof(attribute_t) == sizeof(stun_attribute); 
                !std::is_base_of_v<string_view_attribute, attribute_t>;
                !std::is_base_of_v<data_base_attribute, attribute_t>;
            }
        message_builder& add_attribute() noexcept
        {
            std::ignore = internal_add_attribute<attribute_t>();

            return *this;
        }

        message_builder&& add_integrity(std::string_view username, std::string_view realm, std::string_view password) && noexcept;
        message_builder&& add_integrity(std::string_view password) && noexcept;
        std::span<std::byte> add_fingerprint() && noexcept;
        std::span<std::byte> create() && noexcept;
    private:
        std::uint16_t m_buffer_used{0};
        std::span<std::byte> m_message;

        stun_header& get_header() noexcept;

        // These attributes are only able to be included as part of the integrity attribute
        template<> message_builder& add_attribute<username_attribute>(std::string_view value) noexcept;
        template<> message_builder& add_attribute<realm_attribute>(std::string_view value) noexcept;
        void add_error_code(stun_error_code error) noexcept;

        template <typename attribute_type>
        attribute_type* internal_add_attribute(size_t data = 0) noexcept
        {
            std::uint16_t padded_size = sizeof(attribute_type) + static_cast<std::uint16_t>(data);

            std::uint16_t remainder = padded_size % 4;
            if (remainder != 0)
            {
                padded_size += (4 - remainder);
            }

            assert((m_buffer_used + padded_size <= m_message.size()) && "Buffer is too small");

            auto attr_start = m_message.data() + m_buffer_used;

            auto attr = new(attr_start) attribute_type{};
            attr->type = attribute_type::c_type;
            attr->size = host_uint16_t{ sizeof(attribute_type) - sizeof(stun_attribute) + static_cast<std::uint16_t>(data) };

            m_buffer_used += padded_size;

            // Zero out any padding
            if (remainder != 0)
            {
                std::memset(m_message.data() + m_buffer_used - remainder, 0, remainder);
            }

            return attr;
        }
    };

    
 
    struct message_reader
    {
        static std::expected<message_reader, std::error_code> create(
            std::span<const std::byte> buffer
        ) noexcept;

        bool has_integrity() const noexcept { return m_integrity != nullptr; }
        const username_attribute* get_username() const noexcept { return m_username; }
        const realm_attribute* get_realm() const noexcept { return m_realm; }
        const nonce_attribute* get_nonce() const noexcept { return m_nonce; }
        std::error_code check_integrity(std::string_view password);

        // TODO: Need to make a Forward_iterator type for this.
        inline auto begin() const noexcept { return m_begin; }
        inline auto end() const noexcept { return m_end; }

    private:
        message_reader(
            std::span<const std::byte> buffer
        ) noexcept;

        const stun_header& get_header() const noexcept;
        const stun_attribute* get_next_attibute(const stun_attribute* attr) const noexcept;

        std::error_code validate() noexcept;
     
        std::span<const std::byte> m_message;
        const stun_attribute* m_begin;
        const stun_attribute* m_end;

        const username_attribute* m_username;
        const realm_attribute* m_realm;
        const nonce_attribute* m_nonce;
        const message_integrity_attribute* m_integrity;

    };
}