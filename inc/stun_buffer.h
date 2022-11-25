// https://datatracker.ietf.org/doc/html/rfc5389
#pragma once

#include <array>
#include <bit>
#include <cassert>
#include <memory_resource>
#include <span>
#include <string>
#include <vector>

#include <WinSock2.h>
#include <WS2tcpip.h>

namespace stunpp
{
    namespace util
    {
        template <typename T>
        constexpr T hton(T val)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return std::byteswap(val);
            }
            else
            {
                return val;
            }
        }
    }

    enum class stun_method : std::uint16_t
    {
        reserved0 = 0x0000,
        binding = 0x0001,
        reserved1 = 0x0002,

        invalid = 0xFFFF
    };

    enum class stun_attribute_type : std::uint16_t
    {
        // Required Range
        reserved0 = 0x0000,
        mapped_address = 0x0001,
        reserved1 = 0x0002,
        reserved2 = 0x0003,
        reserved3 = 0x0004,
        reserved4 = 0x0005,
        username = 0x0006,
        reserved5 = 0x0007,
        message_integrity = 0x0008,
        error_code = 0x0009,
        unknown_attributes = 0x000A,
        reserved6 = 0x000B,
        realm = 0x0014,
        nonce = 0x0015,
        xor_mapped_address = 0x0020,

        // Optional Range
        software = 0x0022,
        alternate_server = 0x8023,
        fingerprint = 0x8028,

        invalid = 0xFFFF
    };

    enum class address_family : std::uint8_t
    {
        ipv4 = 0x01,
        ipv6 = 0x02
    };

    enum class stun_error_code : std::uint32_t
    {
        try_alternate = 300,     // The client should contact an alternate server for
        // this request.  This error response MUST only be sent if the
        // request included a USERNAME attribute and a valid MESSAGE-
        // INTEGRITY attribute; otherwise, it MUST NOT be sent and error
        // code 400 (Bad Request) is suggested.  This error response MUST
        // be protected with the MESSAGE-INTEGRITY attribute, and receivers
        // MUST validate the MESSAGE-INTEGRITY of this response before
        // redirecting themselves to an alternate server.

        bad_request = 400,       // The request was malformed.  The client SHOULD NOT
        // retry the request without modification from the previous
        // attempt.  The server may not be able to generate a valid
        // MESSAGE-INTEGRITY for this error, so the client MUST NOT expect
        // a valid MESSAGE-INTEGRITY attribute on this response.

        unauthorized = 401,     // The request did not contain the correct
        // credentials to proceed.  The client should retry the request
        // with proper credentials.

        unknown_attribute = 420, // The server received a STUN packet containing
        // a comprehension-required attribute that it did not understand.
        // The server MUST put this unknown attribute in the UNKNOWN-
        // ATTRIBUTE attribute of its error response.

        stale_nonce = 438,       // The NONCE used by the client was no longer valid.
        // The client should retry, using the NONCE provided in the
        // response.

        server_error = 500       // Server Error: The server has suffered a temporary error.  The
        // client should try again.
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
        std::uint16_t message_type;
        std::uint16_t message_length;
        std::uint32_t magic_cookie;
        std::array<std::uint32_t, 3> transaction_id;
    };

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
        std::uint16_t size;
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
        std::uint8_t zeros;
        address_family family;
        std::uint16_t port;
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
        std::uint8_t zeros;
        address_family family;

        // X-Port is computed by taking the mapped port in host byte order,
        // XOR'ing it with the most significant 16 bits of the magic cookie, and
        // then the converting the result to network byte order.
        std::array<std::byte, 2> port_bytes;

        std::uint16_t port() const noexcept;
    };

    // Specific type for ipv4 addresses
    struct ipv4_xor_mapped_address_attribute : xor_mapped_address_attribute
    {
        std::array<std::byte, 4> address_bytes;

        SOCKADDR_IN address() const noexcept;
    };

    // Specific type for ipv6 addresses
    struct ipv6_xor_mapped_address_attribute : xor_mapped_address_attribute
    {
        std::array<std::byte, 16> address_bytes;

        SOCKADDR_IN6 address(std::span<std::uint32_t, 3> message_id) const noexcept;
    };


    // The USERNAME attribute is used for message integrity.  It identifies
    // the username and password combination used in the message-integrity
    // check.
    // 
    // The value of USERNAME is a variable-length value.  It MUST contain a
    // UTF-8 [RFC3629] encoded sequence of less than 513 bytes, and MUST
    // have been processed using SASLprep [RFC4013].
    struct username_attribute : stun_attribute
    {
        std::string_view value() const noexcept;
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
        std::array<std::byte, 20> key;
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
        std::uint32_t value;
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
    struct realm_attribute : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    // The NONCE attribute may be present in requests and responses.  It
    // contains a sequence of qdtext or quoted-pair, which are defined in
    // RFC 3261 [RFC3261].  Note that this means that the NONCE attribute
    // will not contain actual quote characters.  See RFC 2617 [RFC2617],
    // Section 4.3, for guidance on selection of nonce values in a server.
    // 
    // It MUST be less than 128 characters (which can be as long as 763
    // bytes).
    struct nonce_attribute : stun_attribute
    {
        std::string_view value() const noexcept;
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
    struct unknown_attribute_values : stun_attribute
    {
        std::span<std::uint16_t> values() const noexcept;
    };


    // The SOFTWARE attribute contains a textual description of the software
    // being used by the agent sending the message.  It is used by clients
    // and servers.  Its value SHOULD include manufacturer and version
    // number.  The attribute has no impact on operation of the protocol,
    // and serves only as a tool for diagnostic and debugging purposes.  The
    // value of SOFTWARE is variable length.  It MUST be a UTF-8 [RFC3629]
    // encoded sequence of less than 128 characters (which can be as long as
    // 763 bytes).
    struct software_attribute : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    // The alternate server represents an alternate transport address
    // identifying a different STUN server that the STUN client should try.
    // 
    // It is encoded in the same way as MAPPED-ADDRESS, and thus refers to a
    // single server by IP address.  The IP address family MUST be identical
    // to that of the source IP address of the request.
    struct alternate_server_attribute : mapped_address_attribute
    {
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
            std::span<std::uint32_t, 3> transaction_id,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_error_response(
            stun_method method,
            std::span<std::uint32_t, 3> transaction_id,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_indication(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        message_builder&& add_ipv4_address(const SOCKADDR_IN& addr) && noexcept;
        message_builder&& add_ipv6_address(const SOCKADDR_IN6& addr) && noexcept;
        message_builder&& add_xor_ipv4_address(const SOCKADDR_IN& addr) && noexcept;
        message_builder&& add_xor_ipv6_address(const SOCKADDR_IN6& addr) && noexcept;
        message_builder&& add_username(std::string_view name) && noexcept;
        message_builder&& add_error_code(stun_error_code error) && noexcept;
        message_builder&& add_realm(std::string_view realm) && noexcept;
        message_builder&& add_nonce(std::string_view nonce) && noexcept;
        message_builder&& add_software(std::string_view nonce)&& noexcept;
        message_builder&& add_unknown_attributes(std::span<uint16_t> attrs) && noexcept;

        message_builder&& add_integrity() && noexcept;
        std::span<std::byte> add_fingerprint() && noexcept;
        std::span<std::byte> create() && noexcept;
    private:
        std::uint16_t m_buffer_used{0};
        std::span<std::byte> m_message;

        stun_header& get_header() noexcept;

        template <typename attribute_type>
        attribute_type* add_attribute(stun_attribute_type type, size_t data = 0) noexcept
        {
            assert((m_buffer_used + sizeof(attribute_type) + data <= m_message.size()) && "Buffer is too small");

            auto attr_start = m_message.data() + m_buffer_used;

            auto attr = new(attr_start) attribute_type{};
            attr->type = type;
            attr->size = sizeof(attribute_type) - sizeof(stun_attribute) + static_cast<std::uint16_t>(data);

            m_buffer_used += sizeof(attribute_type) + static_cast<std::uint16_t>(data);

            return attr;
        }
    };

    struct message_reader
    {
    };
}