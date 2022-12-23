#include <gtest/gtest.h>

#include "stun_message.h"

TEST(stun_builder, binding_request) {
    std::array<std::byte, 1024> buffer;
    auto builder = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
        .set_transaction_id({ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D });

    auto packet = std::move(builder).create();

    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";

    const std::array c_expected_bytes{ 
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, // Binding Request, Size 0
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
    };

    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, binding_response_failure) {
    std::array<std::byte, 1024> buffer;
    auto builder = stunpp::message_builder::create_error_response(
        stunpp::stun_method::binding, { 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D }, buffer)
        .add_error_attribute(stunpp::stun_error_code::unauthorized);

    auto packet = std::move(builder).create();

    // This should be greater than the sizes because of the error message
    EXPECT_GT(packet.size(), sizeof(stunpp::stun_header) + sizeof(stunpp::error_code_attribute)) << "Packet did size did not match the size of the header";

    const std::array c_expected_bytes{
        std::byte{0x01}, std::byte{0x11}, std::byte{0x00}, std::byte{0x84}, // Binding Error, Size 292
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x00}, std::byte{0x09}, std::byte{0x00}, std::byte{0x7F}, // Attribute: Error Code, Size: 285
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04}, std::byte{0x01}, // Zero Bits, Class: 4, Number: 1
    };

    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, binding_response_success) {
    
    SOCKADDR_IN address;
    address.sin_family = AF_INET;
    address.sin_port = 0xABCD;
    address.sin_addr.S_un.S_un_b.s_b1 = 127;
    address.sin_addr.S_un.S_un_b.s_b2 = 0;
    address.sin_addr.S_un.S_un_b.s_b3 = 0;
    address.sin_addr.S_un.S_un_b.s_b4 = 1;
    std::array<std::byte, 1024> buffer;
    auto builder = stunpp::message_builder::create_success_response(
        stunpp::stun_method::binding, { 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D }, buffer)
        .add_attribute<stunpp::ipv4_xor_mapped_address_attribute>(address);
    auto packet = std::move(builder).create();

    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header) + sizeof(stunpp::ipv4_xor_mapped_address_attribute)) << "Packet did size did not match the size of the header";

    const std::array c_expected_bytes{
        std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x0C}, // Binding Success, Size 12
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x08}, // Attribute: XOR Mapped Address, Size: 8
        std::byte{0x00}, std::byte{0x01}, std::byte{0xEC}, std::byte{0xB9}, // Zero, Address Family, Port ^ 0x2112
        std::byte{0x5E}, std::byte{0x12}, std::byte{0xA4}, std::byte{0x43}, // IPv4 Address ^ 0x2112A442
    };

    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, binding_request_fingerprint) {
    std::array<std::byte, 1024> buffer;
    auto builder = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
        .set_transaction_id({ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D });

    auto packet = std::move(builder).add_fingerprint();

    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header) + sizeof(stunpp::fingerprint_attribute)) << "Packet did size did not match the size of the header";

    const std::array c_expected_bytes{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x08}, // Binding Request, Size 8
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x80}, std::byte{0x28}, std::byte{0x00}, std::byte{0x04}, // Attribute: Fingerprint, Size: 4
        std::byte{0x34}, std::byte{0xb3}, std::byte{0xb9}, std::byte{0x47}, // CRC32 ^ 0x5354554e
    };

    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, rfc5769_request) {
    // Binding request test
    std::array<std::byte, 1024> buffer;
    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
        .set_padding_value(std::byte{0x20})
        .set_transaction_id({ 0x01a7e7b7, 0x86d634bc, 0xaedf87fa })
        .add_attribute<stunpp::software_attribute>("STUN test client")
        .add_attribute<stunpp::priority_attribute>(stunpp::host_uint32_t(0x6E0001FF))
        .add_attribute<stunpp::ice_controlled_attribute>(stunpp::host_uint64_t(0x932ff9b151263b36))
        .add_attribute<stunpp::username_attribute>("evtj:h6vY")
        .add_short_term_integrity("VOkJxbRl1RmTxUk/WvJxBt")
        .add_fingerprint();

    const std::array c_expected_bytes{
        std::byte{ 0x00 }, std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0x58 }, // Binding request, Size 88
        std::byte{ 0x21 }, std::byte{ 0x12 }, std::byte{ 0xa4 }, std::byte{ 0x42 }, // Magic Cookie
        std::byte{ 0xb7 }, std::byte{ 0xe7 }, std::byte{ 0xa7 }, std::byte{ 0x01 }, // Tranaction Id
        std::byte{ 0xbc }, std::byte{ 0x34 }, std::byte{ 0xd6 }, std::byte{ 0x86 }, // Tranaction Id
        std::byte{ 0xfa }, std::byte{ 0x87 }, std::byte{ 0xdf }, std::byte{ 0xae }, // Tranaction Id
        std::byte{ 0x80 }, std::byte{ 0x22 }, std::byte{ 0x00 }, std::byte{ 0x10 }, // Attribute: Software, Size: 16
        std::byte{ 0x53 }, std::byte{ 0x54 }, std::byte{ 0x55 }, std::byte{ 0x4e }, // "STUN"
        std::byte{ 0x20 }, std::byte{ 0x74 }, std::byte{ 0x65 }, std::byte{ 0x73 }, // " tes"
        std::byte{ 0x74 }, std::byte{ 0x20 }, std::byte{ 0x63 }, std::byte{ 0x6c }, // "t cl"
        std::byte{ 0x69 }, std::byte{ 0x65 }, std::byte{ 0x6e }, std::byte{ 0x74 }, // "ient"
        std::byte{ 0x00 }, std::byte{ 0x24 }, std::byte{ 0x00 }, std::byte{ 0x04 }, // Attribute: Priority, Size: 4
        std::byte{ 0x6e }, std::byte{ 0x00 }, std::byte{ 0x01 }, std::byte{ 0xff }, // Priority
        std::byte{ 0x80 }, std::byte{ 0x29 }, std::byte{ 0x00 }, std::byte{ 0x08 }, // Attribute: Ice Controlled, Size: 8
        std::byte{ 0x93 }, std::byte{ 0x2f }, std::byte{ 0xf9 }, std::byte{ 0xb1 }, // Tie breaker
        std::byte{ 0x51 }, std::byte{ 0x26 }, std::byte{ 0x3b }, std::byte{ 0x36 }, // Tie breaker
        std::byte{ 0x00 }, std::byte{ 0x06 }, std::byte{ 0x00 }, std::byte{ 0x09 }, // Attribute: Username, Size: 9
        std::byte{ 0x65 }, std::byte{ 0x76 }, std::byte{ 0x74 }, std::byte{ 0x6a }, // "evjt"
        std::byte{ 0x3a }, std::byte{ 0x68 }, std::byte{ 0x36 }, std::byte{ 0x76 }, // ":h6v"
        std::byte{ 0x59 }, std::byte{ 0x20 }, std::byte{ 0x20 }, std::byte{ 0x20 }, // "Y\0\0\0"
        std::byte{ 0x00 }, std::byte{ 0x08 }, std::byte{ 0x00 }, std::byte{ 0x14 }, // Attribute: Message Integrity, Size: 20 
        std::byte{ 0x9a }, std::byte{ 0xea }, std::byte{ 0xa7 }, std::byte{ 0x0c }, // HMAC-SHA1
        std::byte{ 0xbf }, std::byte{ 0xd8 }, std::byte{ 0xcb }, std::byte{ 0x56 }, // HMAC-SHA1
        std::byte{ 0x78 }, std::byte{ 0x1e }, std::byte{ 0xf2 }, std::byte{ 0xb5 }, // HMAC-SHA1
        std::byte{ 0xb2 }, std::byte{ 0xd3 }, std::byte{ 0xf2 }, std::byte{ 0x49 }, // HMAC-SHA1
        std::byte{ 0xc1 }, std::byte{ 0xb5 }, std::byte{ 0x71 }, std::byte{ 0xa2 }, // HMAC-SHA1
        std::byte{ 0x80 }, std::byte{ 0x28 }, std::byte{ 0x00 }, std::byte{ 0x04 }, // Attribute: Fingerprint, Size 4
        std::byte{ 0xe5 }, std::byte{ 0x7a }, std::byte{ 0x3b }, std::byte{ 0xcf }, // CRC32 ^ 0x5354554e
    };

    EXPECT_EQ(packet.size(), c_expected_bytes.size()) << "Packet did size did not match the size of the header";
    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, rfc5769_ipv4_response) {
    SOCKADDR_IN address;
    address.sin_family = AF_INET;
    address.sin_port = stunpp::util::hton<std::uint16_t>(32853);
    address.sin_addr.S_un.S_un_b.s_b1 = 192;
    address.sin_addr.S_un.S_un_b.s_b2 = 0;
    address.sin_addr.S_un.S_un_b.s_b3 = 2;
    address.sin_addr.S_un.S_un_b.s_b4 = 1;
    std::array<std::byte, 1024> buffer;
    auto packet = stunpp::message_builder::create_success_response(
            stunpp::stun_method::binding, { 0x01a7e7b7, 0x86d634bc, 0xaedf87fa }, buffer
        )
        .set_padding_value(std::byte{ 0x20 })
        .add_attribute<stunpp::software_attribute>("test vector")
        .add_attribute<stunpp::ipv4_xor_mapped_address_attribute>(address)
        .add_short_term_integrity("VOkJxbRl1RmTxUk/WvJxBt")
        .add_fingerprint();

    const std::array c_expected_bytes{
        std::byte{ 0x01 }, std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0x3c }, // Binding Success, Size 60
        std::byte{ 0x21 }, std::byte{ 0x12 }, std::byte{ 0xa4 }, std::byte{ 0x42 }, // Magic Cookie
        std::byte{ 0xb7 }, std::byte{ 0xe7 }, std::byte{ 0xa7 }, std::byte{ 0x01 }, // Transaction Id
        std::byte{ 0xbc }, std::byte{ 0x34 }, std::byte{ 0xd6 }, std::byte{ 0x86 }, // Transaction Id
        std::byte{ 0xfa }, std::byte{ 0x87 }, std::byte{ 0xdf }, std::byte{ 0xae }, // Transaction Id
        std::byte{ 0x80 }, std::byte{ 0x22 }, std::byte{ 0x00 }, std::byte{ 0x0b }, // Attribute: Software, Size: 11
        std::byte{ 0x74 }, std::byte{ 0x65 }, std::byte{ 0x73 }, std::byte{ 0x74 }, // "test"
        std::byte{ 0x20 }, std::byte{ 0x76 }, std::byte{ 0x65 }, std::byte{ 0x63 }, // " vec"
        std::byte{ 0x74 }, std::byte{ 0x6f }, std::byte{ 0x72 }, std::byte{ 0x20 }, // "tor\x20"
        std::byte{ 0x00 }, std::byte{ 0x20 }, std::byte{ 0x00 }, std::byte{ 0x08 }, // Attribute: XOR Mapped Address, Size: 8
        std::byte{ 0x00 }, std::byte{ 0x01 }, std::byte{ 0xa1 }, std::byte{ 0x47 }, // Family: IPv4, port ^ 0x2112
        std::byte{ 0xe1 }, std::byte{ 0x12 }, std::byte{ 0xa6 }, std::byte{ 0x43 }, // Address ^ 0x2112a442
        std::byte{ 0x00 }, std::byte{ 0x08 }, std::byte{ 0x00 }, std::byte{ 0x14 }, // Attribute: Message Integrity, Size: 20
        std::byte{ 0x2b }, std::byte{ 0x91 }, std::byte{ 0xf5 }, std::byte{ 0x99 }, // HMAC-SHA1
        std::byte{ 0xfd }, std::byte{ 0x9e }, std::byte{ 0x90 }, std::byte{ 0xc3 }, // HMAC-SHA1
        std::byte{ 0x8c }, std::byte{ 0x74 }, std::byte{ 0x89 }, std::byte{ 0xf9 }, // HMAC-SHA1
        std::byte{ 0x2a }, std::byte{ 0xf9 }, std::byte{ 0xba }, std::byte{ 0x53 }, // HMAC-SHA1
        std::byte{ 0xf0 }, std::byte{ 0x6b }, std::byte{ 0xe7 }, std::byte{ 0xd7 }, // HMAC-SHA1
        std::byte{ 0x80 }, std::byte{ 0x28 }, std::byte{ 0x00 }, std::byte{ 0x04 }, // Attribute: Fingerprint, Size 4
        std::byte{ 0xc0 }, std::byte{ 0x7d }, std::byte{ 0x4c }, std::byte{ 0x96 }, // CRC32 ^ 0x5354554e
    };

    EXPECT_EQ(packet.size(), c_expected_bytes.size()) << "Packet did size did not match the size of the header";
    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

TEST(stun_builder, rfc5769_ipv6_response) {
    SOCKADDR_IN6 address;
    address.sin6_family = AF_INET6;
    address.sin6_port = stunpp::util::hton<std::uint16_t>(32853);

    address.sin6_addr.u.Word[0] = stunpp::util::hton<std::uint16_t>(0x2001);
    address.sin6_addr.u.Word[1] = stunpp::util::hton<std::uint16_t>(0x0db8);
    address.sin6_addr.u.Word[2] = stunpp::util::hton<std::uint16_t>(0x1234);
    address.sin6_addr.u.Word[3] = stunpp::util::hton<std::uint16_t>(0x5678);
    address.sin6_addr.u.Word[4] = stunpp::util::hton<std::uint16_t>(0x0011);
    address.sin6_addr.u.Word[5] = stunpp::util::hton<std::uint16_t>(0x2233);
    address.sin6_addr.u.Word[6] = stunpp::util::hton<std::uint16_t>(0x4455);
    address.sin6_addr.u.Word[7] = stunpp::util::hton<std::uint16_t>(0x6677);

    std::array<std::byte, 92> buffer;
    auto packet = stunpp::message_builder::create_success_response(
        stunpp::stun_method::binding, { 0x01a7e7b7, 0x86d634bc, 0xaedf87fa }, buffer
    )
        .set_padding_value(std::byte{ 0x20 })
        .add_attribute<stunpp::software_attribute>("test vector")
        .add_attribute<stunpp::ipv6_xor_mapped_address_attribute>(address)
        .add_short_term_integrity("VOkJxbRl1RmTxUk/WvJxBt")
        .add_fingerprint();

    const std::array c_expected_bytes{
        std::byte{ 0x01 }, std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0x48 }, // Binding Success, Size: 72
        std::byte{ 0x21 }, std::byte{ 0x12 }, std::byte{ 0xa4 }, std::byte{ 0x42 }, // Magic Cookie
        std::byte{ 0xb7 }, std::byte{ 0xe7 }, std::byte{ 0xa7 }, std::byte{ 0x01 }, // Transaction Id
        std::byte{ 0xbc }, std::byte{ 0x34 }, std::byte{ 0xd6 }, std::byte{ 0x86 }, // Transaction Id
        std::byte{ 0xfa }, std::byte{ 0x87 }, std::byte{ 0xdf }, std::byte{ 0xae }, // Transaction Id
        std::byte{ 0x80 }, std::byte{ 0x22 }, std::byte{ 0x00 }, std::byte{ 0x0b }, // Attribute: Software, Size: 11
        std::byte{ 0x74 }, std::byte{ 0x65 }, std::byte{ 0x73 }, std::byte{ 0x74 }, // "test"
        std::byte{ 0x20 }, std::byte{ 0x76 }, std::byte{ 0x65 }, std::byte{ 0x63 }, // " vec"
        std::byte{ 0x74 }, std::byte{ 0x6f }, std::byte{ 0x72 }, std::byte{ 0x20 }, // "tor\x20"
        std::byte{ 0x00 }, std::byte{ 0x20 }, std::byte{ 0x00 }, std::byte{ 0x14 }, // Attribute: XOR Mapped Address, Size: 20
        std::byte{ 0x00 }, std::byte{ 0x02 }, std::byte{ 0xa1 }, std::byte{ 0x47 }, // Family: IPv6, port ^ 0x2112
        std::byte{ 0x01 }, std::byte{ 0x13 }, std::byte{ 0xa9 }, std::byte{ 0xfa }, // Address ^ 0x2112a442
        std::byte{ 0xa5 }, std::byte{ 0xd3 }, std::byte{ 0xf1 }, std::byte{ 0x79 }, // Address ^ Transaction Id
        std::byte{ 0xbc }, std::byte{ 0x25 }, std::byte{ 0xf4 }, std::byte{ 0xb5 }, // Address ^ Transaction Id
        std::byte{ 0xbe }, std::byte{ 0xd2 }, std::byte{ 0xb9 }, std::byte{ 0xd9 }, // Address ^ Transaction Id
        std::byte{ 0x00 }, std::byte{ 0x08 }, std::byte{ 0x00 }, std::byte{ 0x14 }, // Attribute: Message Integrity, Size: 20
        std::byte{ 0xa3 }, std::byte{ 0x82 }, std::byte{ 0x95 }, std::byte{ 0x4e }, // HMAC-SHA1
        std::byte{ 0x4b }, std::byte{ 0xe6 }, std::byte{ 0x7b }, std::byte{ 0xf1 }, // HMAC-SHA1
        std::byte{ 0x17 }, std::byte{ 0x84 }, std::byte{ 0xc9 }, std::byte{ 0x7c }, // HMAC-SHA1
        std::byte{ 0x82 }, std::byte{ 0x92 }, std::byte{ 0xc2 }, std::byte{ 0x75 }, // HMAC-SHA1
        std::byte{ 0xbf }, std::byte{ 0xe3 }, std::byte{ 0xed }, std::byte{ 0x41 }, // HMAC-SHA1
        std::byte{ 0x80 }, std::byte{ 0x28 }, std::byte{ 0x00 }, std::byte{ 0x04 }, // Attribute: Fingerprint, Size 4
        std::byte{ 0xc8 }, std::byte{ 0xfb }, std::byte{ 0x0b }, std::byte{ 0x4c }, // CRC32 ^ 0x5354554e
    };

    EXPECT_EQ(packet.size(), c_expected_bytes.size()) << "Packet did size did not match the size of the header";
    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}



TEST(stun_builder, rfc5769_long_term_credentials) {
    // Binding request test
    std::array<std::byte, 1024> buffer;
    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
        .set_transaction_id({ 0x3334ad78, 0xc072adc6, 0x2e41da29 })
        .add_attribute<stunpp::username_attribute>(reinterpret_cast<const char*>(u8"\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"))
        .add_attribute<stunpp::nonce_attribute>("f//499k954d6OL34oL9FSTvy64sA")
        .add_attribute<stunpp::realm_attribute>("example.org")
        .add_long_term_integrity(
            stunpp::message_builder::generate_md5_key(
                reinterpret_cast<const char*>(u8"\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"),
                "example.org",
                "TheMatrIX"
            )
        )
        .create();

    const std::array c_expected_bytes{
        std::byte{ 0x00 }, std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0x60 }, // Binding request, Size 88
        std::byte{ 0x21 }, std::byte{ 0x12 }, std::byte{ 0xa4 }, std::byte{ 0x42 }, // Mabig Cookie
        std::byte{ 0x78 }, std::byte{ 0xad }, std::byte{ 0x34 }, std::byte{ 0x33 }, // Tranaction Id
        std::byte{ 0xc6 }, std::byte{ 0xad }, std::byte{ 0x72 }, std::byte{ 0xc0 }, // Tranaction Id
        std::byte{ 0x29 }, std::byte{ 0xda }, std::byte{ 0x41 }, std::byte{ 0x2e }, // Tranaction Id
        std::byte{ 0x00 }, std::byte{ 0x06 }, std::byte{ 0x00 }, std::byte{ 0x12 }, // Attribute: Username, Size: 18
        std::byte{ 0xe3 }, std::byte{ 0x83 }, std::byte{ 0x9e }, std::byte{ 0xe3 }, 
        std::byte{ 0x83 }, std::byte{ 0x88 }, std::byte{ 0xe3 }, std::byte{ 0x83 }, 
        std::byte{ 0xaa }, std::byte{ 0xe3 }, std::byte{ 0x83 }, std::byte{ 0x83 }, 
        std::byte{ 0xe3 }, std::byte{ 0x82 }, std::byte{ 0xaf }, std::byte{ 0xe3 }, 
        std::byte{ 0x82 }, std::byte{ 0xb9 }, std::byte{ 0x00 }, std::byte{ 0x00 }, 
        std::byte{ 0x00 }, std::byte{ 0x15 }, std::byte{ 0x00 }, std::byte{ 0x1c }, // Attribute: Nonce, Size: 28
        std::byte{ 0x66 }, std::byte{ 0x2f }, std::byte{ 0x2f }, std::byte{ 0x34 }, 
        std::byte{ 0x39 }, std::byte{ 0x39 }, std::byte{ 0x6b }, std::byte{ 0x39 }, 
        std::byte{ 0x35 }, std::byte{ 0x34 }, std::byte{ 0x64 }, std::byte{ 0x36 }, 
        std::byte{ 0x4f }, std::byte{ 0x4c }, std::byte{ 0x33 }, std::byte{ 0x34 }, 
        std::byte{ 0x6f }, std::byte{ 0x4c }, std::byte{ 0x39 }, std::byte{ 0x46 }, 
        std::byte{ 0x53 }, std::byte{ 0x54 }, std::byte{ 0x76 }, std::byte{ 0x79 }, 
        std::byte{ 0x36 }, std::byte{ 0x34 }, std::byte{ 0x73 }, std::byte{ 0x41 }, 
        std::byte{ 0x00 }, std::byte{ 0x14 }, std::byte{ 0x00 }, std::byte{ 0x0b }, // Attribute: Realm, Size: 11
        std::byte{ 0x65 }, std::byte{ 0x78 }, std::byte{ 0x61 }, std::byte{ 0x6d }, 
        std::byte{ 0x70 }, std::byte{ 0x6c }, std::byte{ 0x65 }, std::byte{ 0x2e }, 
        std::byte{ 0x6f }, std::byte{ 0x72 }, std::byte{ 0x67 }, std::byte{ 0x00 }, 
        std::byte{ 0x00 }, std::byte{ 0x08 }, std::byte{ 0x00 }, std::byte{ 0x14 }, // Attribute: Message Integrity, Size: 20
        std::byte{ 0xf6 }, std::byte{ 0x70 }, std::byte{ 0x24 }, std::byte{ 0x65 }, // HMAC-SHA1
        std::byte{ 0x6d }, std::byte{ 0xd6 }, std::byte{ 0x4a }, std::byte{ 0x3e }, // HMAC-SHA1
        std::byte{ 0x02 }, std::byte{ 0xb8 }, std::byte{ 0xe0 }, std::byte{ 0x71 }, // HMAC-SHA1
        std::byte{ 0x2e }, std::byte{ 0x85 }, std::byte{ 0xc9 }, std::byte{ 0xa2 }, // HMAC-SHA1
        std::byte{ 0x8c }, std::byte{ 0xa8 }, std::byte{ 0x96 }, std::byte{ 0x66 }, // HMAC-SHA1
    };

    EXPECT_EQ(packet.size(), c_expected_bytes.size()) << "Packet did size did not match the size of the header";
    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}
