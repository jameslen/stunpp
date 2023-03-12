#include <gtest/gtest.h>

#include "stunpp/stun_message.h"
#include "stunpp/win32/stun_password_generator.h"

using namespace std::string_view_literals;

TEST(stun_reader, binding_request) {
    const std::array c_message_bytes{ 
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, // Binding Request, Size 0
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
    };

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::request);
        EXPECT_EQ(header.message_length, stunpp::util::network_order_from_value<std::uint16_t>(0));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, binding_response_failure) {
    std::array<std::byte, 1024> buffer;
    auto builder = stunpp::message_builder::create_error_response(
        stunpp::stun_method::binding, { 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D }, buffer)
        .add_error_attribute(stunpp::stun_error_code::unauthorized);

    auto packet = std::move(builder).create();

    // This should be greater than the sizes because of the error message
    EXPECT_GT(packet.size(), sizeof(stunpp::stun_header) + sizeof(stunpp::error_code_attribute)) << "Packet did size did not match the size of the header";

    const std::array c_message_bytes{
        std::byte{0x01}, std::byte{0x11}, std::byte{0x00}, std::byte{0x84}, // Binding Error, Size 132
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x00}, std::byte{0x09}, std::byte{0x00}, std::byte{0x7F}, // Attribute: Error Code, Size: 127
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04}, std::byte{0x01}, // Zero Bits, Class: 4, Number: 1
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::error_response);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(132));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        auto iter = reader.begin();

        EXPECT_NE(iter, reader.end());
        EXPECT_EQ(iter->type, stunpp::stun_attribute_type::error_code);
        EXPECT_EQ(iter->size, stunpp::host_uint16_t(127));
        EXPECT_EQ(iter.as<stunpp::error_code_attribute>()->error_code(), stunpp::stun_error_code::unauthorized);
        EXPECT_EQ(++iter, reader.end());
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, binding_response_success) {
    
    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0xABCD;
    addr.sin_addr.S_un.S_un_b.s_b1 = 127;
    addr.sin_addr.S_un.S_un_b.s_b2 = 0;
    addr.sin_addr.S_un.S_un_b.s_b3 = 0;
    addr.sin_addr.S_un.S_un_b.s_b4 = 1;

    const std::array c_message_bytes{
        std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x0C}, // Binding Success, Size 12
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x08}, // Attribute: XOR Mapped Address, Size: 8
        std::byte{0x00}, std::byte{0x01}, std::byte{0xEC}, std::byte{0xB9}, // Zero, Address Family, Port ^ 0x2112
        std::byte{0x5E}, std::byte{0x12}, std::byte{0xA4}, std::byte{0x43}, // IPv4 Address ^ 0x2112A442
    };

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::success_response);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x0C));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        auto iter = reader.begin();

        EXPECT_NE(iter, reader.end());
        EXPECT_EQ(iter->type, stunpp::stun_attribute_type::xor_mapped_address);
        EXPECT_EQ(iter->size, stunpp::host_uint16_t(8));
        auto address = iter.as<stunpp::xor_mapped_address_attribute>();
        EXPECT_EQ(address->family, stunpp::address_family::ipv4);
        auto result_address = address->ipv4_address();
        EXPECT_EQ(result_address.sin_addr.S_un.S_addr, addr.sin_addr.S_un.S_addr);
        EXPECT_EQ(result_address.sin_port, addr.sin_port);
        EXPECT_EQ(++iter, reader.end());
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, binding_request_fingerprint) {
    const std::array c_message_bytes{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x08}, // Binding Request, Size 8
        std::byte{0x21}, std::byte{0x12}, std::byte{0xa4}, std::byte{0x42}, // Magic Cookie
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xAD}, std::byte{0x0B}, // Tranaction Id
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}, // Tranaction Id
        std::byte{0x0D}, std::byte{0xF0}, std::byte{0xED}, std::byte{0xFE}, // Tranaction Id
        std::byte{0x80}, std::byte{0x28}, std::byte{0x00}, std::byte{0x04}, // Attribute: Fingerprint, Size: 4
        std::byte{0x34}, std::byte{0xb3}, std::byte{0xb9}, std::byte{0x47}, // CRC32 ^ 0x5354554e
    };

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::request);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x08));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x0BADF00D, 0xDEADBEEF, 0xFEEDF00D };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        auto iter = reader.begin();

        EXPECT_NE(iter, reader.end());
        EXPECT_EQ(iter->type, stunpp::stun_attribute_type::fingerprint);
        EXPECT_EQ(iter->size, stunpp::host_uint16_t(4));
        EXPECT_EQ(++iter, reader.end());
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, rfc5769_request) {
    stunpp::stun_password_generator generator{};
    const std::array c_message_bytes{
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

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::request);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x58));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x01a7e7b7, 0x86d634bc, 0xaedf87fa };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        if (reader.has_integrity())
        {
            if (!reader.check_integrity(
                generator,
                generator.generate_short_term_key("VOkJxbRl1RmTxUk/WvJxBt")
            ))
            {
                auto iter = reader.begin();

                EXPECT_NE(iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::software);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(16));
                auto software = iter.as<stunpp::software_attribute>();
                EXPECT_EQ(software->value(), "STUN test client"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::priority);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(4));
                auto priority = iter.as<stunpp::priority_attribute>();
                EXPECT_EQ(priority->value, stunpp::host_uint32_t(0x6E0001FF));

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::ice_controlled);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(8));
                auto ice_controlled = iter.as<stunpp::ice_controlled_attribute>();
                EXPECT_EQ(ice_controlled->value, stunpp::host_uint64_t(0x932ff9b151263b36));

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::username);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(9));
                auto username = iter.as<stunpp::username_attribute>();
                EXPECT_EQ(username->value(), "evtj:h6vY"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::message_integrity);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(20));

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::fingerprint);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(4));

                EXPECT_EQ(++iter, reader.end());
            }
            else
            {
                FAIL();
            }
        }
        else
        {
            FAIL();
        }
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, rfc5769_ipv4_response) {
    stunpp::stun_password_generator generator{};

    SOCKADDR_IN result_address;
    result_address.sin_family = AF_INET;
    result_address.sin_port = stunpp::util::hton<std::uint16_t>(32853);
    result_address.sin_addr.S_un.S_un_b.s_b1 = 192;
    result_address.sin_addr.S_un.S_un_b.s_b2 = 0;
    result_address.sin_addr.S_un.S_un_b.s_b3 = 2;
    result_address.sin_addr.S_un.S_un_b.s_b4 = 1;

    const std::array c_message_bytes{
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

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::success_response);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x3c));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x01a7e7b7, 0x86d634bc, 0xaedf87fa };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        if (reader.has_integrity())
        {
            if (!reader.check_integrity(
                generator,
                generator.generate_short_term_key("VOkJxbRl1RmTxUk/WvJxBt")
            ))
            {
                auto iter = reader.begin();

                EXPECT_NE(iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::software);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(11));
                auto software = iter.as<stunpp::software_attribute>();
                EXPECT_EQ(software->value(), "test vector"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::xor_mapped_address);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(8));
                auto address = iter.as<stunpp::xor_mapped_address_attribute>();
                auto mapped_address = address->ipv4_address();
                EXPECT_EQ(std::memcmp(&mapped_address, &result_address, sizeof(mapped_address)), 0);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::message_integrity);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(20));

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::fingerprint);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(4));

                EXPECT_EQ(++iter, reader.end());
            }
            else
            {
                FAIL();
            }
        }
        else
        {
            FAIL();
        }
    }
    else
    {
        FAIL();
    }
}

TEST(stun_reader, rfc5769_ipv6_response) {
    stunpp::stun_password_generator generator{};

    SOCKADDR_IN6 result_address{};
    result_address.sin6_family = AF_INET6;
    result_address.sin6_port = stunpp::util::hton<std::uint16_t>(32853);
    // 2001:db8:1234:5678:11:2233:4455:6677
    result_address.sin6_addr.u.Word[0] = stunpp::util::hton<std::uint16_t>(0x2001);
    result_address.sin6_addr.u.Word[1] = stunpp::util::hton<std::uint16_t>(0x0db8);
    result_address.sin6_addr.u.Word[2] = stunpp::util::hton<std::uint16_t>(0x1234);
    result_address.sin6_addr.u.Word[3] = stunpp::util::hton<std::uint16_t>(0x5678);
    result_address.sin6_addr.u.Word[4] = stunpp::util::hton<std::uint16_t>(0x0011);
    result_address.sin6_addr.u.Word[5] = stunpp::util::hton<std::uint16_t>(0x2233);
    result_address.sin6_addr.u.Word[6] = stunpp::util::hton<std::uint16_t>(0x4455);
    result_address.sin6_addr.u.Word[7] = stunpp::util::hton<std::uint16_t>(0x6677);

    const std::array c_message_bytes{
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

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::success_response);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x48));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x01a7e7b7, 0x86d634bc, 0xaedf87fa };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        if (reader.has_integrity())
        {
            if (!reader.check_integrity(
                generator,
                generator.generate_short_term_key("VOkJxbRl1RmTxUk/WvJxBt")
            ))
            {
                auto iter = reader.begin();

                EXPECT_NE(iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::software);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(11));
                auto software = iter.as<stunpp::software_attribute>();
                EXPECT_EQ(software->value(), "test vector"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::xor_mapped_address);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(20));
                auto address = iter.as<stunpp::xor_mapped_address_attribute>();
                auto mapped_address = address->ipv6_address(header.transaction_id);
                EXPECT_EQ(std::memcmp(&mapped_address, &result_address, sizeof(mapped_address)), 0);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::message_integrity);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(20));

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::fingerprint);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(4));

                EXPECT_EQ(++iter, reader.end());
            }
            else
            {
                FAIL();
            }
        }
        else
        {
            FAIL();
        }
    }
    else
    {
        FAIL();
    }
}



TEST(stun_reader, rfc5769_long_term_credentials) {
    stunpp::stun_password_generator generator{};

    const std::array c_message_bytes{
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

    auto result = stunpp::message_reader::create(c_message_bytes);

    if (result)
    {
        auto& reader = result.value();

        auto& header = reader.get_header();

        EXPECT_EQ(header.get_method(), stunpp::stun_method::binding);
        EXPECT_EQ(header.get_method_type(), stunpp::stun_method_type::request);
        EXPECT_EQ(header.message_length, stunpp::host_uint16_t(0x60));
        constexpr std::array<std::uint32_t, 3> c_expected_transaction_id{ 0x3334ad78, 0xc072adc6, 0x2e41da29 };
        EXPECT_EQ(header.transaction_id, c_expected_transaction_id);

        if (reader.has_integrity())
        {
            if (!reader.check_integrity(
                generator,
                generator.generate_long_term_md5_key(
                    reader.get_username()->value(),
                    reader.get_realm()->value(),
                    "TheMatrIX"
                )
            ))
            {
                auto iter = reader.begin();

                EXPECT_NE(iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::username);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(18));
                auto username = iter.as<stunpp::username_attribute>();
                EXPECT_EQ(username->value(), std::string_view{ reinterpret_cast<const char*>(u8"\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9") });

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::nonce);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(28));
                auto nonce = iter.as<stunpp::nonce_attribute>();
                EXPECT_EQ(nonce->value(), "f//499k954d6OL34oL9FSTvy64sA"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::realm);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(11));
                auto realm = iter.as<stunpp::realm_attribute>();
                EXPECT_EQ(realm->value(), "example.org"sv);

                EXPECT_NE(++iter, reader.end());
                EXPECT_EQ(iter->type, stunpp::stun_attribute_type::message_integrity);
                EXPECT_EQ(iter->size, stunpp::host_uint16_t(20));

                EXPECT_EQ(++iter, reader.end());
            }
            else
            {
                FAIL();
            }
        }
        else
        {
            FAIL();
        }
    }
    else
    {
        FAIL();
    }
}
