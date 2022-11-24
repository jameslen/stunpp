/*
* Copyright (C) 2011, 2012, 2013 Citrix Systems
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the project nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/
#pragma once

///////////////////////////////////////////////////////////////

#include <array>
#include <bit>
#include <memory_resource>
#include <span>
#include <string>
#include <vector>

#include <WinSock2.h>

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

namespace stunpp
{
    enum class stun_method : uint16_t
    {
        reserved0 = 0x0000,
        binding = 0x0001,
        reserved1 = 0x0002,

        invalid = 0xFFFF
    };

    enum class stun_attribute_type : uint16_t
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

    enum class address_family : uint8_t
    {
        ipv4 = 0x01,
        ipv6 = 0x02
    };

    struct stun_header
    {
        std::uint16_t message_type;
        std::uint16_t message_length;
        std::uint32_t magic_cookie;
        std::array<std::uint32_t,3> transaction_id;
    };

    struct stun_attribute
    {
        stun_attribute_type type;
        std::uint16_t size;
    };

    struct mapped_address_value : stun_attribute
    {
        std::uint8_t zeros;
        address_family family;
        std::uint16_t port;
    };

    struct ipv4_mapped_address_value : mapped_address_value
    {
        std::array<std::byte,4> address_bytes;

        SOCKADDR_IN address() const noexcept;
    };

    struct ipv6_mapped_address_value : mapped_address_value
    {
        std::array<std::byte,16> address_bytes;
        
        SOCKADDR_STORAGE address() const noexcept;
    };

    struct xor_mapped_address_value  : stun_attribute
    {
        std::uint8_t zeros;
        address_family family;
        std::array<std::byte, 2> port_bytes;

        std::uint16_t port() const noexcept;
    };

    struct ipv4_xor_mapped_address_value : xor_mapped_address_value
    {
        std::array<std::byte,4> address_bytes;

        SOCKADDR_IN address(std::span<std::uint8_t, 12> message_id) const noexcept;
    };

    struct ipv6_xor_mapped_address_value : xor_mapped_address_value
    {
        std::array<std::byte,16> address_bytes;

        SOCKADDR_STORAGE address(std::span<std::uint8_t, 12> message_id) const noexcept;
    };

    struct username_value : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    struct message_integrity_value
    {
        std::array<std::byte, 16> key;
    };

    struct fingerprint_value
    {
        // TODO: crc32 of whole message
    };

    struct error_code_value : stun_attribute
    {
        std::uint32_t zero_bits : 21;
        std::uint32_t class_bits : 3;
        std::uint32_t number : 8;
    };

    struct realm_value : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    struct nonce_value : stun_attribute
    {
        std::string_view value() const noexcept;
    };

    struct unknown_attribute_values : stun_attribute
    {
        std::span<std::uint16_t> values() const noexcept;
    };

    struct message_builder
    {
        message_builder(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_request(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_response(
            stun_method method,
            std::span<std::uint32_t, 3> transaction_id,
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_indication(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        message_builder&& add_ipv4_address(const SOCKADDR& addr) &&;
        message_builder&& add_ipv6_address(const sockaddr_storage& addr) &&;
        message_builder&& add_xor_ipv4_address(const SOCKADDR& addr) &&;
        message_builder&& add_xor_ipv6_address(const sockaddr_storage& addr) &&;
        message_builder&& add_username(std::string_view name) &&;
        message_builder&& add_integrity() &&;
        message_builder&& add_error_code() &&;
        message_builder&& add_realm(std::string_view realm) &&;
        message_builder&& add_nonce(std::string_view nonce)&&;
        message_builder&& add_unknown_attributes(std::span<uint16_t> attrs) &&;

        std::span<std::byte> add_fingerprint() &&;
        std::span<std::byte> create() &&;
    private:
        std::size_t m_buffer_used{0};
        std::span<std::byte> m_message;

        stun_header& get_header() noexcept;
    };

    struct message_reader
    {
    };
}