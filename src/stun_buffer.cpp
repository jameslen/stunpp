#include "stun_buffer.h"

#include <cassert>

namespace
{
    std::uint32_t c_magic_cookie = 0x2112A442;

    constexpr uint16_t make_type(
        stunpp::stun_method method
    ) noexcept
    {
        auto stun_method = static_cast<uint16_t>(method) & 0x0FFF;
        return ((stun_method & 0x000F) | ((stun_method & 0x0070) << 1) | ((stun_method & 0x0380) << 2) | ((stun_method & 0x0C00) << 2));
    }

    constexpr bool is_stun_request(stunpp::stun_method msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0000; }
    constexpr bool is_stun_success_resp(stunpp::stun_method msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0100; }
    constexpr bool is_stun_err_resp(stunpp::stun_method msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0110; }
    constexpr bool is_stun_indication(stunpp::stun_method msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0010; }

    constexpr uint16_t get_stun_request(stunpp::stun_method msg_type)      { return ((make_type(msg_type) & 0xFEEF)         ); }
    constexpr uint16_t get_stun_indication(stunpp::stun_method msg_type)   { return ((make_type(msg_type) & 0xFEEF) | 0x0010); }
    constexpr uint16_t get_stun_success_resp(stunpp::stun_method msg_type) { return ((make_type(msg_type) & 0xFEEF) | 0x0100); }
    constexpr uint16_t get_stun_err_resp(stunpp::stun_method msg_type)     { return ((make_type(msg_type)         ) | 0x0110); }
}

namespace stunpp
{
    SOCKADDR_IN ipv4_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, address_bytes.data(), address_bytes.size());
        addr.sin_port = port;
        return addr;
    }

    SOCKADDR_IN6 ipv6_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, address_bytes.data(), address_bytes.size());
        addr.sin6_port = port;
        return addr;
    }

    uint16_t xor_mapped_address_attribute::port() const noexcept
    {
        std::uint16_t port = std::bit_cast<std::uint16_t>(port_bytes);
        return port ^ util::hton(static_cast<std::uint16_t>(c_magic_cookie >> 16));
    }

    SOCKADDR_IN ipv4_xor_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, address_bytes.data(), address_bytes.size());
        addr.sin_addr.S_un.S_addr ^= util::hton(c_magic_cookie);
        addr.sin_port = port();
        return addr;
    }

    SOCKADDR_IN6 ipv6_xor_mapped_address_attribute::address(std::span<std::uint32_t, 3> message_id) const noexcept
    {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, address_bytes.data(), address_bytes.size());

        std::uint32_t magic_cookie = util::hton(c_magic_cookie);
        
        auto src = address_bytes.data();
        auto dst = reinterpret_cast<std::byte*>(addr.sin6_addr.u.Byte);
        auto id = reinterpret_cast<std::byte*>(message_id.data());

        for (std::uint32_t i = 0; i < 4; ++i)
        {
            dst[i] = src[i] ^ reinterpret_cast<const std::byte*>(&magic_cookie)[i];
        }

        for (std::uint32_t i = 0; i < 12; ++i)
        {
            dst[i + 4] = src[i + 4] ^ id[i];
        }

        addr.sin6_port = port();
        return addr;
    }

    std::string_view username_attribute::value() const noexcept
    {
        auto string_start = reinterpret_cast<const std::byte*>(this) + sizeof(stun_attribute);

        return { reinterpret_cast<const char*>(string_start), size };
    }

    stun_error_code error_code_attribute::error_code() const noexcept
    {
        return {}; // TODO:
    }

    std::string_view error_code_attribute::error_message() const noexcept
    {
        return {}; // TODO:
    }

    std::string_view realm_attribute::value() const noexcept
    {
        auto string_start = reinterpret_cast<const std::byte*>(this) + sizeof(stun_attribute);

        return { reinterpret_cast<const char*>(string_start), size };
    }

    std::string_view nonce_attribute::value() const noexcept
    {
        auto string_start = reinterpret_cast<const std::byte*>(this) + sizeof(stun_attribute);

        return { reinterpret_cast<const char*>(string_start), size };
    }

    std::span<std::uint16_t> unknown_attribute_values::values() const noexcept
    {
        return {}; // TODO:
    }

    std::string_view software_attribute::value() const noexcept
    {
        auto string_start = reinterpret_cast<const std::byte*>(this) + sizeof(stun_attribute);

        return { reinterpret_cast<const char*>(string_start), size };
    }

    message_builder::message_builder(
        std::span<std::byte> buffer
    ) noexcept :
        m_message(buffer)
    {
        assert(buffer.size() > sizeof(stun_header) && "Buffer must be large enough for at least the STUN message header.");

        auto& header = get_header();
        header.message_length = 0;
        header.magic_cookie = util::hton(c_magic_cookie);

        for (auto&& byte : header.transaction_id)
        {
            byte = (std::uint32_t)rand();
        }

        m_buffer_used = sizeof(stun_header);
    }

    message_builder message_builder::create_request(
        stun_method method,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_request(method));

        return builder;
    }

    message_builder message_builder::create_success_response(
        stun_method method,
        std::span<std::uint32_t, 3> transaction_id,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_success_resp(method));
        header.transaction_id[0] = transaction_id[0];
        header.transaction_id[1] = transaction_id[1];
        header.transaction_id[2] = transaction_id[2];

        return builder;
    }

    message_builder message_builder::create_error_response(
        stun_method method,
        std::span<std::uint32_t, 3> transaction_id,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_err_resp(method));
        header.transaction_id[0] = transaction_id[0];
        header.transaction_id[1] = transaction_id[1];
        header.transaction_id[2] = transaction_id[2];

        return builder;
    }

    message_builder message_builder::create_indication(
        stun_method method,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_indication(method));

        return builder;
    }

    message_builder&& message_builder::add_ipv4_address(
        const SOCKADDR_IN& address
    ) && noexcept
    {
        auto attr = add_attribute<ipv4_mapped_address_attribute>(stun_attribute_type::mapped_address);

        attr->family = address_family::ipv4;
        attr->size = sizeof(ipv4_mapped_address_attribute) - sizeof(stun_attribute);
        attr->port = address.sin_port;
        std::memcpy(attr->address_bytes.data(), &address.sin_addr, attr->address_bytes.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_ipv6_address(
        const SOCKADDR_IN6& address
    ) && noexcept
    {
        auto attr = add_attribute<ipv6_mapped_address_attribute>(stun_attribute_type::mapped_address);

        attr->family = address_family::ipv6;
        attr->size = sizeof(ipv6_mapped_address_attribute) - sizeof(stun_attribute);
        attr->port = address.sin6_port;
        std::memcpy(attr->address_bytes.data(), &address.sin6_addr, attr->address_bytes.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_xor_ipv4_address(
        const SOCKADDR_IN& address
    ) && noexcept
    {
        auto attr = add_attribute<ipv4_xor_mapped_address_attribute>(stun_attribute_type::xor_mapped_address);

        attr->family = address_family::ipv4;
        attr->size = sizeof(ipv4_xor_mapped_address_attribute) - sizeof(stun_attribute);

        std::uint16_t xor_port = address.sin_port ^ util::hton(static_cast<std::uint16_t>(c_magic_cookie >> 16));
        std::memcpy(attr->port_bytes.data(), &xor_port, attr->port_bytes.size());
        
        std::uint32_t xor_address = address.sin_addr.S_un.S_addr ^ util::hton(c_magic_cookie);
        std::memcpy(attr->address_bytes.data(), &xor_address, attr->address_bytes.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_xor_ipv6_address(
        const SOCKADDR_IN6& address
    ) && noexcept
    {
        auto attr = add_attribute<ipv6_xor_mapped_address_attribute>(stun_attribute_type::xor_mapped_address);

        attr->family = address_family::ipv6;
        attr->size = sizeof(ipv6_xor_mapped_address_attribute) - sizeof(stun_attribute);
        
        std::uint16_t xor_port = address.sin6_port ^ util::hton(static_cast<std::uint16_t>(c_magic_cookie >> 16));
        std::memcpy(attr->port_bytes.data(), &xor_port, attr->port_bytes.size());

        std::uint32_t magic_cookie = util::hton(c_magic_cookie);

        auto src = reinterpret_cast<const std::byte*>(address.sin6_addr.u.Byte);
        auto dst = attr->address_bytes.data();
        auto id = reinterpret_cast<std::byte*>(get_header().transaction_id.data());

        for (std::uint32_t i = 0; i < 4; ++i)
        {
            dst[i] = src[i] ^ reinterpret_cast<const std::byte*>(&magic_cookie)[i];
        }

        for (std::uint32_t i = 0; i < 12; ++i)
        {
            dst[i + 4] = src[i + 4] ^ id[i];
        }

        return std::move(*this);
    }

    message_builder&& message_builder::add_username(
        std::string_view username
    ) && noexcept
    {
        auto attr = add_attribute<username_attribute>(stun_attribute_type::username, username.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), username.data(), username.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_error_code(
        stun_error_code /*error*/
    ) && noexcept
    {
        auto attr = add_attribute<error_code_attribute>(stun_attribute_type::error_code);

        attr->size = sizeof(error_code_attribute) - sizeof(stun_attribute);

        // TODO: Error

        return std::move(*this);
    }

    message_builder&& message_builder::add_realm(
        std::string_view realm
    ) && noexcept
    {
        auto attr = add_attribute<realm_attribute>(stun_attribute_type::realm, realm.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), realm.data(), realm.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_nonce(
        std::string_view nonce
    ) && noexcept
    {
        auto attr = add_attribute<nonce_attribute>(stun_attribute_type::nonce, nonce.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), nonce.data(), nonce.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_software(
        std::string_view software
    )&& noexcept
    {
        auto attr = add_attribute<software_attribute>(stun_attribute_type::software, software.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), software.data(), software.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_unknown_attributes(
        std::span<std::uint16_t> attributes
    ) && noexcept
    {
        auto attr = add_attribute<unknown_attribute_values>(stun_attribute_type::unknown_attributes, attributes.size() * sizeof(std::uint16_t));

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), attributes.data(), attributes.size() * sizeof(std::uint16_t));

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
    ) && noexcept
    {
        auto attr = add_attribute<message_integrity_attribute>(stun_attribute_type::message_integrity);

        (void)attr;

        // TODO: Add hash.  Remember m_buffer_user - sizeof(message_integrity_attribute)

        return std::move(*this);
    }

    std::span<std::byte> message_builder::add_fingerprint(
    ) && noexcept
    {
        auto attr = add_attribute<fingerprint_attribute>(stun_attribute_type::fingerprint);

        (void)attr;

        // TODO: Add crc32. Remember m_buffer_user - sizeof(fingerprint_atrribute)

        auto& header = get_header();
        header.message_length = m_buffer_used - sizeof(stun_header);

        return { m_message.data(), m_buffer_used };
    }

    std::span<std::byte> message_builder::create() && noexcept
    {
        auto& header = get_header();
        header.message_length = m_buffer_used - sizeof(stun_header);
        return { m_message.data(), m_buffer_used };
    }

    stun_header& message_builder::get_header() noexcept
    {
        return *reinterpret_cast<stun_header*>(m_message.data());
    }
}