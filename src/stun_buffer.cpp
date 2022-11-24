#include "stun_buffer.h"

#include <cassert>

namespace
{
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
    SOCKADDR_IN ipv4_mapped_address_value::address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, address_bytes.data(), address_bytes.size());
        addr.sin_port = util::hton(port);
        return addr;
    }

    SOCKADDR_STORAGE ipv6_mapped_address_value::address() const noexcept
    {
        return {};
    }

    uint16_t xor_mapped_address_value::port() const noexcept
    {
        return 0; // TODO: XOR woth MSB of cookie
    }

    SOCKADDR_IN ipv4_xor_mapped_address_value::address(std::span<std::uint8_t, 12> message_id) const noexcept
    {
        // TODO: XOR with message id
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, address_bytes.data(), address_bytes.size());
        addr.sin_port = util::hton(port());
        return addr;
    }

    SOCKADDR_STORAGE ipv6_xor_mapped_address_value::address(std::span<std::uint8_t, 12> message_id) const noexcept
    {
        return {};
    }

    message_builder::message_builder(
        stun_method method,
        std::span<std::byte> buffer
    ) noexcept :
        m_message(buffer)
    {
        assert(buffer.size() > sizeof(stun_header) && "Buffer must be large enough for at least the STUN message header.");

        auto& header = get_header();
        header.message_length = 0;
        header.magic_cookie = util::hton(0x2112A442);

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
        message_builder builder(method, buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_request(method));

        return builder;
    }

    message_builder message_builder::create_response(
        stun_method method,
        std::span<std::uint32_t, 3> transaction_id,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(method, buffer);

        auto& header = builder.get_header();
        header.message_type = util::hton(get_stun_success_resp(method));
        header.transaction_id[0] = transaction_id[0];
        header.transaction_id[1] = transaction_id[1];
        header.transaction_id[2] = transaction_id[2];

        return builder;
    }

    std::span<std::byte> message_builder::create() &&
    {
        return { m_message.data(), m_buffer_used };
    }

    stun_header& message_builder::get_header() noexcept
    {
        // TODO: Proper lifetime start
        return *reinterpret_cast<stun_header*>(m_message.data());
    }

    message_builder&& message_builder::add_ipv4_address(
        const SOCKADDR& address
    ) &&
    {
        assert((m_buffer_used + sizeof(ipv4_mapped_address_value) <= m_message.size()) && "Buffer is too small");

        auto attr_start = m_message.data() + m_buffer_used;

        auto attr = new(attr_start) ipv4_mapped_address_value{};
        attr->type = stun_attribute_type::mapped_address;
        attr->family = address_family::ipv4;
        attr->size = sizeof(ipv4_mapped_address_value) - sizeof(stun_attribute);
        attr->port = reinterpret_cast<const sockaddr_in&>(address).sin_port;
        std::memcpy(attr->address_bytes.data(), &reinterpret_cast<const sockaddr_in&>(address).sin_addr, 4);

        m_buffer_used += sizeof(ipv4_mapped_address_value);
        return std::move(*this);
    }
}