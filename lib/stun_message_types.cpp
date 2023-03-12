#include "stun_message_types.h"

namespace
{
    constexpr stunpp::host_uint16_t c_method_mask = 0x0110;

    constexpr stunpp::stun_method_type get_method_type(stunpp::net_uint16_t message_type) noexcept
    {
        return stunpp::stun_method_type(static_cast<stunpp::host_uint16_t>(message_type) & c_method_mask);
    }

    constexpr stunpp::stun_method get_method(stunpp::net_uint16_t message_type) noexcept
    {
        auto stun_method = stunpp::host_uint16_t(message_type) & 0xFEEF;
        return stunpp::stun_method(
            (stun_method & 0x000F) |
            ((stun_method & 0x00E0) >> 1) |
            ((stun_method & 0x0E00) >> 2) |
            ((stun_method & 0x3000) >> 2)
        );
    }
}

namespace stunpp
{
    stun_method stun_header::get_method() const noexcept
    {
        return ::get_method(message_type);
    }

    stun_method_type stun_header::get_method_type() const noexcept
    {
        return ::get_method_type(message_type);
    }

    SOCKADDR_IN mapped_address_attribute::ipv4_address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, detail::get_bytes_after(this), 4);
        addr.sin_port = port.read();;
        return addr;
    }

    SOCKADDR_IN6 mapped_address_attribute::ipv6_address() const noexcept
    {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, detail::get_bytes_after(this), 16);
        addr.sin6_port = port.read();
        return addr;
    }

    net_uint16_t xor_mapped_address_attribute::port() const noexcept
    {
        return port_bytes ^ host_uint16_t(c_stun_magic_cookie >> 16);
    }

    SOCKADDR_IN xor_mapped_address_attribute::ipv4_address() const noexcept
    {
        auto address_bytes = detail::get_bytes_after_as<std::uint32_t>(this);
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = (util::network_order_from_value(*address_bytes) ^ c_stun_magic_cookie).read();
        addr.sin_port = port().read();
        return addr;
    }

    SOCKADDR_IN6 xor_mapped_address_attribute::ipv6_address(std::span<const std::uint32_t, 3> message_id) const noexcept
    {
        auto address_bytes = detail::get_bytes_after_as<std::array<std::uint32_t,4>>(this);
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, address_bytes->data(), sizeof(*address_bytes));

        auto dst = reinterpret_cast<std::array<std::uint32_t, 4>*>(addr.sin6_addr.u.Byte);

        detail::xor_map_ipv6_address(*dst, *address_bytes, message_id);

        addr.sin6_port = port().read();
        return addr;
    }

    std::string_view string_view_attribute::value() const noexcept
    {
        return { detail::get_bytes_after_as<const char>(this), static_cast<host_uint16_t>(size) };
    }

    stun_error_code error_code_attribute::error_code() const noexcept
    {
        return stun_error_code{ static_cast<std::uint32_t>(class_bits * 100 + number) };
    }

    std::string_view error_code_attribute::error_message() const noexcept
    {
        auto local_size = host_uint16_t{ size };
        std::uint16_t string_length = local_size - sizeof(error_code_attribute) + sizeof(stun_attribute);
        if (string_length == 0)
        {
            return {};
        }
        return std::string_view{ detail::get_bytes_after_as<const char>(this), string_length };
    }

    stun_error_code address_error_code_attribute::error_code() const noexcept
    {
        return stun_error_code{ static_cast<std::uint32_t>(class_bits * 100 + number) };
    }

    std::string_view address_error_code_attribute::error_message() const noexcept
    {
        auto local_size = host_uint16_t{ size };
        std::uint16_t string_length = local_size - sizeof(error_code_attribute) + sizeof(stun_attribute);
        if (string_length == 0)
        {
            return {};
        }
        return std::string_view{ detail::get_bytes_after_as<const char>(this), string_length };
    }
}