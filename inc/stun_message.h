// https://datatracker.ietf.org/doc/html/rfc5389
#pragma once

#include <cassert>
#include <expected>

#include "stun_error_category.h"
#include "stun_message_types.h"

namespace stunpp
{
    namespace detail
    {
        template <typename T>
        std::span<std::byte> to_byte_span(T* ptr)
        {
            return std::span<std::byte>(reinterpret_cast<std::byte*>(ptr), sizeof(T));
        }

        template <typename T>
        std::span<const std::byte> to_byte_span(const T* ptr)
        {
            return std::span<const std::byte>(reinterpret_cast<const std::byte*>(ptr), sizeof(T));
        }

        template <typename T>
        concept stun_attribute = requires (T t) {
            std::is_base_of_v<stunpp::stun_attribute, T>;
        };

        template <typename T>
        constexpr bool is_simple_stun_attribute = sizeof(T) == sizeof(stunpp::stun_attribute) &&
            std::is_base_of_v<stunpp::stun_attribute, T> &&
            !std::is_base_of_v<string_view_attribute, T> &&
            !std::is_base_of_v<iterable_base_attribute, T> &&
            !std::is_base_of_v<value_base_attribute, T>;

        template <typename T>
        concept simple_stun_attribute = is_simple_stun_attribute<T>;
    }

    struct message_builder;

    template <typename attribute_t>
        requires requires { 
            typename attribute_t::value_t; 
         }
    struct attribute_builder
    {
        attribute_builder& append(
            const typename attribute_t::value_t& value
        ) noexcept
        {
            attribute->size += builder.append(detail::to_byte_span(&value));

            return *this;
        }

        message_builder& end() noexcept
        {
            return builder;
        }

        attribute_t* attribute;
        message_builder* builder;
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
            std::span<std::byte> buffer
        ) noexcept;

        static message_builder create_indication(
            stun_method method,
            std::span<std::byte> buffer
        ) noexcept;

        // This method should not generally be called. It is primarily here for testing
        message_builder& set_transaction_id(
            const std::array<std::uint32_t, 3>& transaction_id
        ) noexcept;

        // This is only intended to be used for the tests where the padding values are non-zero
        message_builder& set_padding_value(
            std::byte value
        ) noexcept;

        template<detail::stun_attribute attribute_t>
            requires std::is_base_of_v<string_view_attribute, attribute_t>
        message_builder& add_attribute(std::string_view value) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>(value.size());

            std::memcpy(detail::get_bytes_after(attr), value.data(), value.size());

            return *this;
        }

        template<detail::stun_attribute attribute_t>
            requires std::is_base_of_v<ipv4_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(const SOCKADDR_IN& address) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv4;
            attr->port = address.sin_port;
            std::memcpy(attr->address_bytes.data(), &address.sin_addr, attr->address_bytes.size());

            return *this;
        }

        template<detail::stun_attribute attribute_t>
            requires std::is_base_of_v<ipv6_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(const SOCKADDR_IN6& address) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv6;
            attr->port = address.sin6_port;
            std::memcpy(attr->address_bytes.data(), &address.sin6_addr, attr->address_bytes.size());

            return *this;
        }

        template<detail::stun_attribute attribute_t>
            requires std::is_base_of_v<ipv4_xor_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(
            const SOCKADDR_IN& address
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv4;

            attr->port_bytes = util::network_order_from_value(address.sin_port) ^ static_cast<host_uint16_t>(c_stun_magic_cookie >> 16);

            attr->address_bytes = (util::network_order_from_value<std::uint32_t>(address.sin_addr.S_un.S_addr) ^ c_stun_magic_cookie).read();

            return *this;
        }

        template<detail::stun_attribute attribute_t>
            requires std::is_base_of_v<ipv6_xor_mapped_address_attribute, attribute_t>
        message_builder& add_attribute(
            const SOCKADDR_IN6& address
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->family = address_family::ipv6;

            attr->port_bytes = util::network_order_from_value(address.sin6_port) ^ static_cast<host_uint16_t>(c_stun_magic_cookie >> 16);

            constexpr net_uint32_t magic_cookie = c_stun_magic_cookie;

            auto src = reinterpret_cast<const std::array<const std::uint32_t, 4>*>(address.sin6_addr.u.Byte);
            
            auto& id = get_header().transaction_id;

            detail::xor_map_ipv6_address(attr->address_bytes, *src, id);

            return *this;
        }

        template<detail::stun_attribute attribute_t, typename data_t>
        message_builder& add_attribute(
            std::span<const data_t> data
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>(data.size_bytes());

            std::memcpy(detail::get_bytes_after<stun_attribute>(attr), data.data(), data.size() * sizeof(data_t));

            return *this;
        }

        template<detail::stun_attribute attribute_t, std::integral data_t>
            requires std::is_base_of_v<integral_attribute<data_t>, attribute_t>
        message_builder& add_attribute(
            util::host_ordered<data_t> data
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->value = data;

            return *this;
        }

        template<detail::stun_attribute attribute_t, typename data_t>
            requires std::is_base_of_v<enum_attribute<data_t>, attribute_t>
        message_builder& add_attribute(
            data_t data
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            attr->value = data;

            return *this;
        }

        template<detail::stun_attribute attribute_t>
            requires requires {
                std::is_base_of_v<iterable_base_attribute, attribute_t>;
                std::is_base_of_v<iterable_attribute<typename attribute_t::value_t>, attribute_t>;
            }
        attribute_builder<attribute_t> add_attribute(
        ) noexcept
        {
            auto attr = internal_add_attribute<attribute_t>();

            return attribute_builder<attribute_t>{attr, *this};
        }

        template<detail::simple_stun_attribute attribute_t>
        message_builder& add_attribute() noexcept
        {
            std::ignore = internal_add_attribute<attribute_t>();

            return *this;
        }

        message_builder& add_error_attribute(stun_error_code error) noexcept;
        message_builder& add_address_error_attribute(address_family family, stun_error_code error) noexcept;

        message_builder& add_icmp_attribute(uint16_t type, uint16_t code, const std::array<std::byte, 4>& data) noexcept;

        message_builder&& add_short_term_integrity(std::string_view password) & noexcept;
        message_builder&& add_long_term_integrity(std::span<const std::uint8_t> key) & noexcept;

        std::span<std::byte> add_fingerprint() && noexcept;
        std::span<std::byte> create() && noexcept;

        std::uint16_t append(std::span<const std::byte> data) noexcept;

        static std::array<std::uint8_t, 16> generate_md5_key(std::string_view username, std::string_view realm, std::string_view password) noexcept;
    private:
        std::uint16_t m_buffer_used{0};
        std::span<std::byte> m_message;
        std::byte m_padding{ 0 };

        stun_header& get_header() noexcept;

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
                std::memset(m_message.data() + m_buffer_used - (4 - remainder), static_cast<int>(m_padding), 4 - remainder);
            }

            return attr;
        }
    };

    struct stun_attribute_iterator
    {
        using iterator_concept = std::forward_iterator_tag;
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = const stun_attribute;
        using pointer = const value_type*;
        using reference = const value_type&;

        stun_attribute_iterator() noexcept = default;

        stun_attribute_iterator(const stun_attribute* ptr) noexcept : m_ptr{ ptr } {}

        inline reference operator*() const noexcept { return *m_ptr; }
        inline pointer operator->() noexcept { return m_ptr; }

        stun_attribute_iterator& operator++() noexcept;
        stun_attribute_iterator operator++(int) noexcept;

        bool operator==(const stun_attribute_iterator& rhs) const noexcept { return m_ptr == rhs.m_ptr; }

        template<typename T>
        const T* as() const noexcept { assert(m_ptr->type == T::c_type);  return static_cast<const T*>(m_ptr); }
    private:
        const stun_attribute* m_ptr;
    };

    struct message_reader
    {
        static std::expected<message_reader, std::error_code> create(
            std::span<const std::byte> buffer
        ) noexcept;

        const stun_header& get_header() const noexcept;

        bool has_integrity() const noexcept { return m_integrity != nullptr; }
        const username_attribute* get_username() const noexcept { return m_username; }
        const realm_attribute* get_realm() const noexcept { return m_realm; }
        const nonce_attribute* get_nonce() const noexcept { return m_nonce; }
        std::error_code check_integrity(std::string_view password);

        inline auto begin() const noexcept { return m_begin; }
        inline auto end() const noexcept { return m_end; }

    private:
        message_reader(
            std::span<const std::byte> buffer
        ) noexcept;


        std::error_code validate() noexcept;
     
        std::span<const std::byte> m_message;
        stun_attribute_iterator m_begin{};
        stun_attribute_iterator m_end{};

        const username_attribute* m_username{};
        const realm_attribute* m_realm{};
        const nonce_attribute* m_nonce{};
        const message_integrity_attribute* m_integrity{};

    };
}