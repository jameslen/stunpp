#include "stun_buffer.h"

#include <cassert>

#include "win32/message_fingerprint.h"

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

    constexpr bool is_stun_request(stunpp::stun_method msg_type)      noexcept { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0000; }
    constexpr bool is_stun_success_resp(stunpp::stun_method msg_type) noexcept { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0100; }
    constexpr bool is_stun_err_resp(stunpp::stun_method msg_type)     noexcept { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0110; }
    constexpr bool is_stun_indication(stunpp::stun_method msg_type)   noexcept { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0010; }

    constexpr uint16_t get_stun_request(stunpp::stun_method msg_type)      noexcept { return ((make_type(msg_type) & 0xFEEF)         ); }
    constexpr uint16_t get_stun_indication(stunpp::stun_method msg_type)   noexcept { return ((make_type(msg_type) & 0xFEEF) | 0x0010); }
    constexpr uint16_t get_stun_success_resp(stunpp::stun_method msg_type) noexcept { return ((make_type(msg_type) & 0xFEEF) | 0x0100); }
    constexpr uint16_t get_stun_err_resp(stunpp::stun_method msg_type)     noexcept { return ((make_type(msg_type)         ) | 0x0110); }

    constexpr std::uint32_t c_crcMask = 0xFFFFFFFFUL;

    const std::array<std::uint32_t,256> c_crctable{
      0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
      0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
      0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
      0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
      0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
      0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
      0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
      0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
      0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
      0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
      0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
      0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
      0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
      0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
      0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
      0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
      0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
      0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
      0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
      0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
      0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
      0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
      0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
      0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
      0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
      0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
      0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
      0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
      0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
      0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
      0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
      0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
    };

    std::uint32_t compute_crc32(
        std::span<std::byte> buffer
    ) noexcept
    {
        std::uint32_t crc = c_crcMask;
        for(auto&& byte : buffer)
        {
            crc = c_crctable[static_cast<std::uint8_t>(crc) ^ static_cast<std::uint8_t>(byte)] ^ (crc >> 8);
        }
        return (~crc);
    }
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

    std::string_view string_view_attribute::value() const noexcept
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

    std::span<const std::uint16_t> unknown_attribute_values::values() const noexcept
    {
        auto string_start = reinterpret_cast<const std::byte*>(this) + sizeof(stun_attribute);

        return { reinterpret_cast<const std::uint16_t*>(string_start), size };
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
        auto attr = add_attribute<ipv4_mapped_address_attribute>();

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
        auto attr = add_attribute<ipv6_mapped_address_attribute>();

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
        auto attr = add_attribute<ipv4_xor_mapped_address_attribute>();

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
        auto attr = add_attribute<ipv6_xor_mapped_address_attribute>();

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

    message_builder&& message_builder::add_error_code(
        stun_error_code /*error*/
    ) && noexcept
    {
        auto attr = add_attribute<error_code_attribute>();

        attr->size = sizeof(error_code_attribute) - sizeof(stun_attribute);

        // TODO: Error

        return std::move(*this);
    }

    message_builder&& message_builder::add_nonce(
        std::string_view nonce
    ) && noexcept
    {
        auto attr = add_attribute<nonce_attribute>(nonce.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), nonce.data(), nonce.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_software(
        std::string_view software
    )&& noexcept
    {
        auto attr = add_attribute<software_attribute>(software.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), software.data(), software.size());

        return std::move(*this);
    }

    message_builder&& message_builder::add_unknown_attributes(
        std::span<std::uint16_t> attributes
    ) && noexcept
    {
        auto attr = add_attribute<unknown_attribute_values>(attributes.size() * sizeof(std::uint16_t));

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), attributes.data(), attributes.size() * sizeof(std::uint16_t));

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
        std::string_view username,
        std::string_view realm,
        std::string_view password
    ) && noexcept
    {
        add_username(username);
        add_realm(realm);

        auto attr = add_attribute<message_integrity_attribute>();
        auto& header = get_header();
        header.message_length = m_buffer_used - sizeof(stun_header);
        auto buffer_used = m_buffer_used - sizeof(message_integrity_attribute);

        // The key for the HMAC depends on whether long-term or short-term
        // credentials are in use.  For long-term credentials, the key is 16
        // bytes:
        // 
        //          key = MD5(username ":" realm ":" SASLprep(password))
        // 
        // That is, the 16-byte key is formed by taking the MD5 hash of the
        // result of concatenating the following five fields: (1) the username,
        // with any quotes and trailing nulls removed, as taken from the
        // USERNAME attribute (in which case SASLprep has already been applied);
        // (2) a single colon; (3) the realm, with any quotes and trailing nulls
        // removed; (4) a single colon; and (5) the password, with any trailing
        // nulls removed and after processing using SASLprep.  For example, if
        // the username was 'user', the realm was 'realm', and the password was
        // 'pass', then the 16-byte HMAC key would be the result of performing
        // an MD5 hash on the string 'user:realm:pass', the resulting hash being
        // 0x8493fbc53ba582fb4c044c456bdc40eb.
        std::array<std::byte, 2048> key;
        assert(username.size() + realm.size() + password.size() + 2 <= key.size() && "Key buffer is too small");
        std::memcpy(key.data(), username.data(), username.size());
        key[username.size()] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + 1, realm.data(), realm.size());
        key[username.size() + realm.size() + 1] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + realm.size() + 2, password.data(), password.size());

        compute_integrity(
            attr->hmac_sha1,
            std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 },
            std::span<std::byte>{ m_message.data(), buffer_used }
        );

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
        std::string_view password
    ) && noexcept
    {
        auto attr = add_attribute<message_integrity_attribute>();
        auto& header = get_header();
        header.message_length = m_buffer_used - sizeof(stun_header);
        auto buffer_used = m_buffer_used - sizeof(message_integrity_attribute);

        // For short-term credentials:
        // 
        //                        key = SASLprep(password)
        // 
        // where MD5 is defined in RFC 1321 [RFC1321] and SASLprep() is defined
        // in RFC 4013 [RFC4013].
        compute_integrity(
            attr->hmac_sha1,
            std::span<const std::byte>{ reinterpret_cast<const std::byte*>(password.data()), password.size() },
            std::span<std::byte>{ m_message.data(), buffer_used }
        );

        return std::move(*this);
    }

    std::span<std::byte> message_builder::add_fingerprint(
    ) && noexcept
    {
        auto& header = get_header();
        header.message_length = m_buffer_used - sizeof(stun_header);

        auto crc = util::hton(compute_crc32({ m_message.data(), m_buffer_used - sizeof(fingerprint_attribute) }) ^ 0x5354554Elu);

        auto attr = add_attribute<fingerprint_attribute>();

        attr->value = crc;

        header.message_length = m_buffer_used - sizeof(stun_header);
        return { m_message.data(), m_buffer_used };
    }

    void message_builder::add_username(
        std::string_view username
    ) noexcept
    {
        auto attr = add_attribute<username_attribute>(username.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), username.data(), username.size());
    }

    void message_builder::add_realm(
        std::string_view realm
    ) noexcept
    {
        auto attr = add_attribute<realm_attribute>(realm.size());

        std::memcpy(reinterpret_cast<std::byte*>(attr) + sizeof(stun_attribute), realm.data(), realm.size());
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