#include "stun_message.h"

#include <cassert>
#include <system_error>
#include <ranges>


#include "win32/crypto_functions.h"

using namespace std::string_view_literals;
namespace
{
    constexpr stunpp::host_uint16_t c_method_mask = 0x0110;

    const std::array c_error_messages{
        std::pair{
            stunpp::stun_error_code::try_alternate,
            "The client should contact an alternate server for "
            "this request.This error response MUST only be sent if the "
            "request included a USERNAME attributeand a valid MESSAGE - "
            "INTEGRITY attribute; otherwise, it MUST NOT be sentand error "
            "code 400 (Bad Request) is suggested.This error response MUST "
            "be protected with the MESSAGE - INTEGRITY attribute,and receivers "
            "MUST validate the MESSAGE - INTEGRITY of this response before "
            "redirecting themselves to an alternate server."sv },
        std::pair{ 
            stunpp::stun_error_code::bad_request,
            "The request was malformed.The client SHOULD NOT "
            "retry the request without modification from the previous "
            "attempt.The server may not be able to generate a valid "
            "MESSAGE - INTEGRITY for this error, so the client MUST NOT expect "
            "a valid MESSAGE - INTEGRITY attribute on this response."sv },
        std::pair{ 
            stunpp::stun_error_code::unauthorized,
            "The request did not contain the correct "
            "credentials to proceed.The client should retry the request "
            "with proper credentials."sv },
        std::pair{ 
            stunpp::stun_error_code::forbidden,
            "The request was valid but cannot be performed due "
            "to administrative or similar restrictions."sv },
        std::pair{ 
            stunpp::stun_error_code::unknown_attribute,
            "The server received a STUN packet containing"
            "a comprehension - required attribute that it did not understand. "
            "The server MUST put this unknown attribute in the UNKNOWN - "
            "ATTRIBUTE attribute of its error response."sv },
        std::pair{ 
            stunpp::stun_error_code::allocation_mistmatch,
            "A request was received by the server that"
            "requires an allocation to be in place, but no allocation exists, "
            "or a request was received that requires no allocation, but an "
            "allocation exists."sv },
        std::pair{ 
            stunpp::stun_error_code::stale_nonce,
            "The NONCE used by the client was no longer valid. "
            "The client should retry, using the NONCE provided in the "
            "response."sv },
        std::pair{
            stunpp::stun_error_code::address_family_not_supported,
            "The server does not support the address family requested by the"
            "client."sv
        },
        std::pair{ 
            stunpp::stun_error_code::wrong_credentials,
            "The credentials in the(non - Allocate) "
            "request do not match those used to create the allocation."sv },
        std::pair{ 
            stunpp::stun_error_code::unsupported_transport_protocol,
            "The Allocate request asked the "
            "server to use a transport protocol between the serverand the peer "
            "that the server does not support.NOTE: This does NOT refer to "
            "the transport protocol used in the 5 - tuple."sv },
        std::pair{
            stunpp::stun_error_code::peer_address_family_mismatch,
            "A peer address is part of a different address family than that of"
            "the relayed transport address of the allocation."sv
        },
        std::pair{ 
            stunpp::stun_error_code::allocation_quota_reached,
            "No more allocations using this "
            "username can be created at the present time."sv },
        std::pair{
            stunpp::stun_error_code::role_conflict,
            "The client asserted an ICE role(controlling or "
            "controlled) that is in conflict with the role of the server."sv
        },
        std::pair{ 
            stunpp::stun_error_code::server_error,
            "Server Error : The server has suffered a temporary error. The "
            "client should try again."sv },
        std::pair{ 
            stunpp::stun_error_code::insufficient_capacity,
            "The server is unable to carry out the "
            "request due to some capacity limit being reached.In an Allocat e"
            "response, this could be due to the server having no more relayed "
            "transport addresses available at that time, having none with the "
            "requested properties, or the one that corresponds to the specified "
            "reservation token is not available."sv }
    };

    std::string_view get_error_message(stunpp::stun_error_code error) noexcept
    {
        for (auto& [code, message] : c_error_messages)
        {
            if (error == code)
            {
                return message;
            }
        }
        return {};
    }

    template <uint32_t round_value, std::integral value_t>
    constexpr [[nodiscard]] stunpp::util::host_ordered<value_t> round(stunpp::util::host_ordered<value_t> value) noexcept
    {
        value_t remainder = value % round_value;
        if (remainder != 0)
        {
            value += (round_value - remainder);
        }
        return value;
    }

    constexpr uint16_t encode_method(
        stunpp::stun_method method
    ) noexcept
    {
        auto stun_method = static_cast<uint16_t>(method) & 0x0FFF;
        return ((stun_method       & 0x000F) |
               ((stun_method << 1) & 0x00E0) |
               ((stun_method << 2) & 0x0E00) |
               ((stun_method << 2) & 0x3000)
        );
    }

    constexpr stunpp::net_uint16_t encode_message_type(stunpp::stun_method method, stunpp::stun_method_type type) noexcept
    {
        return stunpp::host_uint16_t(encode_method(method) | static_cast<uint16_t>(type));
    }

    constexpr stunpp::stun_method_type get_method_type(stunpp::net_uint16_t message_type) noexcept
    {
        return stunpp::stun_method_type(static_cast<stunpp::host_uint16_t>(message_type) & c_method_mask);
    }
    
    constexpr stunpp::stun_method get_method(stunpp::net_uint16_t message_type) noexcept
    {
        auto stun_method = stunpp::host_uint16_t(message_type) & 0xFEEF;
        return stunpp::stun_method(
                 (stun_method & 0x000F)       |
                ((stun_method & 0x00E0) >> 1) |
                ((stun_method & 0x0E00) >> 2) |
                ((stun_method & 0x3000) >> 2)
        );
    }

    constexpr std::uint32_t c_crcMask = 0xFFFFFFFFUL;

    constexpr std::array<std::uint32_t,256> c_crctable{
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

    stunpp::host_uint32_t compute_crc32(
        const stunpp::stun_header& header,
        std::span<const std::byte> buffer
    ) noexcept
    {
        std::uint32_t crc = c_crcMask;

        for (auto byte : std::span<const std::byte>(reinterpret_cast<const std::byte*>(&header), sizeof(stunpp::stun_header)))
        {
            crc = c_crctable[static_cast<std::uint8_t>(crc) ^ static_cast<std::uint8_t>(byte)] ^ (crc >> 8);
        }

        for(auto byte : buffer)
        {
            crc = c_crctable[static_cast<std::uint8_t>(crc) ^ static_cast<std::uint8_t>(byte)] ^ (crc >> 8);
        }
        return (~crc);
    }

    constexpr std::uint32_t crc_test()
    {
        std::uint32_t crc = c_crcMask;

        constexpr std::array buffer{
            std::byte{'1'}, std::byte{'2'}, std::byte{'3'},
            std::byte{'4'}, std::byte{'5'}, std::byte{'6'},
            std::byte{'7'}, std::byte{'8'}, std::byte{'9'}
        };

        for (auto byte : buffer)
        {
            crc = c_crctable[static_cast<std::uint8_t>(crc) ^ static_cast<std::uint8_t>(byte)] ^ (crc >> 8);
        }
        return (~crc);
    }

    static_assert(crc_test() == 0xcbf43926);
}

namespace stunpp
{
    namespace detail
    {
        void xor_map_ipv6_address(
            std::span<std::uint32_t, 4> dst,
            std::span<const std::uint32_t, 4> src,
            std::span<const uint32_t, 3> id
        ) noexcept
        {
            net_uint32_t magic_cookie = c_stun_magic_cookie;
            std::array<std::uint32_t, 4> xor_data{ magic_cookie.read(), id[0], id[1], id[2] };

            for (auto i = 0; i < 4; ++i)
            {
                dst[i] = src[i] ^ xor_data[i];
            }
        }
    }

    stun_method stun_header::get_method() const noexcept
    {
        return ::get_method(message_type);
    }

    stun_method_type stun_header::get_method_type() const noexcept
    {
        return ::get_method_type(message_type);
    }

    SOCKADDR_IN ipv4_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr.S_un.S_addr, address_bytes.data(), address_bytes.size());
        addr.sin_port = port.read();;
        return addr;
    }

    SOCKADDR_IN6 ipv6_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, address_bytes.data(), address_bytes.size());
        addr.sin6_port = port.read();
        return addr;
    }

    net_uint16_t xor_mapped_address_attribute::port() const noexcept
    {
        return port_bytes ^ host_uint16_t(c_stun_magic_cookie >> 16);
    }

    SOCKADDR_IN ipv4_xor_mapped_address_attribute::address() const noexcept
    {
        SOCKADDR_IN addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = (util::network_order_from_value(address_bytes) ^ c_stun_magic_cookie).read();
        addr.sin_port = port().read();
        return addr;
    }

    SOCKADDR_IN6 ipv6_xor_mapped_address_attribute::address(std::span<const std::uint32_t, 3> message_id) const noexcept
    {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        std::memcpy(addr.sin6_addr.u.Byte, address_bytes.data(), address_bytes.size());

        auto dst = reinterpret_cast<std::array<std::uint32_t, 4>*>(addr.sin6_addr.u.Byte);

        detail::xor_map_ipv6_address(*dst, address_bytes, message_id);

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
        if( string_length == 0 )
        {
            return {};
        }
        return std::string_view{ detail::get_bytes_after_as<const char>(this), string_length };
    }

    message_builder::message_builder(
        std::span<std::byte> buffer
    ) noexcept :
        m_message(buffer)
    {
        assert(buffer.size() > sizeof(stun_header) && "Buffer must be large enough for at least the STUN message header.");

        auto& header = get_header();
        header.message_length = util::network_order_from_value<std::uint16_t>(0);
        header.magic_cookie = host_uint32_t(c_stun_magic_cookie);

        header.transaction_id = generate_id();

        m_buffer_used = sizeof(stun_header);
    }

    message_builder message_builder::create_request(
        stun_method method,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = encode_message_type(method, stun_method_type::request);

        return builder;
    }

    message_builder message_builder::create_success_response(
        stun_method method,
        const std::array<std::uint32_t, 3>& transaction_id,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = encode_message_type(method, stun_method_type::success_response);
        header.transaction_id = transaction_id;

        return builder;
    }

    message_builder message_builder::create_error_response(
        stun_method method,
        const std::array<std::uint32_t, 3>& transaction_id,
        stun_error_code error,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = encode_message_type(method, stun_method_type::error_response);
        header.transaction_id = transaction_id;

        builder.add_error_code(error);

        return builder;
    }

    message_builder message_builder::create_indication(
        stun_method method,
        std::span<std::byte> buffer
    ) noexcept
    {
        message_builder builder(buffer);

        auto& header = builder.get_header();
        header.message_type = encode_message_type(method, stun_method_type::indication);

        return builder;
    }

    message_builder& message_builder::set_transaction_id(
        const std::array<std::uint32_t, 3>& transation_id
    ) noexcept
    {
        auto& header = get_header();
        header.transaction_id = transation_id;

        return *this;
    }

    message_builder& message_builder::set_padding_value(
        std::byte value
    ) noexcept
    {
        m_padding = value;

        return *this;
    }

    void message_builder::add_error_code(
        stun_error_code error
    ) noexcept
    {
        auto message = get_error_message(error);
        auto attr = internal_add_attribute<error_code_attribute>(message.size());

        auto hundreds = static_cast<uint32_t>(error) / 100;
        attr->class_bits = hundreds;

        std::uint8_t error_value = static_cast<uint32_t>(error) % 100;
        attr->number = error_value;

        attr->zero_bits = 0;

        std::memcpy(detail::get_bytes_after(attr), message.data(), message.size());
    }

    message_builder&& message_builder::add_integrity(
        std::string_view username,
        std::string_view nonce,
        std::string_view realm,
        std::string_view password
    ) & noexcept
    {
        add_attribute<username_attribute>(username);
        add_attribute<nonce_attribute>(nonce);
        add_attribute<realm_attribute>(realm);

        auto attr = internal_add_attribute<message_integrity_attribute>();
        auto& header = get_header();

        host_uint16_t message_length = m_buffer_used - sizeof(stun_header);
        header.message_length = message_length;

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
        attr->hmac_sha1 = {};
        compute_integrity(
            attr->hmac_sha1,
            compute_md5_hash(std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 }),
            header,
            { detail::get_bytes_after(&header), m_buffer_used - sizeof(stun_header) - sizeof(message_integrity_attribute) }
        );

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
        std::string_view username,
        std::string_view realm,
        std::string_view password
    ) & noexcept
    {
        add_attribute<username_attribute>(username);
        add_attribute<realm_attribute>(realm);

        host_uint16_t message_length = m_buffer_used - sizeof(stun_header);

        auto attr = internal_add_attribute<message_integrity_attribute>();
        auto& header = get_header();
        header.message_length = message_length;

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
            compute_md5_hash(std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 }),
            header,
            std::span<std::byte>{ detail::get_bytes_after(&header), message_length }
        );

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
        std::string_view username,
        std::string_view password
    ) & noexcept
    {
        add_attribute<username_attribute>(username);
        auto attr = internal_add_attribute<message_integrity_attribute>();
        auto& header = get_header();

        host_uint16_t message_length = m_buffer_used - sizeof(stun_header);
        header.message_length = message_length;

        // For short-term credentials:
        // 
        //                        key = SASLprep(password)
        // 
        // where MD5 is defined in RFC 1321 [RFC1321] and SASLprep() is defined
        // in RFC 4013 [RFC4013].
        attr->hmac_sha1 = {};
        compute_integrity(
            attr->hmac_sha1,
            { reinterpret_cast<const std::uint8_t*>(password.data()), password.size() },
            header,
            { detail::get_bytes_after(&header), m_buffer_used - sizeof(stun_header) - sizeof(message_integrity_attribute) }
        );

        return std::move(*this);
    }

    message_builder&& message_builder::add_integrity(
        std::string_view password
    ) & noexcept
    {
        auto attr = internal_add_attribute<message_integrity_attribute>();
        auto& header = get_header();

        host_uint16_t message_length = m_buffer_used - sizeof(stun_header);
        header.message_length = message_length;

        // For short-term credentials:
        // 
        //                        key = SASLprep(password)
        // 
        // where MD5 is defined in RFC 1321 [RFC1321] and SASLprep() is defined
        // in RFC 4013 [RFC4013].
        attr->hmac_sha1 = {};
        compute_integrity(
            attr->hmac_sha1,
            { reinterpret_cast<const std::uint8_t*>(password.data()), password.size() },
            header,
            { detail::get_bytes_after(&header), m_buffer_used - sizeof(stun_header) - sizeof(message_integrity_attribute) }
        );

        return std::move(*this);
    }

    std::span<std::byte> message_builder::add_fingerprint(
    ) && noexcept
    {
        auto attr = internal_add_attribute<fingerprint_attribute>();

        host_uint16_t message_length = m_buffer_used - sizeof(stun_header);

        auto& header = get_header();
        header.message_length = message_length;

        net_uint32_t crc = compute_crc32(header, { detail::get_bytes_after(&header), message_length - sizeof(fingerprint_attribute)}) ^ 0x5354554Elu;
        attr->value = crc;

        message_length = m_buffer_used - sizeof(stun_header);

        header.message_length = message_length;
        return { m_message.data(), m_buffer_used };
    }

    std::span<std::byte> message_builder::create() && noexcept
    {
        auto& header = get_header();
        header.message_length = host_uint16_t{ m_buffer_used - sizeof(stun_header) };
        return { m_message.data(), m_buffer_used };
    }

    stun_header& message_builder::get_header() noexcept
    {
        return *reinterpret_cast<stun_header*>(m_message.data());
    }

    stun_attribute_iterator& stun_attribute_iterator::operator++() noexcept
    {
        auto padded_size = round<4>(static_cast<host_uint16_t>(m_ptr->size));

        m_ptr = detail::get_bytes_after_as<const stun_attribute>(m_ptr, padded_size);

        return *this;
    }

    stun_attribute_iterator stun_attribute_iterator::operator++(int) noexcept
    {
        auto result = *this;
        ++(*this);
        return result;
    }

    message_reader::message_reader(
        std::span<const std::byte> buffer
    ) noexcept :
        m_message(buffer)
    {
    }

    std::expected<message_reader, std::error_code> message_reader::create(
        std::span<const std::byte> buffer
    ) noexcept
    {
        message_reader reader(buffer);

        auto ec = reader.validate();

        if (ec)
        {
            return std::unexpected(ec);
        }
        return reader;
    }

    std::error_code message_reader::validate() noexcept
    {
        // Start by verifying that the stun header can fit in the buffer
        if (m_message.size() < sizeof(stun_header))
        {
            return make_error_code(stun_validation_error::size_mismatch);
        }

        auto& header = get_header();

        // Ensure that this is a stun message by checking the magic cookie
        if (header.magic_cookie != c_stun_magic_cookie)
        {
            return make_error_code(stun_validation_error::not_stun_message);
        }

        host_uint16_t message_length = header.message_length;

        // Ensure that the header isn't lying about the size of the full message
        if (m_message.size() == sizeof(stun_header) && message_length != 0)
        {
            return make_error_code(stun_validation_error::size_mismatch);
        }
        else if (message_length + sizeof(stun_header) > m_message.size())
        {
            return make_error_code(stun_validation_error::size_mismatch);
        }

        // If there are no attributes then this packet is valid.
        if (header.message_length == 0)
        {
            return {};
        }

        uint16_t size = 0;

        auto attribute = detail::get_bytes_after_as<const stun_attribute>(&header);

        // Ensure that we don't read past the end of the buffer
        if (sizeof(stun_header) + sizeof(stun_attribute) >= m_message.size())
        {
            return stun_validation_error::size_mismatch;
        }

        m_begin = attribute;

        while (size < message_length)
        {
            auto padded_size = round<4>(static_cast<host_uint16_t>(attribute->size));
            size += sizeof(stun_attribute) + padded_size;

            if (size > message_length)
            {
                return make_error_code(stun_validation_error::size_mismatch);
            }
            else if (sizeof(stun_header) + size > m_message.size())
            {
                // Ensure that we don't read past the end of the buffer
                return make_error_code(stun_validation_error::size_mismatch);
            }

            if (attribute->type == stun_attribute_type::username)
            {
                m_username = static_cast<const username_attribute*>(attribute);
            }
            else if (attribute->type == stun_attribute_type::realm)
            {
                m_realm = static_cast<const realm_attribute*>(attribute);
            }
            else if (attribute->type == stun_attribute_type::nonce)
            {
                m_nonce = static_cast<const nonce_attribute*>(attribute);
            }
            else if (attribute->type == stun_attribute_type::message_integrity)
            {
                m_integrity = static_cast<const message_integrity_attribute*>(attribute);
            }
            else if (attribute->type == stun_attribute_type::fingerprint)
            {
                // We're going to modify the header to be able to recreate the crc without copying the whole packet
                auto edit_header = header;

                // Remove payload of the fingerprint attribute for the computation of the crc
                host_uint16_t local_message_length = size;
                edit_header.message_length = local_message_length;

                auto crc = compute_crc32(edit_header, { detail::get_bytes_after(&header), static_cast<size_t>(size - sizeof(stun_attribute) - padded_size) }) ^ 0x5354554Elu;

                auto* fingerprint = static_cast<const fingerprint_attribute*>(attribute);

                // We ignore all attributes after the fingerprint. So either return validation failed or the result
                if (fingerprint->value != crc)
                {
                    return make_error_code(stun_validation_error::fingerprint_failed);
                }

                attribute = detail::get_bytes_after_as<const stun_attribute>(attribute, padded_size);
                break;
            }

            // TODO: Lifetimes
            attribute = detail::get_bytes_after_as<const stun_attribute>(attribute, padded_size);
        }

        m_end = attribute;
        return {};
    }

    std::error_code message_reader::check_integrity(std::string_view password)
    {
        // If there's no integrity attribute then return valid.
        if (!m_integrity)
        {
            return make_error_code(stun_validation_error::integrity_attribute_not_found);
        }

        bool short_term_credentials = !m_username || !m_realm;

        if(!short_term_credentials)
        {
            if (!m_username)
            {
                return make_error_code(stun_validation_error::username_attribute_not_found);
            }
            if (!m_realm)
            {
                return make_error_code(stun_validation_error::realm_attribute_not_found);
            }
        }

        auto& header = get_header();

        host_uint16_t size = 0;
        const stun_attribute* attribute = detail::get_bytes_after_as<const stun_attribute>(&header);

        // Ensure that we don't read past the end of the buffer
        if (sizeof(stun_header) + sizeof(stun_attribute) >= m_message.size())
        {
            return make_error_code(stun_validation_error::size_mismatch);
        }

        host_uint16_t message_length = header.message_length;
        while (size < message_length)
        {
            std::uint16_t padded_size = sizeof(stun_attribute) + round<4>(static_cast<host_uint16_t>(attribute->size));

            size += padded_size;

            if (attribute->type == stun_attribute_type::message_integrity)
            {
                break;
            }

            // Ensure that we don't read past the end of the buffer
            if (sizeof(stun_header) + size >= m_message.size())
            {
                return make_error_code(stun_validation_error::size_mismatch);
            }

            attribute = detail::get_bytes_after_as<const stun_attribute>(&header, size);
        }

        std::array<std::byte, 20> hmac;

        auto edit_header = header;
        edit_header.message_length = size;

        if (short_term_credentials)
        {
            compute_integrity(
                hmac,
                { reinterpret_cast<const std::uint8_t*>(password.data()), password.size() },
                edit_header,
                std::span<const std::byte>{ detail::get_bytes_after(&header), size - sizeof(message_integrity_attribute) }
            );
        }
        else
        {
            auto username = m_username->value();
            auto realm = m_realm->value();

            std::array<std::byte, 2048> key;
            assert(username.size() + realm.size() + password.size() + 2 <= key.size() && "Key buffer is too small");
            std::memcpy(key.data(), username.data(), username.size());
            key[username.size()] = std::byte{ ':' };
            std::memcpy(key.data() + username.size() + 1, realm.data(), realm.size());
            key[username.size() + realm.size() + 1] = std::byte{ ':' };
            std::memcpy(key.data() + username.size() + realm.size() + 2, password.data(), password.size());

            compute_integrity(
                hmac,
                compute_md5_hash(std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 }),
                edit_header,
                std::span<const std::byte>{ detail::get_bytes_after(&header), size - sizeof(message_integrity_attribute) }
            );
        }
        

        if (hmac == m_integrity->hmac_sha1)
        {
            return {};
        }
        else
        {
            return make_error_code(stun_validation_error::integrity_check_failed);
        }
    }

    const stun_header& message_reader::get_header() const noexcept
    {
        return *reinterpret_cast<const stun_header*>(m_message.data());
    }

}