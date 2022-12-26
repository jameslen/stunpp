#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <span>

typedef void* BCRYPT_ALG_HANDLE;
typedef void* BCRYPT_HASH_HANDLE;

namespace stunpp
{
    struct stun_header;

    class stun_password_generator
    {
    public:
        stun_password_generator() noexcept;
        ~stun_password_generator() noexcept;

        // For short - term credentials, the Hash - Based Message Authentication
        //     Code(HMAC) key is defined as follow :
        // 
        // key = OpaqueString(password)
        std::span<const std::uint8_t> generate_short_term_key(
            std::string_view password
        ) const noexcept;

        // This password algorithm is taken from[RFC1321].
        // 
        // The key length is 16 bytes, and the parameters value is empty.
        // 
        // Note: This algorithm MUST only be used for compatibility with
        // legacy systems.
        // 
        // key = MD5(username ":" OpaqueString(realm)
        //     ":" OpaqueString(password))
        std::array<std::uint8_t, 16> generate_long_term_md5_key(
            std::string_view username,
            std::string_view realm,
            std::string_view password
        ) const noexcept;

        // This password algorithm is taken from[RFC7616].
        // 
        // The key length is 32 bytes, and the parameters value is empty.
        // 
        // key = SHA-256(username ":" OpaqueString(realm)
        //     ":" OpaqueString(password))
        std::array<std::uint8_t, 32> generate_long_term_sha256_key(
            std::string_view username,
            std::string_view realm,
            std::string_view password
        ) const noexcept;

        void compute_integrity_sha1(
            std::array<std::byte, 20>& hmac,
            std::span<const std::uint8_t> key,
            const stun_header& header,
            std::span<const std::byte> data
        ) const noexcept;

        void compute_integrity_sha256(
            std::array<std::byte, 32>& hmac,
            std::span<const std::uint8_t> key,
            const stun_header& header,
            std::span<const std::byte> data
        ) const noexcept;

        static std::array<uint32_t, 3> generate_id() noexcept;

    private:
        BCRYPT_ALG_HANDLE md5_alg_handle{};
        BCRYPT_HASH_HANDLE md5_hash_handle{};
        std::array<std::uint8_t, 1024> md5_hash_object_buffer{};

        BCRYPT_ALG_HANDLE sha256_alg_handle{};
        BCRYPT_HASH_HANDLE sha256_hash_handle{};
        std::array<std::uint8_t, 1024> sha256_hash_object_buffer{};

        BCRYPT_ALG_HANDLE sha1hmac_alg_handle{};

        BCRYPT_ALG_HANDLE sha256hmac_alg_handle{};
    };
}