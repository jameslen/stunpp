#include "stun_password_generator.h"

#include <cassert>

#include "stun_message_types.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

namespace
{
    constexpr inline bool NT_SUCCESS(NTSTATUS status) { return status >= 0; }

    template<size_t hmac_size>
    void compute_integrity(
        BCRYPT_ALG_HANDLE alg_handle,
        std::array<std::byte, hmac_size>& hmac,
        std::span<const std::uint8_t> key,
        const stunpp::stun_header& header,
        std::span<const std::byte> data
    )
    {
        BCRYPT_HASH_HANDLE hash_handle{};
        std::array<std::uint8_t, 1024> hash_object_buffer{};

        ULONG data_temp{};
        DWORD hash_object_size{};
        auto res = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query object length");
        std::ignore = res;
        assert(hash_object_size <= hash_object_buffer.size() && "Hash object larger than buffer");

        DWORD hash_size{};
        res = BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query hash length");
        std::ignore = res;
        assert(hash_size <= hmac.size() && "Hash size larger than buffer");

        res = BCryptCreateHash(
            alg_handle,
            &hash_handle,
            reinterpret_cast<PUCHAR>(hash_object_buffer.data()), hash_object_size,
            const_cast<std::uint8_t*>(key.data()), static_cast<ULONG>(key.size()),
            BCRYPT_HASH_REUSABLE_FLAG
        );
        assert(NT_SUCCESS(res) && "Failed to create hash object");
        std::ignore = res;

        res = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(const_cast<stunpp::stun_header*>(&header)), sizeof(header), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");

        res = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");
        std::ignore = res;

        res = BCryptFinishHash(hash_handle, reinterpret_cast<PUCHAR>(hmac.data()), static_cast<ULONG>(hmac.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to finish hash");
        std::ignore = res;

        BCryptDestroyHash(hash_handle);
    }

    void create_password_hash_structures(
        BCRYPT_ALG_HANDLE& alg_handle,
        BCRYPT_HASH_HANDLE& hash_handle,
        std::array<std::uint8_t, 1024>& buffer,
        const wchar_t* algorithm
    )
    {
        auto res = BCryptOpenAlgorithmProvider(&alg_handle, algorithm, nullptr, 0);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;

        ULONG data_temp{};
        DWORD hash_object_size{};
        res = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query object length");
        std::ignore = res;
        assert(hash_object_size <= buffer.size() && "Hash object larger than buffer");

        res = BCryptCreateHash(
            alg_handle,
            &hash_handle,
            reinterpret_cast<PUCHAR>(buffer.data()),
            hash_object_size,
            nullptr,
            0,
            BCRYPT_HASH_REUSABLE_FLAG
        );
        assert(NT_SUCCESS(res) && "Failed to create hash object");
        std::ignore = res;
    }

    template <size_t key_size>
    std::array<std::uint8_t, key_size> compute_hash(
        BCRYPT_HASH_HANDLE hash_handle,
        std::span<const std::byte> key
    )
    {
        std::array<uint8_t, key_size> hash_buffer{};

        auto res = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(key.data())), static_cast<ULONG>(key.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");

        res = BCryptFinishHash(hash_handle, hash_buffer.data(), static_cast<ULONG>(hash_buffer.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to finish hash");
        std::ignore = res;

        return hash_buffer;
    }
}

namespace stunpp
{
    stun_password_generator::stun_password_generator() noexcept
    {
        create_password_hash_structures(
            md5_alg_handle,
            md5_hash_handle,
            md5_hash_object_buffer,
            BCRYPT_MD5_ALGORITHM
        );

        create_password_hash_structures(
            sha256_alg_handle,
            sha256_hash_handle,
            sha256_hash_object_buffer,
            BCRYPT_SHA256_ALGORITHM
        );

        auto res = BCryptOpenAlgorithmProvider(&sha1hmac_alg_handle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;

        res = BCryptOpenAlgorithmProvider(&sha256hmac_alg_handle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;
    }

    stun_password_generator::~stun_password_generator() noexcept
    {
        BCryptDestroyHash(md5_hash_handle);
        BCryptCloseAlgorithmProvider(md5_alg_handle, 0);
        BCryptDestroyHash(sha256_hash_handle);
        BCryptCloseAlgorithmProvider(sha256_alg_handle, 0);
        BCryptCloseAlgorithmProvider(sha1hmac_alg_handle, 0);
        BCryptCloseAlgorithmProvider(sha256hmac_alg_handle, 0);
    }

    std::span<const std::uint8_t> stun_password_generator::generate_short_term_key(std::string_view password) const noexcept
    {
        return std::span<const std::uint8_t>{ reinterpret_cast<const std::uint8_t*>(password.data()), password.size() };
    }

    std::array<std::uint8_t, 16> stun_password_generator::generate_long_term_md5_key(
        std::string_view username,
        std::string_view realm,
        std::string_view password
    ) const noexcept
    {
        std::array<std::byte, 2048> key;
        assert(username.size() + realm.size() + password.size() + 2 <= key.size() && "Key buffer is too small");
        std::memcpy(key.data(), username.data(), username.size());
        key[username.size()] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + 1, realm.data(), realm.size());
        key[username.size() + realm.size() + 1] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + realm.size() + 2, password.data(), password.size());

        return compute_hash<16>(md5_hash_handle, std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 });
    }

    std::array<std::uint8_t, 32> stun_password_generator::generate_long_term_sha256_key(
        std::string_view username,
        std::string_view realm,
        std::string_view password
    ) const noexcept
    {
        std::array<std::byte, 2048> key;
        assert(username.size() + realm.size() + password.size() + 2 <= key.size() && "Key buffer is too small");
        std::memcpy(key.data(), username.data(), username.size());
        key[username.size()] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + 1, realm.data(), realm.size());
        key[username.size() + realm.size() + 1] = std::byte{ ':' };
        std::memcpy(key.data() + username.size() + realm.size() + 2, password.data(), password.size());

        return compute_hash<32>(sha256_hash_handle, std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 });
    }

    void stun_password_generator::compute_integrity_sha1(
        std::array<std::byte, 20>& hmac,
        std::span<const std::uint8_t> key,
        const stun_header& header,
        std::span<const std::byte> data
    ) const noexcept
    {
        compute_integrity(
            sha1hmac_alg_handle,
            hmac,
            key,
            header,
            data
        );
    }

    void stun_password_generator::compute_integrity_sha256(
        std::array<std::byte, 32>& hmac,
        std::span<const std::uint8_t> key,
        const stun_header& header,
        std::span<const std::byte> data
    ) const noexcept
    {
        compute_integrity(
            sha256hmac_alg_handle,
            hmac,
            key,
            header,
            data
        );
    }

    std::array<uint32_t, 3> stun_password_generator::generate_id() noexcept
    {
        std::array<uint32_t, 3> id;
        auto res = BCryptGenRandom(nullptr, (PUCHAR)id.data(), sizeof(id), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        assert(NT_SUCCESS(res) && "Failed to generate random numbers");
        std::ignore = res;

        return id;
    }
}