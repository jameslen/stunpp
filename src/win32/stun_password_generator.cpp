#include "stun_password_generator.h"

#include <cassert>

#include "stun_message_types.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

namespace
{
    constexpr inline bool NT_SUCCESS(NTSTATUS status) { return status >= 0; }
}

namespace stunpp
{
    stun_password_generator::stun_password_generator() noexcept
    {
        auto res = BCryptOpenAlgorithmProvider(&md5_alg_handle, BCRYPT_MD5_ALGORITHM, nullptr, 0);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;

        ULONG data_temp{};
        DWORD hash_object_size{};
        res = BCryptGetProperty(md5_alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query object length");
        std::ignore = res;
        assert(hash_object_size <= md5_hash_object_buffer.size() && "Hash object larger than buffer");

        res = BCryptCreateHash(
            md5_alg_handle,
            &md5_hash_handle,
            reinterpret_cast<PUCHAR>(md5_hash_object_buffer.data()),
            hash_object_size,
            nullptr,
            0,
            0);
        assert(NT_SUCCESS(res) && "Failed to create hash object");
        std::ignore = res;

        res = BCryptOpenAlgorithmProvider(&sha1hmac_alg_handle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;

        res = BCryptOpenAlgorithmProvider(&sha256hamc_alg_handle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
        std::ignore = res;
    }

    stun_password_generator::~stun_password_generator() noexcept
    {

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

        return compute_md5_hash(std::span<std::byte>{ key.data(), username.size() + realm.size() + password.size() + 2 });
    }

    std::array<std::uint8_t, 16> stun_password_generator::compute_md5_hash(std::span<const std::byte> key) const noexcept
    {
        std::array<uint8_t, 16> hash_buffer{};

        auto res = BCryptHashData(md5_hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(key.data())), static_cast<ULONG>(key.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");

        res = BCryptFinishHash(md5_hash_handle, hash_buffer.data(), static_cast<ULONG>(hash_buffer.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to finish hash");
        std::ignore = res;

        return hash_buffer;
    }

    void stun_password_generator::compute_integrity_sha1(
        std::array<std::byte, 20>& hmac,
        std::span<const std::uint8_t> key,
        const stun_header& header,
        std::span<const std::byte> data
    ) const noexcept
    {
        BCRYPT_HASH_HANDLE sha1hmac_hash_handle{};
        std::array<std::uint8_t, 1024> sha1hmac_hash_object_buffer{};

        ULONG data_temp{};
        DWORD hash_object_size{};
        auto res = BCryptGetProperty(sha1hmac_alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query object length");
        std::ignore = res;
        assert(hash_object_size <= sha1hmac_hash_object_buffer.size() && "Hash object larger than buffer");

        DWORD hash_size{};
        res = BCryptGetProperty(sha1hmac_alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query hash length");
        std::ignore = res;
        assert(hash_size <= hmac.size() && "Hash size larger than buffer");

        res = BCryptCreateHash(
            sha1hmac_alg_handle,
            &sha1hmac_hash_handle,
            reinterpret_cast<PUCHAR>(sha1hmac_hash_object_buffer.data()), hash_object_size,
            const_cast<std::uint8_t*>(key.data()), static_cast<ULONG>(key.size()),
            BCRYPT_HASH_REUSABLE_FLAG
        );
        assert(NT_SUCCESS(res) && "Failed to create hash object");
        std::ignore = res;

        
        res = BCryptHashData(sha1hmac_hash_handle, reinterpret_cast<PUCHAR>(const_cast<stun_header*>(&header)), sizeof(header), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");

        res = BCryptHashData(sha1hmac_hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");
        std::ignore = res;

        res = BCryptFinishHash(sha1hmac_hash_handle, reinterpret_cast<PUCHAR>(hmac.data()), static_cast<ULONG>(hmac.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to finish hash");
        std::ignore = res;

        BCryptDestroyHash(sha1hmac_hash_handle);
    }

    void stun_password_generator::compute_integrity_sha256(
        std::array<std::byte, 32>& hmac,
        std::span<const std::uint8_t> key,
        const stun_header& header,
        std::span<const std::byte> data
    ) const noexcept
    {
        BCRYPT_HASH_HANDLE sha256hmac_hash_handle{};
        std::array<std::uint8_t, 1024> sha256hmac_hash_object_buffer{};

        ULONG data_temp{};
        DWORD hash_object_size{};
        auto res = BCryptGetProperty(sha256hamc_alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query object length");
        std::ignore = res;
        assert(hash_object_size <= sha256hmac_hash_object_buffer.size() && "Hash object larger than buffer");

        DWORD hash_size{};
        res = BCryptGetProperty(sha256hamc_alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &data_temp, 0);
        assert(NT_SUCCESS(res) && "Failed to query hash length");
        std::ignore = res;
        assert(hash_size <= hmac.size() && "Hash size larger than buffer");

        res = BCryptCreateHash(
            sha256hamc_alg_handle,
            &sha256hmac_hash_handle,
            reinterpret_cast<PUCHAR>(sha256hmac_hash_object_buffer.data()), hash_object_size,
            const_cast<std::uint8_t*>(key.data()), static_cast<ULONG>(key.size()),
            BCRYPT_HASH_REUSABLE_FLAG
        );
        assert(NT_SUCCESS(res) && "Failed to create hash object");
        std::ignore = res;

        res = BCryptHashData(sha256hmac_hash_handle, reinterpret_cast<PUCHAR>(const_cast<stun_header*>(&header)), sizeof(header), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");

        res = BCryptHashData(sha256hmac_hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to hash data");
        std::ignore = res;

        res = BCryptFinishHash(sha256hmac_hash_handle, reinterpret_cast<PUCHAR>(hmac.data()), static_cast<ULONG>(hmac.size()), 0);
        assert(NT_SUCCESS(res) && "Failed to finish hash");
        std::ignore = res;

        BCryptDestroyHash(sha256hmac_hash_handle);
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