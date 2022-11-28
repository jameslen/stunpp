#pragma once

#include <cassert>

#include <bcrypt.h>

constexpr inline bool NT_SUCCESS(NTSTATUS status) { return status >= 0; }

namespace stunpp
{
	void compute_integrity(std::array<std::byte, 20>& hmac, std::span<const std::byte> key, std::span<const std::byte> data)
	{
        auto md5_key_hash = [&]()
        {
            BCRYPT_ALG_HANDLE alg_handle{};
            auto res = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_MD5_ALGORITHM, nullptr, 0);
            assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
            std::ignore = res;

            ULONG data_temp{};
            DWORD hash_object_size{};
            res = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
            assert(NT_SUCCESS(res) && "Failed to query object length");
            std::ignore = res;
            std::array<std::byte, 1024> hash_object_buffer{};
            assert(hash_object_size <= hash_object_buffer.size() && "Hash object larger than buffer");

            DWORD hash_size{};
            res = BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &data_temp, 0);
            assert(NT_SUCCESS(res) && "Failed to query hash length");
            std::ignore = res;
            std::array<uint8_t, 16> hash_buffer{};
            assert(hash_size <= hash_buffer.size() && "Hash size larger than buffer");

            BCRYPT_HASH_HANDLE hash_handle{};
            res = BCryptCreateHash(alg_handle, &hash_handle, reinterpret_cast<PUCHAR>(hash_object_buffer.data()), hash_object_size, nullptr, 0, 0);
            assert(NT_SUCCESS(res) && "Failed to create hash object");
            std::ignore = res;

            res = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), data.size(), 0);
            assert(NT_SUCCESS(res) && "Failed to hash data");
            std::ignore = res;

            res = BCryptFinishHash(hash_handle, hash_buffer.data(), hash_buffer.size(), 0);
            assert(NT_SUCCESS(res) && "Failed to finish hash");
            std::ignore = res;

            BCryptCloseAlgorithmProvider(alg_handle, 0);
            BCryptDestroyHash(hash_handle);

            return hash_buffer;
        }();

        [&]()
        {
            BCRYPT_ALG_HANDLE alg_handle{};
            auto res = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            assert(NT_SUCCESS(res) && "Failed to open Crypto Provider");
            std::ignore = res;

            ULONG data_temp{};
            DWORD hash_object_size{};
            res = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_object_size, sizeof(DWORD), &data_temp, 0);
            assert(NT_SUCCESS(res) && "Failed to query object length");
            std::ignore = res;
            std::array<std::byte, 1024> hash_object_buffer{};
            assert(hash_object_size <= hash_object_buffer.size() && "Hash object larger than buffer");

            DWORD hash_size{};
            res = BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &data_temp, 0);
            assert(NT_SUCCESS(res) && "Failed to query hash length");
            std::ignore = res;
            assert(hash_size <= hmac.size() && "Hash size larger than buffer");

            BCRYPT_HASH_HANDLE hash_handle{};
            res = BCryptCreateHash(alg_handle, &hash_handle, reinterpret_cast<PUCHAR>(hash_object_buffer.data()), hash_object_size, md5_key_hash.data(), md5_key_hash.size(), 0);
            assert(NT_SUCCESS(res) && "Failed to create hash object");
            std::ignore = res;

            res = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), data.size(), 0);
            assert(NT_SUCCESS(res) && "Failed to hash data");
            std::ignore = res;

            res = BCryptFinishHash(hash_handle, reinterpret_cast<PUCHAR>(hmac.data()), hmac.size(), 0);
            assert(NT_SUCCESS(res) && "Failed to finish hash");
            std::ignore = res;

            BCryptCloseAlgorithmProvider(alg_handle, 0);
            BCryptDestroyHash(hash_handle);
        }();
	}

    std::array<uint32_t, 3> generate_id()
    {
        std::array<uint32_t, 3> id;
        auto res = BCryptGenRandom(nullptr, (PUCHAR)id.data(), sizeof(id), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        assert(NT_SUCCESS(res) && "Failed to generate random numbers");
        std::ignore = res;

        return id;
    }
}