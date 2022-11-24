/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cstddef>
#include <cstdint>
#include <WinSock2.h>
#include <ws2ipdef.h>

#include "stun_buffer2.h"

#include <random>

//#include <openssl/md5.h>
//#include <openssl/hmac.h>
//#include <openssl/err.h>

namespace
{
    constexpr size_t c_stunMagicCookie = 0x2112A442;
    constexpr size_t c_stunDefaultAllocateLifetime = 600;
    constexpr size_t c_maxSHASize = 128;
    constexpr size_t c_messageIdOffset = 8;

    constexpr size_t c_sha1SizeBytes = 20;
    constexpr size_t c_sha256SizeBytes = 32;
    constexpr size_t c_sha384SizeBytes = 48;
    constexpr size_t c_sha512SizeBytes = 64;

    constexpr bool IsValidStunChannel(uint16_t chn) noexcept { return ((chn) >= 0x4000 && (chn) <= 0x7FFF); }

    constexpr uint16_t make_type(
        StunMethod method
    ) noexcept
    {
        uint16_t stunMethod = static_cast<uint16_t>(method) & 0x0FFF;
        return ((stunMethod & 0x000F) | ((stunMethod & 0x0070) << 1) | ((stunMethod & 0x0380) << 2) | ((stunMethod & 0x0C00) << 2));
    }

    constexpr bool IS_STUN_REQUEST(StunMethod msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0000; }
    constexpr bool IS_STUN_SUCCESS_RESP(StunMethod msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0100; }
    constexpr bool IS_STUN_ERR_RESP(StunMethod msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0110; }
    constexpr bool IS_STUN_INDICATION(StunMethod msg_type) { return (static_cast<uint16_t>(msg_type) & 0x0110) == 0x0010; }

    constexpr StunMethod GET_STUN_REQUEST(StunMethod msg_type) { return static_cast<StunMethod>((make_type(msg_type) & 0xFEEF)); }
    constexpr StunMethod GET_STUN_INDICATION(StunMethod msg_type) { return static_cast<StunMethod>((make_type(msg_type) & 0xFEEF) | 0x0010); }
    constexpr StunMethod GET_STUN_SUCCESS_RESP(StunMethod msg_type) { return static_cast<StunMethod>((make_type(msg_type) & 0xFEEF) | 0x0100); }
    constexpr StunMethod GET_STUN_ERR_RESP(StunMethod msg_type) { return static_cast<StunMethod>((make_type(msg_type)) | 0x0110); }

    constexpr auto c_crcMask = 0xFFFFFFFFUL;

    const uint32_t crctable[256] = {
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

    uint32_t ns_crc32(
        const std::byte* buffer,
        uint32_t len
    ) noexcept
    {
        uint32_t crc = c_crcMask;
        while (len--)
        {
            crc = crctable[(uint8_t)crc ^ (uint8_t)(*buffer++)] ^ (crc >> 8);
        }
        return (~crc);
    }

    constexpr size_t get_hmackey_size(
        SHAType shatype
    ) noexcept
    {
        if (shatype == SHAType::SHA256)
            return 32;
        if (shatype == SHAType::SHA384)
            return 48;
        if (shatype == SHAType::SHA512)
            return 64;
        return 16;
    }

    template <typename T>
    constexpr T RoundTo4(T value)
    {
        T temp = value & 0x03;
        if (temp)
        {
            return value + 4 - temp;
        }
        return value;
    }

    bool StunProductIntegrityKey(
        std::string_view username,
        std::string_view realm,
        std::string_view password,
        hmackey_t key,
        SHAType shatype
    ) noexcept
    {
        bool ret = true;

        //ERR_clear_error();

        //std::string str(username);
        //str += ":";
        //str += realm;
        //str += ":";
        //str += password;

        //const EVP_MD* sha;

        //if (shatype == SHAType::SHA256)
        //{
        //    sha = EVP_sha256();
        //}
        //else if (shatype == SHAType::SHA384)
        //{
        //    sha = EVP_sha384();
        //}
        //else if (shatype == SHAType::SHA512)
        //{
        //    sha = EVP_sha512();
        //}
        //else
        //{
        //    sha = EVP_md5();
        //}

        //unsigned int keylen = 0;
        //EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        //EVP_DigestInit_ex(ctx, sha, NULL);
        //EVP_DigestUpdate(ctx, str.data(), str.size());
        //EVP_DigestFinal(ctx, (uint8_t*)key, &keylen);
        //EVP_MD_CTX_free(ctx);

        return ret;
    }

    bool AddressEncode(
        const SOCKADDR_STORAGE* addr,
        uint8_t* cfield,
        int* clen,
        bool isXored,
        uint32_t mc,
        const uint8_t* tsx_id
    ) noexcept
    {
        if (!cfield || !clen || !addr || !tsx_id)
        {
            return false;
        }

        auto ss = reinterpret_cast<const SOCKADDR*>(addr);

        if (ss->sa_family == AF_INET || ss->sa_family == 0)
        {
            auto ipv4Addr = reinterpret_cast<const sockaddr_in*>(addr);

            *clen = 8;

            cfield[0] = 0;
            cfield[1] = 1; //IPv4 family

            if (isXored)
            {
                /* Port */
                ((uint16_t*)cfield)[1] = (ipv4Addr->sin_port) ^ ntohs(mc >> 16);

                /* Address */
                ((uint32_t*)cfield)[1] = (ipv4Addr->sin_addr.s_addr) ^ ntohl(mc);

            }
            else
            {
                /* Port */
                ((uint16_t*)cfield)[1] = ipv4Addr->sin_port;

                /* Address */
                ((uint32_t*)cfield)[1] = ipv4Addr->sin_addr.s_addr;
            }

        }
        else if (ss->sa_family == AF_INET6)
        {
            auto ipv6Addr = reinterpret_cast<const sockaddr_in6*>(addr);

            *clen = 20;

            cfield[0] = 0;
            cfield[1] = 2; //IPv6 family

            if (isXored)
            {
                uint8_t* dst = cfield + 4;
                const uint8_t* src = (const uint8_t*)&(ipv6Addr->sin6_addr);
                uint32_t magic = ntohl(mc);

                /* Port */
                ((uint16_t*)cfield)[1] = ipv6Addr->sin6_port ^ ntohs(mc >> 16);

                /* Address */
                for (uint32_t i = 0; i < 4; ++i) {
                    dst[i] = (uint8_t)(src[i] ^ ((const uint8_t*)&magic)[i]);
                }
                for (uint32_t i = 0; i < 12; ++i) {
                    dst[i + 4] = (uint8_t)(src[i + 4] ^ tsx_id[i]);
                }
            }
            else
            {
                /* Port */
                ((uint16_t*)cfield)[1] = ipv6Addr->sin6_port;

                /* Address */
                memcpy(cfield + 4, &ipv6Addr->sin6_addr, 16);
            }
        }
        else
        {
            return false;
        }

        return true;
    }

    bool AddressDecode(
        SOCKADDR_STORAGE* addr,
        const uint8_t* cfield,
        int len,
        bool isXored,
        uint32_t mc,
        const uint8_t* tsx_id
    ) noexcept
    {

        if (!cfield || !len || !addr || !tsx_id || (len < 8) || cfield[0] != 0)
        {
            return false;
        }

        ADDRESS_FAMILY sa_family{};

        if (cfield[1] == 1)
        {
            sa_family = AF_INET;
        }
        else if (cfield[1] == 2)
        {
            sa_family = AF_INET6;
        }
        else
        {
            return false;
        }

        auto address = reinterpret_cast<sockaddr*>(addr);

        address->sa_family = sa_family;

        if (sa_family == AF_INET)
        {
            if (len != 8)
            {
                return false;
            }

            auto ipv4Addr = reinterpret_cast<sockaddr_in*>(addr);
            ipv4Addr->sin_port = ((const uint16_t*)cfield)[1];
            ipv4Addr->sin_addr.s_addr = ((const uint32_t*)cfield)[1];

            if (isXored)
            {
                ipv4Addr->sin_port ^= ntohs(mc >> 16);
                ipv4Addr->sin_addr.s_addr ^= ntohl(mc);
            }

        }
        else if (sa_family == AF_INET6)
        {
            if (len != 20)
            {
                return false;
            }

            auto ipv6Addr = reinterpret_cast<sockaddr_in6*>(addr);
            ipv6Addr->sin6_port = ((const uint16_t*)cfield)[1];
            memcpy(&ipv6Addr->sin6_addr, cfield + 4, 16);

            if (isXored)
            {
                uint32_t magic = ntohl(mc);
                ipv6Addr->sin6_port ^= ntohs(mc >> 16);

                auto src = ((const uint8_t*)cfield) + 4;
                auto dst = (uint8_t*)&ipv6Addr->sin6_addr;

                for (uint32_t i = 0; i < 4; ++i)
                {
                    dst[i] = (uint8_t)(src[i] ^ ((const uint8_t*)&magic)[i]);
                }
                for (uint32_t i = 0; i < 12; ++i)
                {
                    dst[i + 4] = (uint8_t)(src[i + 4] ^ tsx_id[i]);
                }
            }
        }
        else
        {
            return false;
        }

        return true;
    }

    bool AddressAnyNoPort(
        const SOCKADDR_STORAGE* addr
    ) noexcept
    {
        if (!addr)
        {
            return true;
        }

        auto address = reinterpret_cast<const sockaddr*>(addr);

        if (address->sa_family == AF_INET)
        {
            auto addr4 = reinterpret_cast<const sockaddr_in*>(address);
            return (addr4->sin_addr.s_addr == 0);
        }
        else if (address->sa_family == AF_INET6)
        {
            auto addr6 = reinterpret_cast<const sockaddr_in6*>(address);
            for (size_t i = 0; i < sizeof(addr6->sin6_addr); i++)
            {
                if (((const char*)(&(addr6->sin6_addr)))[i])
                {
                    return false;
                }
            }
        }

        return true;
    }

    void AddressSetPort(
        SOCKADDR_STORAGE* addr,
        uint16_t port
    ) noexcept
    {
        if (addr)
        {
            auto address = reinterpret_cast<sockaddr*>(addr);

            if (address->sa_family == AF_INET)
            {
                auto addr4 = reinterpret_cast<sockaddr_in*>(address);
                addr4->sin_port = ntohs(port);
            }
            else if (address->sa_family == AF_INET6)
            {
                auto addr6 = reinterpret_cast<sockaddr_in6*>(address);
                addr6->sin6_port = ntohs(port);
            }
        }
    }

    constexpr bool IsXorAddress(
        StunAttributeType attr
    ) noexcept
    {
        switch (attr)
        {
        case StunAttributeType::XORMappedAddress:
        case StunAttributeType::XORPeerAddress:
        case StunAttributeType::XORRelayedAddress:
            return true;
        default:
            return false;
        };
    }

    uint64_t nswap64(uint64_t v)
    {
        uint8_t* src = (uint8_t*)&v;
        uint8_t* dst = src + 7;
        while (src < dst) {
            uint8_t vdst = *dst;
            *(dst--) = *src;
            *(src++) = vdst;
        }
        return v;
    }

    struct PayloadReader
    {
        explicit PayloadReader(const ATG::SocketPayload& payload) noexcept :
            payload(payload)
        {}

        template <typename T>
        const T* as(size_t offset = 0) const noexcept
        {
            return reinterpret_cast<const T*>(payload.buffer) + offset;
        }

        uint16_t as_hs(size_t offset = 0) const noexcept
        {
            return ntohs(*as<uint16_t>(offset));
        }

        const ATG::SocketPayload& payload;
    };

    struct PayloadWriter
    {
        explicit PayloadWriter(ATG::SocketPayload& payload) noexcept :
            payload(payload)
        {}

        template <typename T>
        T* as(size_t offset = 0) noexcept
        {
            return reinterpret_cast<T*>(payload.buffer) + offset;
        }

        ATG::SocketPayload& payload;
    };
}

StunAttributeType StunAttribute::Type() const noexcept
{
    if (m_bufferStart)
    {
        return static_cast<StunAttributeType>(as_hs());
    }
    return StunAttributeType::Invalid;
}

bool StunAttribute::GetAddress(
    SOCKADDR_STORAGE& address,
    const MessageId& transactionId
) const noexcept
{
    memset(&address, 0, sizeof(SOCKADDR_STORAGE));

    auto type = Type();

    if (type == StunAttributeType::Invalid)
    {
        return false;
    }

    auto cfield = Value();

    if (!cfield)
    {
        return false;
    }

    if (!AddressDecode(&address, cfield, Length(), IsXorAddress(type), c_stunMagicCookie, transactionId.transactionId))
    {
        return false;
    }

    return true;
}

uint64_t StunAttribute::GetReservationToken() const noexcept
{
    if (m_bufferStart)
    {
        const uint8_t* val = Value();

        if (val && Length() == sizeof(uint64_t))
        {
            uint64_t token;
            memcpy(&token, val, sizeof(uint64_t));
            return nswap64(token);
        }
    }
    return 0;
}

uint16_t StunAttribute::GetChannelNumber() const noexcept
{
    if (m_bufferStart && Length() >= 2)
    {
        uint16_t channelNumber = as_hs();

        if (IsValidStunChannel(channelNumber))
        {
            return channelNumber;
        }
    }
    return 0;
}

int32_t StunAttribute::Length() const noexcept
{
    if (m_bufferStart)
    {
        return static_cast<int32_t>(as_hs(1));
    }
    return -1;
}

const uint8_t* StunAttribute::Value() const noexcept
{
    if (m_bufferStart)
    {
        if (Length() >= 1)
        {
            return as<uint8_t>(4);
        }
    }

    return nullptr;
}

bool StunAttribute::MoveNext() noexcept
{
    if (m_bufferStart)
    {
        // Get the length of the whole buffer
        size_t bufLen = ntohs(((const uint16_t*)(m_bufferStart))[1]) + c_stunHeaderLength;

        // Get a pointer to the end if it
        const std::byte* end = m_bufferStart + bufLen;

        int attrlen = RoundTo4(Length());

        // Check that we don't go past the end of the buffer
        if (attrlen < end - as<std::byte>() - 4)
        {
            const std::byte* attr_end = as<std::byte>(4llu + attrlen);
            m_attributeOffset = attr_end - m_bufferStart;

            return true;
        }
        else
        {
            m_bufferStart = nullptr;
        }
    }
    return false;
}

MessageId GetMessageId(
    const ATG::SocketPayload& payload
) noexcept
{
    MessageId id;
    memcpy(id.transactionId, payload.buffer + c_messageIdOffset, c_stunTIDSize);
    return id;
}

int GetCommandMessageLength(
    const ATG::SocketPayload& payload
) noexcept
{
    if (payload.size < c_stunHeaderLength)
    {
        return -1;
    }

    PayloadReader reader(payload);

    /* Validate the size the buffer claims to be */
    size_t bufferLength = reader.as_hs(1) + c_stunHeaderLength;

    if (bufferLength > payload.size)
    {
        return -1;
    }

    return static_cast<int>(bufferLength);
}

bool CalculateHMAC(
    const std::byte* buffer,
    size_t length,
    const std::byte* key,
    size_t keyLength,
    std::byte* hmac,
    unsigned int* hmacLength,
    SHAType shatype
) noexcept
{
    /*ERR_clear_error();

    const EVP_MD* sha = nullptr;

    if (shatype == SHAType::SHA256)
    {
        sha = EVP_sha256();
    }
    else if (shatype == SHAType::SHA384)
    {
        sha = EVP_sha384();
    }
    else if (shatype == SHAType::SHA512)
    {
        sha = EVP_sha512();
    }
    else
    {
        sha = EVP_sha1();
    }

    return HMAC(sha, key, (int)keyLength, (uint8_t*)buffer, length, (uint8_t*)hmac, hmacLength) != 0;*/
    return false;
}

StunMessageBuilder::StunMessageBuilder(
    ATG::SocketPayload& payload
) noexcept :
    payload(payload)
{
}

bool StunMessageBuilder::InitChannelMessage(
    uint16_t channelNumber,
    int messageLength,
    bool padding
) noexcept
{
    uint16_t rlen = (uint16_t)messageLength;

    if (messageLength < 0 || (c_maxStunMessageLength < (4llu + messageLength)))
    {
        return false;
    }

    payload.turnChannel[0] = ntohs(channelNumber);
    payload.turnChannel[1] = ntohs((uint16_t)messageLength);

    if (padding)
    {
        rlen = RoundTo4(rlen);
    }

    payload.size = 4llu + rlen;

    return true;
}

bool StunMessageBuilder::InitDataIndication(
) noexcept
{
    InitCommand(GET_STUN_INDICATION(StunMethod::Send));
    return true;
}

bool StunMessageBuilder::SetBindingRequest(
) noexcept
{
    InitCommand(GET_STUN_REQUEST(StunMethod::Binding));

    return true;
}

bool StunMessageBuilder::SetAllocateRequest(
    uint32_t lifetime
) noexcept
{
    InitCommand(GET_STUN_REQUEST(StunMethod::Allocate));

    {
        uint8_t field[4]{};
        field[0] = static_cast<uint8_t>(StunAttributeType::TransportUdpValue);

        if (!AddAttribute(StunAttributeType::RequestedTransport, field, sizeof(field)))
        {
            return false;
        }
    }
    {
        if (lifetime < 1)
        {
            lifetime = c_stunDefaultAllocateLifetime;
        }

        uint32_t field = ntohl(lifetime);
        if (!AddAttribute(StunAttributeType::Lifetime, (uint8_t*)(&field), sizeof(field)))
        {
            return false;
        }
    }
    {
        uint8_t value = 0x00;

        if (!AddAttribute(StunAttributeType::EvenPort, &value, 1))
        {
            return false;
        }
    }

    return true;
}

bool StunMessageBuilder::SetAllocationRefreshRequest(
    uint32_t lifetime
) noexcept
{
    InitCommand(GET_STUN_REQUEST(StunMethod::Refresh));
    lifetime = htonl(lifetime);
    return AddAttribute(StunAttributeType::Lifetime, reinterpret_cast<uint8_t*>(&lifetime), sizeof(uint32_t));
}


uint16_t StunMessageBuilder::SetCreatePermissionRequest(
    const SOCKADDR_STORAGE* peer_addr
) noexcept
{
    InitCommand(GET_STUN_REQUEST(StunMethod::CreatePermission));

    return !peer_addr || !AddAddressAttritbute(StunAttributeType::XORPeerAddress, peer_addr);
}

uint16_t StunMessageBuilder::SetChannelBindRequest(
    const SOCKADDR_STORAGE* peer_addr,
    uint16_t channelNumber
) noexcept
{
    if (!IsValidStunChannel(channelNumber))
    {
        channelNumber = 0x4000 + ((uint16_t)(((uint32_t)rand()) % (0x7FFF - 0x4000 + 1)));
    }

    InitCommand(GET_STUN_REQUEST(StunMethod::ChannelBind));

    if (!AddChannelNumber(channelNumber) || !peer_addr || !AddAddressAttritbute(StunAttributeType::XORPeerAddress, peer_addr))
    {
        return 0;
    }

    return channelNumber;
}

bool StunMessageBuilder::AddChannelNumber(
    uint16_t channelNumber
) noexcept
{
    uint16_t field[2];
    field[0] = ntohs(channelNumber);
    field[1] = 0;

    return AddAttribute(StunAttributeType::ChannelNumber, reinterpret_cast<uint8_t*>(field), sizeof(field));
}

bool StunMessageBuilder::AddAddress(
    StunAttributeType attributeType,
    const SOCKADDR_STORAGE& address
) noexcept
{
    MessageId tid = GetMessageId(payload);

    uint8_t cfield[64];
    int clen = 0;

    return AddressEncode(&address, cfield, &clen, IsXorAddress(attributeType), c_stunMagicCookie, tid.transactionId) && AddAttribute(attributeType, cfield, clen);
}

bool StunMessageBuilder::AddEvenPort(
    bool useEven
) noexcept
{
    uint8_t value = 0;
    if (useEven)
    {
        value = 0x80;
    }

    return AddAttribute(StunAttributeType::EvenPort, &value, 1);
}

bool StunMessageBuilder::AddAttribute(
    StunAttributeType attribute,
    const uint8_t* value,
    int length
) noexcept
{
    if (length < 0 || !value)
    {
        length = 0;
    }

    int commandLength = GetCommandMessageLength(payload);
    int roundedLength = RoundTo4(commandLength + 4 + length);

    if (roundedLength < c_maxStunMessageLength)
    {
        std::byte* attributeStart = payload.buffer + commandLength;
        uint16_t* attributeStartAsUInt16 = (uint16_t*)attributeStart;

        SetCommandMessageLength(roundedLength);

        payload.size = roundedLength;

        attributeStartAsUInt16[0] = ntohs(static_cast<uint16_t>(attribute));
        attributeStartAsUInt16[1] = ntohs(static_cast<uint16_t>(length));

        if (length > 0)
        {
            memcpy(attributeStart + 4, value, length);
        }

        return true;
    }
    return false;
}


bool StunMessageBuilder::SetCommandMessageLength(
    int length
) noexcept
{
    if (payload.size < c_stunHeaderLength)
    {
        return false;
    }

    PayloadWriter writer(payload);

    *writer.as<uint16_t>(1) = ntohs((uint16_t)(length - c_stunHeaderLength));

    return true;
}

void StunMessageBuilder::InitCommand(
    StunMethod message_type
) noexcept
{
    payload.size = c_stunHeaderLength;
    memset(payload.buffer, 0, payload.size);

    PayloadWriter writer(payload);

    uint16_t message = static_cast<uint16_t>(message_type);
    message &= (uint16_t)(0x3FFF);
    *writer.as<uint16_t>(0) = ntohs(message);
    *writer.as<uint16_t>(1) = 0;
    *writer.as<uint32_t>(1) = ntohl(c_stunMagicCookie);

    auto idValue = writer.as<uint32_t>(2);
    for (size_t i = 0; i < 3; ++i)
    {
        idValue[i] = (uint32_t)rand();
    }
}

bool StunMessageBuilder::AddFingerprint() noexcept
{
    uint32_t crc32 = 0;

    AddAttribute(StunAttributeType::FingerPrint, reinterpret_cast<uint8_t*>(&crc32), sizeof(crc32));

    crc32 = ns_crc32(payload.buffer, (int)payload.size - 8);

    *((uint32_t*)(payload.buffer + payload.size - 4)) = ntohl(crc32 ^ 0x5354554Elu);

    return true;
}

bool StunMessageBuilder::AddIntegrityByUser(
    std::string_view username,
    std::string_view realm,
    std::string_view password,
    std::string_view nonce,
    SHAType shatype
) noexcept
{
    hmackey_t key{};
    return StunProductIntegrityKey(username, realm, password, key, shatype) && AddIntegrityByKey(username, realm, nonce, key, shatype);
}

bool StunMessageBuilder::AddAddressAttritbute(
    StunAttributeType attr_type,
    const SOCKADDR_STORAGE* ca
) noexcept
{
    MessageId tid = GetMessageId(payload);

    uint8_t cfield[64];
    int clen = 0;

    return AddressEncode(ca, cfield, &clen, IsXorAddress(attr_type), c_stunMagicCookie, tid.transactionId) && AddAttribute(attr_type, cfield, clen);
}

bool StunMessageBuilder::AddIntegrityByKey(
    std::string_view username,
    std::string_view realm,
    std::string_view nonce,
    hmackey_t key,
    SHAType shatype
) noexcept
{
    if (!AddAttribute(StunAttributeType::Username, reinterpret_cast<const uint8_t*>(username.data()), static_cast<int>(username.size())) ||
        !AddAttribute(StunAttributeType::Nonce, reinterpret_cast<const uint8_t*>(nonce.data()), static_cast<int>(nonce.size())) ||
        !AddAttribute(StunAttributeType::Realm, reinterpret_cast<const uint8_t*>(realm.data()), static_cast<int>(realm.size())))
    {
        return false;
    }

    uint8_t hmac[c_maxSHASize];

    unsigned int shasize;

    switch (shatype)
    {
    case SHAType::SHA256:
        shasize = c_sha256SizeBytes;
        break;
    case SHAType::SHA384:
        shasize = c_sha384SizeBytes;
        break;
    case SHAType::SHA512:
        shasize = c_sha512SizeBytes;
        break;
    default:
        shasize = c_sha1SizeBytes;
    };

    return AddAttribute(
        StunAttributeType::MessageIntegrity,
        hmac,
        shasize
    ) &&
        CalculateHMAC(
            payload.buffer,
            payload.size - 4 - shasize,
            key,
            get_hmackey_size(shatype),
            payload.buffer + payload.size - shasize,
            &shasize, shatype
        );
}

StunMessageReader::StunMessageReader(
    const ATG::SocketPayload& payload
) noexcept :
    payload(payload)
{
}

StunMethod StunMessageReader::GetMessageType(
) const noexcept
{
    if (payload.size < 2)
    {
        return StunMethod::Invalid;
    }

    return static_cast<StunMethod>(PayloadReader(payload).as_hs() & 0x3FFF);
}

bool StunMessageReader::IsStunRequest(
) const noexcept
{
    return IS_STUN_REQUEST(GetMessageType());
}

bool StunMessageReader::IsSuccessResponse(
) const noexcept
{
    return !IsChannelMessage() && IS_STUN_SUCCESS_RESP(GetMessageType());
}

bool StunMessageReader::IsChannelMessage(
    uint16_t& channelNumber,
    bool mandatoryPadding
) const noexcept
{
    if (payload.size == 0 || payload.size < 4)
    {
        return false;
    }

    PayloadReader reader(payload);

    channelNumber = reader.as_hs();

    if (!IsValidStunChannel(channelNumber))
    {
        return false;
    }

    size_t length = payload.size;

    if (length > 0xFFFF)
    {
        length = 0xFFFF;
    }

    // Length of the payload minus the headers
    uint16_t dataLengthActual = static_cast<uint16_t>(length) - 4;

    // Length of the payload as encoded in the packet
    uint16_t dataLengthHeader = reader.as_hs(1);

    // There's a mismatch so this isn't a channel message
    if (dataLengthHeader > dataLengthActual)
    {
        return false;
    }

    if (dataLengthHeader != dataLengthActual && dataLengthActual & 0x0003)
    {
        if (mandatoryPadding)
        {
            return false;
        }
        else if ((dataLengthActual < dataLengthHeader) || (dataLengthActual == 0))
        {
            return false;
        }
        else if (dataLengthActual - dataLengthHeader > 3)
        {
            return false;
        }
    }

    return true;
}

bool StunMessageReader::IsDataIndication(
    SOCKADDR_STORAGE& address
) const noexcept
{
    PayloadReader reader(payload);

    if (IS_STUN_INDICATION(GetMessageType()))
    {
        auto dataAttribute = GetFirstAttributeByType(StunAttributeType::Data);
        auto peerAttribute = GetFirstAttributeByType(StunAttributeType::XORPeerAddress);

        peerAttribute.GetAddress(address, GetMessageId(payload));

        return dataAttribute && peerAttribute;
    }
    return false;
}

bool StunMessageReader::IsErrorResponse(
    StunError& error
) const noexcept
{
    if (!IsChannelMessage() && IS_STUN_ERR_RESP(GetMessageType()))
    {
        auto attribute = GetFirstAttributeByType(StunAttributeType::ErrorCode);

        if (attribute && attribute.Length() >= 4)
        {
            auto value = attribute.Value();

            error.code = static_cast<int>(value[2] * 100 + value[3]);

            error.message[0] = 0;

            if (attribute.Length() > 4)
            {
                size_t messageLength = attribute.Length() - 4llu;

                if (messageLength > (sizeof(StunError::message) - 1))
                {
                    messageLength = sizeof(StunError::message) - 1;
                }

                memcpy(error.message, value + 4, messageLength);
                error.message[messageLength] = 0;
            }
        }
        return true;
    }
    return false;
}

bool StunMessageReader::IsChallengeResponse(
    StunError& error,
    std::pmr::string& realm,
    std::pmr::string& nonce,
    std::pmr::string* serverName
) const noexcept
{
    if (IsErrorResponse(error) && (error.code == 401 || error.code == 438))
    {
        if (auto realmAttribute = GetFirstAttributeByType(StunAttributeType::Realm))
        {
            if (auto value = realmAttribute.Value(); value != nullptr)
            {
                realm = std::string_view{ reinterpret_cast<const char*>(value), (uint32_t)realmAttribute.Length() };

                if (auto thirdPartyAuthAttribute = GetFirstAttributeByType(StunAttributeType::ThirdPartyAuthorization))
                {
                    if (value = thirdPartyAuthAttribute.Value(); value != nullptr)
                    {
                        if (serverName)
                        {
                            *serverName = std::string_view{ reinterpret_cast<const char*>(value), (uint32_t)thirdPartyAuthAttribute.Length() };
                        }
                    }
                }

                if (auto nonceAttribute = GetFirstAttributeByType(StunAttributeType::Nonce))
                {
                    if (value = nonceAttribute.Value(); value != nullptr)
                    {
                        nonce = std::string_view{ reinterpret_cast<const char*>(value), (uint32_t)nonceAttribute.Length() };
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool StunMessageReader::CheckIntegrity(
    std::string_view username,
    std::string_view realm,
    std::string_view password,
    SHAType shatype
) const noexcept
{
    std::byte new_hmac[c_maxSHASize]{};

    auto integrityAttribute = GetFirstAttributeByType(StunAttributeType::MessageIntegrity);
    if (!integrityAttribute)
    {
        return false;
    }

    switch (integrityAttribute.Length())
    {
    case c_sha256SizeBytes:
        if (shatype != SHAType::SHA256)
            return false;
        break;
    case c_sha384SizeBytes:
        if (shatype != SHAType::SHA384)
            return false;
        break;
    case c_sha512SizeBytes:
        if (shatype != SHAType::SHA512)
            return false;
        break;
    case c_sha1SizeBytes:
        if (shatype != SHAType::SHA1)
            return false;
        break;
    default:
        return false;
    };

    uint32_t shasize = integrityAttribute.Length();

    int originalLength = GetCommandMessageLength(payload);
    if (originalLength < 0)
    {
        return false;
    }

    // In order to validate the HMAC we need to modify the buffer to put in the size
    // that was there when the HMAC was originally computed. 
    ATG::SocketPayload valdationPayload = payload;
    StunMessageBuilder builder(valdationPayload);

    int new_len = (int)(integrityAttribute.as<const std::byte>() - payload.buffer) + 4 + shasize;
    if (new_len > originalLength || !builder.SetCommandMessageLength(new_len))
    {
        return false;
    }

    hmackey_t key{};
    StunProductIntegrityKey(username, realm, password, key, shatype);
    int res = CalculateHMAC(valdationPayload.buffer, (size_t)new_len - 4 - shasize, key, get_hmackey_size(shatype), new_hmac, &shasize, shatype);

    if (res < 0)
    {
        return false;
    }

    auto old_hmac = integrityAttribute.Value();
    if (!old_hmac || memcmp(old_hmac, new_hmac, shasize))
    {
        return false;
    }

    return true;
}

StunAttribute StunMessageReader::GetFirstAttribute() const noexcept
{
    int messageLength = GetCommandMessageLength(payload);

    if (messageLength > c_stunHeaderLength)
    {
        return StunAttribute(payload.buffer, c_stunHeaderLength);
    }

    return {};
}

StunAttribute StunMessageReader::GetFirstAttributeByType(
    StunAttributeType attributeType
) const noexcept
{
    auto attribute = GetFirstAttribute();

    while (attribute)
    {
        if (attribute.Type() == attributeType)
        {
            return attribute;
        }

        attribute.MoveNext();
    }

    return {};
}

bool StunMessageReader::IsChannelMessage() const noexcept
{
    return payload.size >= 4 && IsValidStunChannel(PayloadReader(payload).as_hs());
}

