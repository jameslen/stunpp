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
#pragma once

///////////////////////////////////////////////////////////////

#include "SocketPayload.h"

#include <memory_resource>
#include <string>

struct StunBuffer;

constexpr size_t c_stunTIDSize = 12;
constexpr size_t c_stunHeaderLength = 20;
constexpr size_t c_stunChannelHeaderLength = 4;
constexpr size_t c_maxStunMessageLength = 1384;
constexpr size_t c_stunBufferSize = c_maxStunMessageLength;
constexpr size_t c_udpStunBufferSize = 1384;
constexpr size_t c_stunMacPasswordSize = 256;

using hmackey_t = std::byte[64];
using password_t = std::byte[c_stunMacPasswordSize + 1];

enum class StunAttributeType : uint16_t
{
    MappedAddress = 0x0001,
    ChangeRequest = 0x0003,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    TransportUdpValue = 0x0011,
    XORPeerAddress = 0x0012,
    Data = 0x0013,
    Realm = 0x0014,
    Nonce = 0x0015,
    XORRelayedAddress = 0x0016,
    RequestedAddressFamily = 0x0017,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    XORMappedAddress = 0x0020,
    ReservationToken = 0x0022,
    Padding = 0x0026,
    ResponsePort = 0x0027,

    AlternateServer = 0x8023,
    FingerPrint = 0x8028,
    ResponseOrigin = 0x802B,
    OtherAddress = 0x802C,
    ThirdPartyAuthorization = 0x802E,
    MobilityTicket = 0x8030,
    AdditionalAddressFamily = 0x8032,

    Invalid = 0xFFFF
};

enum class StunMethod : uint16_t
{
    Binding = 0x0001,
    Allocate = 0x0003,
    Refresh = 0x0004,
    Send = 0x006,
    Data = 0x007,
    CreatePermission = 0x0008,
    ChannelBind = 0x0009,
    Connect = 0x000A,
    ConnectionBind = 0x000B,
    ConnectionAttempt = 0x000C,

    Invalid = 0xFFFF
};

enum class SHAType : uint8_t
{
    Default = 0,
    SHA1 = Default,
    SHA256,
    SHA384,
    SHA512,

    Error = 0xFF
};

struct MessageId
{
    uint8_t transactionId[c_stunTIDSize];

    bool operator==(const MessageId& rhs) const noexcept
    {
        return memcmp(transactionId, rhs.transactionId, c_stunTIDSize) == 0;
    }

    bool operator<(const MessageId& rhs) const noexcept
    {
        return memcmp(transactionId, rhs.transactionId, c_stunTIDSize) == -1;
    }
};

struct StunError
{
    uint32_t code{};
    char message[256]{};
    size_t messageSize{};
};

struct StunAttribute
{
    StunAttribute() noexcept = default;

    StunAttribute(
        const std::byte* data,
        size_t offset
    ) noexcept :
        m_bufferStart(data),
        m_attributeOffset(offset)
    {

    }

    template <typename T>
    const T* as(
        size_t index = 0
    ) const noexcept
    {
        return reinterpret_cast<const T*>(m_bufferStart + m_attributeOffset) + index;
    }

    uint16_t as_hs(
        size_t index = 0
    ) const noexcept
    {
        return ntohs(*as<uint16_t>(index));
    }

    StunAttributeType Type() const noexcept;

    bool GetAddress(
        SOCKADDR_STORAGE& addr,
        const MessageId& tid
    ) const noexcept;

    uint64_t GetReservationToken() const noexcept;
    uint16_t GetChannelNumber() const noexcept;

    int32_t Length() const noexcept;
    const uint8_t* Value() const noexcept;

    operator bool() const noexcept { return m_bufferStart != nullptr; }

    bool MoveNext() noexcept;

private:
    const std::byte* m_bufferStart{ nullptr };
    size_t m_attributeOffset{ 0 };
};

MessageId GetMessageId(
    const ATG::SocketPayload& payload
) noexcept;

int GetCommandMessageLength(
    const ATG::SocketPayload& payload
) noexcept;

struct StunMessageBuilder
{
    explicit StunMessageBuilder(
        ATG::SocketPayload& payload
    ) noexcept;

    bool SetCommandMessageLength(
        int length
    ) noexcept;

    bool InitChannelMessage(
        uint16_t channelNumber,
        int messageLength,
        bool padding
    ) noexcept;

    bool InitDataIndication(
    ) noexcept;

    bool SetBindingRequest(
    ) noexcept;

    bool SetAllocateRequest(
        uint32_t lifetime
    ) noexcept;

    bool SetAllocationRefreshRequest(
        uint32_t lifetime
    ) noexcept;

    uint16_t SetCreatePermissionRequest(
        const SOCKADDR_STORAGE* peer_addr
    ) noexcept;

    uint16_t SetChannelBindRequest(
        const SOCKADDR_STORAGE* peer_addr,
        uint16_t channel_number
    ) noexcept;

    bool AddChannelNumber(
        uint16_t channelNumber
    ) noexcept;

    bool AddAddress(
        StunAttributeType attributeType,
        const SOCKADDR_STORAGE& address
    ) noexcept;

    bool AddEvenPort(
        bool useEven
    ) noexcept;

    bool AddAttribute(
        StunAttributeType attribute,
        const uint8_t* value,
        int length
    ) noexcept;

    bool AddFingerprint(
    ) noexcept;

    bool AddIntegrityByUser(
        std::string_view username,
        std::string_view realm,
        std::string_view password,
        std::string_view nonce,
        SHAType shatype = SHAType::Default
    ) noexcept;

    ATG::SocketPayload& payload;

private:

    void InitCommand(
        StunMethod message_type
    ) noexcept;

    bool AddAddressAttritbute(
        StunAttributeType attr_type,
        const SOCKADDR_STORAGE* ca
    ) noexcept;

    bool AddIntegrityByKey(
        std::string_view username,
        std::string_view realm,
        std::string_view nonce,
        hmackey_t key,
        SHAType shatype
    ) noexcept;
};

struct StunMessageReader
{
    explicit StunMessageReader(
        const ATG::SocketPayload& payload
    ) noexcept;

    StunMethod GetMessageType(
    ) const noexcept;

    bool IsStunRequest(
    ) const noexcept;

    bool IsSuccessResponse(
    ) const noexcept;

    bool IsChannelMessage(
        uint16_t& channelNumber,
        bool mandatoryPadding
    ) const noexcept;

    bool IsDataIndication(
        SOCKADDR_STORAGE& address
    ) const noexcept;

    bool IsErrorResponse(
        StunError& error
    ) const noexcept;

    bool IsChallengeResponse(
        StunError& error,
        std::pmr::string& realm,
        std::pmr::string& nonce,
        std::pmr::string* serverName
    ) const noexcept;

    bool CheckIntegrity(
        std::string_view username,
        std::string_view realm,
        std::string_view password,
        SHAType shatype = SHAType::Default
    ) const noexcept;

    StunAttribute GetFirstAttribute() const noexcept;

    StunAttribute GetFirstAttributeByType(
        StunAttributeType attr_type
    ) const noexcept;

    const ATG::SocketPayload& payload;

private:
    bool IsChannelMessage() const noexcept;
};

