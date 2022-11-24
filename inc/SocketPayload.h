//--------------------------------------------------------------------------------------
// SocketPayload.h
//
// Advanced Technology Group (ATG)
// Copyright (C) Microsoft Corporation. All rights reserved.
//--------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------
// File: SocketPayload.h
//
// Advanced Technology Group (ATG)
// Copyright (C) Microsoft Corporation. All rights reserved.
//--------------------------------------------------------------------------------------
#pragma once

namespace ATG
{
    constexpr size_t c_MaxPayloadSize = 1300llu;

    struct SocketPayload
    {
        uint32_t size{ 0 };
        uint16_t turnChannel[2]{ 0, 0 };
        std::byte buffer[c_MaxPayloadSize]{};

        SocketPayload& operator=(const SocketPayload& rhs) noexcept
        {
            turnChannel[0] = rhs.turnChannel[0];
            turnChannel[1] = rhs.turnChannel[1];
            memcpy(buffer, rhs.buffer, rhs.size);
            size = rhs.size;
            return *this;
        }

        bool operator==(const SocketPayload& rhs) const noexcept
        {
            return
                size == rhs.size &&
                memcmp(buffer, rhs.buffer, size) == 0;
        }
    };
}


