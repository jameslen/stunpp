#pragma once 

namespace stunpp::util
{
    template <typename T>
    constexpr T hton(T val)
    {
        if constexpr (std::endian::native == std::endian::little)
        {
            return std::byteswap(val);
        }
        else
        {
            return val;
        }
    }

    // Thin wrapper class for keeping track of when data is in the host byte order
    // and when it needs to be converted to comply with the network protocol.
    template <std::integral T>
    struct host_ordered
    {
        constexpr host_ordered(T value) noexcept: 
            value{ value } 
        {
        }

        template<std::integral U>
        constexpr host_ordered(const host_ordered<U>& src) noexcept :
            value(static_cast<T>(static_cast<U>(src)))
        {
        }

        template <std::integral U>
        constexpr host_ordered<T> operator>>(U shift) const noexcept
        {
            return value >> shift;
        }

        template <std::integral U>
        constexpr host_ordered<T> operator<<(U shift) const noexcept
        {
            return value << shift;
        }

        template <std::integral U>
        constexpr host_ordered<T> operator^(U rhs) const noexcept
        {
            return value ^ rhs;
        }

        template <std::integral U>
        constexpr host_ordered<T> operator|(U rhs) const noexcept
        {
            return value | rhs;
        }

        template <std::integral U>
        constexpr host_ordered<T> operator&(U rhs) const noexcept
        {
            return value & rhs;
        }

        template <std::integral U>
        constexpr operator host_ordered<U>() const noexcept
        {
            return static_cast<U>(value);
        }

        constexpr operator T() const noexcept
        {
            return value;
        }

        constexpr host_ordered<T>& operator+=(const host_ordered<T>& rhs) noexcept
        {
            value += rhs.value;
            return *this;
        }

    private:
        T value;
    };

    // Wrapper class for converting to network byte order for network transport.
    // Allows for clarity of when data needs to be in a specific byte order and
    // seemless conversion to and from the host order.
    template <std::integral T>
    struct network_ordered
    {
        constexpr network_ordered() noexcept = default;

        constexpr network_ordered(const host_ordered<T>& src) noexcept:
            value(util::hton(static_cast<T>(src)))
        {
        }

        constexpr T read() const noexcept { return value; }

        constexpr bool operator==(const host_ordered<T>& rhs) const noexcept
        {
            return *this == network_ordered<T>(rhs);
        }

        constexpr bool operator<(const host_ordered<T>& rhs) const
        {
            return host_ordered<T>(*this) < rhs;
        }

        // Equality can be defaulted as the values will compare as equal no matter
        // the byte order
        constexpr bool operator==(const network_ordered<T>& rhs) const noexcept = default;

        // For equality we need to convert the values back to host order for 
        // proper comparison
        constexpr bool operator<(const network_ordered<T>& rhs) const
        {
            return host_ordered<T>(*this) < host_ordered<T>(rhs);
        }

        constexpr operator host_ordered<T>() const noexcept
        {
            return util::hton(static_cast<T>(value));
        }

        // Bitwise operations can happen as long as the data is in the same order.
        constexpr network_ordered<T> operator^(const network_ordered<T>& rhs) const
        {
            network_ordered<T> data;
            data.value = value ^ rhs.value;
            return data;
        }

        constexpr network_ordered<T> operator|(const network_ordered<T>& rhs) const
        {
            network_ordered<T> data;
            data.value = value | rhs.value;
            return data;
        }

        constexpr network_ordered<T> operator&(const network_ordered<T>& rhs) const
        {
            network_ordered<T> data;
            data.value = value & rhs.value;
            return data;
        }

        constexpr network_ordered<T> operator^(const host_ordered<T>& rhs) const
        {
            return *this ^ network_ordered<T>(rhs);
        }

        constexpr network_ordered<T> operator|(const host_ordered<T>& rhs) const
        {
            return *this | network_ordered<T>(rhs);
        }

        constexpr network_ordered<T> operator&(const host_ordered<T>& rhs) const
        {
            return *this & network_ordered<T>(rhs);
        }

        template<std::integral U>
        constexpr friend network_ordered<U> network_order_from_value(U val) noexcept;
    private:
        T value;
    };

    template <std::integral U>
    constexpr network_ordered<U> network_order_from_value(U val) noexcept
    {
        network_ordered<U> data;
        data.value = val;
        return data;
    }
}