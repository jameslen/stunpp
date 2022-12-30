#include <format>
#include <iostream>

#include "stunpp/stun_message.h"

#include "magic_enum.hpp"

#include <winsock2.h>

template <>
struct magic_enum::customize::enum_range<stunpp::stun_attribute_type> {
    static constexpr int min = 0;
    static constexpr int max = 0x2D00;
    // (max - min) must be less than UINT16_MAX.
};

template <typename T>
    requires std::is_base_of_v<stunpp::mapped_address_attribute, T> || std::is_base_of_v<stunpp::xor_mapped_address_attribute, T>
std::tuple<std::string_view, std::string> get_address_attribute_strings(const stunpp::stun_attribute& attr) noexcept
{
    
    auto family = [&] {
        if constexpr (std::is_base_of_v<stunpp::mapped_address_attribute, T>)
        {
            return static_cast<const stunpp::mapped_address_attribute&>(attr).family;
        }
        else
        {
            return static_cast<const stunpp::xor_mapped_address_attribute&>(attr).family;
        }
    }();

    if (family == stunpp::address_family::ipv4)
    {
        auto address = [&] {
            if constexpr (std::is_base_of_v<stunpp::mapped_address_attribute, T>)
            {
                return static_cast<const stunpp::ipv4_mapped_address_attribute&>(attr).address();
            }
            else
            {
                return static_cast<const stunpp::ipv4_xor_mapped_address_attribute&>(attr).address();
            }
        }(); 

        char buffer[] = "255.255.255.255";

        inet_ntop(AF_INET, &address.sin_addr, buffer, std::size(buffer));

        return { magic_enum::enum_name(family), std::format("{}:{}", buffer, ntohs(address.sin_port)) };
    }

    return {};
}

int main()
{
    WSADATA wsa{};
    std::ignore = WSAStartup(MAKEWORD(2, 2), &wsa);

    auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in local_address{};
    local_address.sin_family = AF_INET;

    auto res = bind(s, (sockaddr*)&local_address, sizeof(local_address));

    std::array<std::byte, 1024> buffer;
    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer).create();

    sockaddr_in destination{};
    res = inet_pton(AF_INET, "18.191.223.12", &destination.sin_addr);
    destination.sin_port = htons(3478);
    destination.sin_family = AF_INET;

    res = sendto(s, (const char*)packet.data(), packet.size(), 0, (sockaddr*)&destination, sizeof(destination));

    sockaddr_in source{};
    int len = sizeof(source);
    std::array<std::byte, 1500> recv_buffer{};
    int size = recvfrom(s, (char*)recv_buffer.data(), recv_buffer.size(), 0, (sockaddr*)&source, &len);

    auto reader_result = stunpp::message_reader::create(std::span{ recv_buffer.data(), static_cast<size_t>(size) });
    auto& reader = reader_result.value();

    auto& header = reader.get_header();

    auto method = header.get_method();
    auto method_type = header.get_method_type();

    std::cout << std::format("Method: {}\nType: {}\nLength: {}\nAttributes:\n", 
        magic_enum::enum_name(method),
        magic_enum::enum_name(method_type),
        std::uint16_t{ stunpp::host_uint16_t{ header.message_length } }
    );

    std::cout << std::format("+{:-<27}+{:->6}+{:->8}+{:-<23}+\n", "", "", "", "");
    std::cout << std::format("| {:^25} | {:^4} | {} | {:<21} |\n", "Type", "Size", "Family", "Address");
    std::cout << std::format("+{:-<27}+{:->6}+{:->8}+{:-<23}+\n", "", "", "", "");

    for (auto&& attr : reader)
    {
        std::cout << std::format("| {:<25} | {:>4} ",
            magic_enum::enum_name(attr.type),
            std::uint16_t{ stunpp::host_uint16_t{ attr.size } }
        );
        switch (attr.type)
        {
        case stunpp::stun_attribute_type::mapped_address:
        case stunpp::stun_attribute_type::other_address:
        case stunpp::stun_attribute_type::response_origin:
        {
            auto&& [family, address] = get_address_attribute_strings<stunpp::mapped_address_attribute>(attr);

            std::cout << std::format("| {:^6} | {:<21} |\n", family, address);
            break;
        }
        case stunpp::stun_attribute_type::xor_mapped_address:
        {
            auto&& [family, address] = get_address_attribute_strings<stunpp::xor_mapped_address_attribute>(attr);

            std::cout << std::format("| {:^6} | {:<21} |\n", family, address);
            break;
        }
        default:
            break;
        }
    }

    std::cout << std::format("+{:-<27}+{:->6}+{:->8}+{:-<23}+\n", "", "", "", "");
    

    closesocket(s);
    WSACleanup();

    return 0;
}