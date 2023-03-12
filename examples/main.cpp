#include <format>
#include <iostream>

#include "stunpp/stun_message.h"

#include <winsock2.h>

namespace digi::net
{
    enum class address_family : std::uint32_t
    {
        ipv4 = 1,
        ipv6 = 2,
        dual_stack = 3
    };


    template <typename socket_type>
    class socket_base
    {

    };

    class dgram_socket : public socket_base<dgram_socket>
    {

    };

    class stream_socket : public socket_base<dgram_socket>
    {

    };
}

int main()
{
    WSADATA wsa{};
    std::ignore = WSAStartup(MAKEWORD(2, 2), &wsa);

    //auto local_addresses = digi::net::get_local_addresses();

    //auto s = digi::net::udp_socket(local_addresses[0]);

    //auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    //sockaddr_in local_address{};
    //local_address.sin_family = AF_INET;

    //auto res = bind(s, (sockaddr*)&local_address, sizeof(local_address));

        

    //closesocket(s);
    WSACleanup();

    return 0;
}