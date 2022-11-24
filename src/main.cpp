#include <cassert>
#include <format>
#include <iostream>

#include "stun_buffer.h"

#include "stun_buffer2.h"

int main()
{
    {
        // Binding request test
        std::array<std::byte, 1024> buffer;
        auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
            .create();

        ATG::SocketPayload payload{};
        StunMessageBuilder builder{payload};
        builder.SetBindingRequest();

        // Skip the last 12 bytes because that's randomly generated
        assert(memcmp(packet.data(), payload.buffer, packet.size() - 12) == 0);
    }

    {
        // Binding Response Test
        // Source packet
        std::array<std::byte, 1024> source_buffer;
        auto source_packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, source_buffer)
            .create();

        // TODO: Reader:
        stunpp::stun_header& source_header = *reinterpret_cast<stunpp::stun_header*>(source_packet.data());

        std::array<std::byte, 1024> buffer;
        auto packet = stunpp::message_builder::create_response(stunpp::stun_method::binding, source_header.transaction_id, buffer)
            .add_ipv4_address({})
            .create();

        //ATG::SocketPayload payload{};
        //StunMessageBuilder builder{ payload };
        //builder.r();

        // Skip the last 12 bytes because that's randomly generated
        //assert(memcmp(packet.data(), payload.buffer, packet.size() - 12) == 0);

        int i = 0;
    }

    int i = 0;

    //net::socket_options opts{};
    //net::datagram_socket local_socket(&opts);

    //net::ipv4_address destination;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
    //local_socket.send_to(destination, packet);

    //auto reader = stunpp::message_reader(packet);

    //const stunpp::stun_header& header = reader.get_message_header();
    //auto message_type = header.message_type;
    //auto& attr_iter = reader.get_first_attribute();

    //net::ipv4_address server_address;

    //net::socket_options opts{};
    //net::datagram_socket socket(opts);

    //// auto receiver = socket.start_receiving(scheduler.get_scheduler) 
    ////     | then([](std::span<const std::byte) {
    ////         // TODO: Parse this and dispatch
    ////     });

    //socket.send_to(server_address, packet);
}