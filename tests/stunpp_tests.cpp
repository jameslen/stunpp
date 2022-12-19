#include <gtest/gtest.h>

#include "stun_buffer.h"

TEST(network_ordering, initializing) {
    stunpp::util::network_ordered<std::uint16_t> network = stunpp::util::network_order_from_value((uint16_t)0xAABB);

    EXPECT_EQ(network.read(), 0xAABB) << "Value did not get stored as expected is in Network ordered storage";

    stunpp::util::host_ordered<std::uint16_t> host((uint16_t)0xAABB);

    EXPECT_EQ(host, 0xAABB) << "Value did not get stored as expected is in host ordered storage";
}

TEST(network_ordering, simple_conversion) {
    stunpp::util::host_ordered<std::uint16_t> host((uint16_t)0xAABB);

    stunpp::util::network_ordered<std::uint16_t> network = host;

    EXPECT_EQ(network.read(), 0xBBAA) << "Value did not get stored as is in Network ordered storage";

    stunpp::util::network_ordered<std::uint16_t> network2 = stunpp::util::network_order_from_value<uint16_t>(0xCCDD);
    stunpp::util::host_ordered<std::uint16_t> host2 = network2;

    EXPECT_EQ(host2, 0xDDCC) << "Value did not get stored as expected is in host ordered storage";
}

TEST(network_ordering, comparison) {
    stunpp::util::network_ordered<std::uint16_t> network = stunpp::util::network_order_from_value((uint16_t)0xAABB);
    stunpp::util::host_ordered<std::uint16_t> host((uint16_t)0xBBAA);

    EXPECT_EQ(network, host) << "Values were not equal";
    EXPECT_EQ(host, network) << "Values were not equal";

}

//// Demonstrate some basic assertions.
//TEST(stun_builder, binding_request) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//    
//}
//
//TEST(stun_builder, binding_response_failure) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//
//}
//
//TEST(stun_builder, binding_response_success) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//
//}
//
//TEST(stun_reader, binding_request) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//}
//
//TEST(stun_reader, binding_response_failure) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//
//}
//
//TEST(stun_reader, binding_response_success) {
//    // Binding request test
//    std::array<std::byte, 1024> buffer;
//    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
//        .create();
//
//    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";
//
//    // Skip the last 12 bytes because that's randomly generated
//
//}
