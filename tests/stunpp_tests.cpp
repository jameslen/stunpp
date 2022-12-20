#include <gtest/gtest.h>

#include "stun_buffer.h"

// Demonstrate some basic assertions.
TEST(stun_builder, binding_request) {
    // Binding request test
    std::array<std::byte, 1024> buffer;
    auto packet = stunpp::message_builder::create_request(stunpp::stun_method::binding, buffer)
        .create();

    EXPECT_EQ(packet.size(), sizeof(stunpp::stun_header)) << "Packet did size did not match the size of the header";

    // Skip the last 12 bytes because that's randomly generated
    const std::array<std::byte, 8> c_expected_bytes{  };

    EXPECT_EQ(std::memcmp(packet.data(), c_expected_bytes.data(), c_expected_bytes.size()), 0) << "Generated packet data did not match";
}

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
