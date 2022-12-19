#include <gtest/gtest.h>

#include "network_order_storage.h"

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