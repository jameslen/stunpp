enable_testing()

include(GoogleTest)

add_executable(
	stunpp_tests
	stunpp_reader_tests.cpp
	stunpp_network_order_tests.cpp
	stunpp_builder_tests.cpp)

target_link_libraries(
	stunpp_tests
	stunpp
	GTest::gtest_main
)

gtest_discover_tests(stunpp_tests)
