enable_testing()

add_executable(
	stunpp_tests
	stunpp_tests.cpp
)
target_link_libraries(
	stunpp_tests
	stunpp
	GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(stunpp_tests)