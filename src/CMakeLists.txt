add_library(stunpp "stun_message.cpp" "stun_message_types.cpp")

target_include_directories(stunpp PUBLIC ../inc)

target_link_libraries(stunpp ws2_32 bcrypt)

target_compile_options(stunpp PRIVATE /sdl /permissive- /JMC- /W4 /Zc:__cplusplus)
