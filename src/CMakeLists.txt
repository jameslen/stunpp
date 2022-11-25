add_library(stunpp stun_buffer.cpp)

target_include_directories(stunpp PUBLIC ../inc)

target_link_libraries(stunpp ws2_32)

target_compile_options(stunpp PRIVATE /sdl /permissive- /JMC- /W4 /Zc:__cplusplus)
