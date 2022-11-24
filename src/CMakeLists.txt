add_executable(stunpp_server main.cpp stun_buffer.cpp stun_buffer2.cpp)

target_include_directories(stunpp_server PRIVATE ../inc)

target_link_libraries(stunpp_server ws2_32)

target_compile_options(stunpp_server PRIVATE /sdl /permissive- /JMC- /Zc:__cplusplus)
