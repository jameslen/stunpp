add_executable(stunpp_server main.cpp)

target_include_directories(stunpp_server PRIVATE ../inc)

target_compile_options(stunpp_server PRIVATE /sdl /permissive- /JMC- /Zc:__cplusplus)