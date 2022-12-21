add_library(stunpp "stun_message.cpp" "win32/crypto_functions.h")

target_include_directories(stunpp PUBLIC ../inc)

target_link_libraries(stunpp ws2_32 bcrypt)

target_compile_options(stunpp PRIVATE /sdl /permissive- /JMC- /W4 /Zc:__cplusplus)
