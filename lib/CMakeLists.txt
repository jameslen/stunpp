add_library(stunpp "stun_message.cpp" "stun_message_types.cpp" "win32/stun_password_generator.cpp")

target_include_directories(stunpp PRIVATE "../inc/stunpp" "../inc/stunpp/win32" PUBLIC "../inc")

target_link_libraries(stunpp PUBLIC ws2_32 bcrypt)

target_compile_options(stunpp PRIVATE /sdl /permissive- /analyze /JMC- /W4 /Zc:__cplusplus)
