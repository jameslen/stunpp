add_executable(stunpp_client "main.cpp")

target_include_directories(stunpp_client PRIVATE "external/magic_enum")

target_link_libraries(stunpp_client stunpp)

target_compile_options(stunpp_client PRIVATE /sdl /permissive- /analyze /JMC- /W4 /Zc:__cplusplus)
