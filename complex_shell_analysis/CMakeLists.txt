cmake_minimum_required(VERSION 3.16)
project(complex_shell)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(complex_shell complex_shell.cpp)

# Link Windows libraries
if(WIN32)
    target_link_libraries(complex_shell 
        kernel32 
        user32 
        advapi32 
        ws2_32
    )
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(complex_shell PRIVATE /W4)
else()
    target_compile_options(complex_shell PRIVATE -Wall -Wextra -Wpedantic)
endif()
