cmake_minimum_required(VERSION 3.16)
project(powershell_exec)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(powershell_exec powershell_exec.cpp)

# Link Windows libraries
if(WIN32)
    target_link_libraries(powershell_exec 
        kernel32 
        user32 
        advapi32 
        ws2_32
    )
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(powershell_exec PRIVATE /W4)
else()
    target_compile_options(powershell_exec PRIVATE -Wall -Wextra -Wpedantic)
endif()
