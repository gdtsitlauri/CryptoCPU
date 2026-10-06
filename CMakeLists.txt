cmake_minimum_required(VERSION 3.16)
project(CryptoCPU CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
if(MSVC)
  add_compile_options(/W4 /wd4068)            # 4068: HLS pragmas are unknown to the host compiler
else()
  add_compile_options(-Wall -Wextra -Wno-unknown-pragmas)
endif()

add_library(cryptocpu STATIC src/aes128.cpp src/xex.cpp src/cryptocpu.cpp ref/isa_ref.cpp)
target_include_directories(cryptocpu PUBLIC src ref)

add_executable(cryptocpu_tb tests/cryptocpu_tb.cpp)
target_link_libraries(cryptocpu_tb cryptocpu)

add_executable(security_tb tests/security_tb.cpp)
target_link_libraries(security_tb cryptocpu)

add_executable(aes_kat tests/aes_kat.cpp)
target_link_libraries(aes_kat cryptocpu)

add_executable(image_tool tools/image_tool.cpp)
target_link_libraries(image_tool cryptocpu)
