cmake_minimum_required(VERSION 3.15)
project(test)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Drogon (this handles most dependencies)
find_package(Drogon CONFIG REQUIRED)

add_executable(${PROJECT_NAME} test.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)

option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" ON)
if(ENABLE_SANITIZERS)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address,undefined)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address,undefined)
endif()

# Copy users.db to build directory if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/users.db")
    file(COPY "${CMAKE_SOURCE_DIR}/users.db" DESTINATION "${CMAKE_BINARY_DIR}")
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)