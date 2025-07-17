cmake_minimum_required(VERSION 3.15)
project(test)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Drogon
find_package(Drogon CONFIG REQUIRED)

# Collect source files
set(SOURCES
    src/main.cpp
    src/db/database.cpp
    src/rate_limiter/rate_limiter.cpp
    src/auth/auth_utils.cpp
    src/middleware/middleware.cpp
    src/handlers/handlers.cpp
    src/Bcrypt.cpp/src/bcrypt.cpp
    src/Bcrypt.cpp/src/blowfish.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    include
    src/Bcrypt.cpp/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)

option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
if(ENABLE_SANITIZERS)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -fsanitize=address)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -O3)
endif()

# Copy users.db to build directory if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/users.db")
    file(COPY "${CMAKE_SOURCE_DIR}/users.db" DESTINATION "${CMAKE_BINARY_DIR}")
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)