cmake_minimum_required(VERSION 3.10)
project(SecureNoteSharing)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

# Tìm packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)  # ← THÊM dòng này

add_compile_options(-Wno-deprecated-declarations)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "SQLite3 found: ${SQLite3_FOUND}")
message(STATUS "CURL found: ${CURL_FOUND}")  # ← THÊM dòng này

# Server executable
add_executable(server 
    server.cpp 
    database.cpp
    crypto_utils.cpp
)

target_link_libraries(server 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    SQLite::SQLite3
    pthread
)

# Client executable
add_executable(client 
    client.cpp 
    crypto_utils.cpp
)

target_link_libraries(client 
    OpenSSL::SSL 
    OpenSSL::Crypto
    CURL::libcurl  # ← SỬA dòng này (từ curl thành CURL::libcurl)
    pthread
)