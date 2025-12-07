#include "include/httplib.h"
#include "include/json.hpp"
#include <iostream>
#include <openssl/evp.h>
#include <sqlite3.h>

using json = nlohmann::json;

int main() {
    std::cout << "Testing includes...\n";
    
    // Test JSON
    json j = {{"test", "value"}};
    std::cout << "JSON: " << j.dump() << "\n";
    
    // Test OpenSSL
    std::cout << "OpenSSL version: " << OPENSSL_VERSION_TEXT << "\n";
    
    // Test SQLite
    std::cout << "SQLite version: " << sqlite3_libversion() << "\n";
    
    // Test httplib
    httplib::Server svr;
    std::cout << "httplib loaded successfully\n";
    
    std::cout << "\n✓ All includes work!\n";
    return 0;
}