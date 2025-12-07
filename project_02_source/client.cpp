#include "crypto_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include "include/json.hpp"
#include <curl/curl.h>
using json = nlohmann::json;

// Helper function cho CURL response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class NoteClient {
private:
    std::string server_url = "http://localhost:8080";
    std::string auth_token;
    
    std::string httpPost(const std::string& endpoint, const std::string& data, 
                        const std::string& token = "") {
        CURL* curl = curl_easy_init();
        std::string response;
        if (curl) {
            std::string url = server_url + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            if (!token.empty()) {
                std::string auth_header = "Authorization: Bearer " + token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            
            CURLcode res = curl_easy_perform(curl);
            
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
        
        return response;
    }
    
    std::string httpGet(const std::string& endpoint, const std::string& token = "") {
        CURL* curl = curl_easy_init();
        std::string response;
        
        if (curl) {
            std::string url = server_url + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            
            struct curl_slist* headers = nullptr;
            if (!token.empty()) {
                std::string auth_header = "Authorization: Bearer " + token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            
            curl_easy_perform(curl);
            
            if (headers) curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
        
        return response;
    }

public:
    bool registerUser(const std::string& username, const std::string& password) {
        json body = {{"username", username}, {"password", password}};
        std::string response = httpPost("/api/auth/register", body.dump());
        
        try {
            json resp = json::parse(response);
            if (resp["success"] == true) {
                std::cout << "✓ Registration successful!\n";
                return true;
            }
        } catch (...) {}
        
        std::cout << "✗ Registration failed: " << response << "\n";
        return false;
    }
    
    bool login(const std::string& username, const std::string& password) {
        json body = {{"username", username}, {"password", password}};
        
        // DEBUG: In ra request
        std::cout << "[DEBUG] Sending login request...\n";
        std::cout << "[DEBUG] Body: " << body.dump() << "\n";
        
        std::string response = httpPost("/api/auth/login", body.dump());
        
        // DEBUG: In ra response
        std::cout << "[DEBUG] Response: " << response << "\n";
        
        try {
            json resp = json::parse(response);
            if (resp.contains("token")) {
                auth_token = resp["token"];
                std::cout << "✓ Login successful! Token: " << auth_token.substr(0, 20) << "...\n";
                return true;
            } else {
                std::cout << "[DEBUG] No token in response\n";
            }
        } catch (const std::exception& e) {
            std::cout << "[DEBUG] JSON parse error: " << e.what() << "\n";
        }
        
        std::cout << "✗ Login failed\n";
        return false;
    }
    bool uploadNote(const std::string& filepath) {
        if (auth_token.empty()) {
        std::cout << "✗ Not logged in! Please login first (Choice 2)\n";
        return false;
        }
    
        std::cout << "[DEBUG] Token length: " << auth_token.length() << "\n";
        std::cout << "[DEBUG] Token: " << auth_token.substr(0, 30) << "...\n";
        // Read file
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            std::cout << "✗ Cannot open file: " << filepath << "\n";
            return false;
        }
        
        std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
        file.close();
        
        std::cout << "📄 File size: " << plaintext.size() << " bytes\n";
        
        // Generate key and encrypt
        auto key = CryptoUtils::generateAESKey();
        auto encrypted = CryptoUtils::encryptAES_GCM(plaintext, key);
        
        std::cout << "🔒 Encrypted successfully\n";
        
        // Save key locally
        std::string key_file = filepath + ".key";
        std::ofstream key_out(key_file, std::ios::binary);
        key_out.write(reinterpret_cast<const char*>(key.data()), key.size());
        key_out.close();
        
        std::cout << "🔑 Key saved to: " << key_file << "\n";
        
        // Upload to server
        json body = {
            {"filename", filepath},
            {"encrypted_data", CryptoUtils::base64Encode(encrypted.ciphertext)},
            {"iv", CryptoUtils::base64Encode(encrypted.iv)},
            {"tag", CryptoUtils::base64Encode(encrypted.tag)}
        };
        std::cout << "[DEBUG] Sending request with token: " << auth_token.substr(0, 20) << "...\n";
        std::string response = httpPost("/api/notes/create", body.dump(), auth_token);
        std::cout << "[DEBUG] Response: " << response << "\n";
    
        
        std::string response = httpPost("/api/notes/create", body.dump(), auth_token);
        
        try {
            json resp = json::parse(response);
            if (resp.contains("note_id")) {
                std::cout << "✓ Note uploaded! ID: " << resp["note_id"] << "\n";
                return true;
            }
        } catch (...) {}
        
        std::cout << "✗ Upload failed: " << response << "\n";
        return false;
    }
    
    void listNotes() {
        std::string response = httpGet("/api/notes/list", auth_token);
        
        try {
            json resp = json::parse(response);
            if (resp.contains("notes")) {
                auto notes = resp["notes"];
                std::cout << "\n📋 Your notes (" << notes.size() << "):\n";
                std::cout << "----------------------------------------\n";
                for (const auto& note : notes) {
                    std::cout << "  ID: " << note["note_id"] 
                             << " | File: " << note["filename"] << "\n";
                }
                std::cout << "----------------------------------------\n";
            }
        } catch (...) {
            std::cout << "✗ Failed to list notes\n";
        }
    }
    
    bool downloadNote(int note_id, const std::string& key_file, 
                     const std::string& output_file) {
        // Get note from server
        std::string response = httpGet("/api/notes/" + std::to_string(note_id), auth_token);
        
        try {
            json resp = json::parse(response);
            
            // Read key
            std::ifstream key_in(key_file, std::ios::binary);
            if (!key_in) {
                std::cout << "✗ Cannot open key file: " << key_file << "\n";
                return false;
            }
            std::vector<uint8_t> key(32);
            key_in.read(reinterpret_cast<char*>(key.data()), 32);
            key_in.close();
            
            // Decrypt
            CryptoUtils::EncryptedData encrypted;
            encrypted.ciphertext = CryptoUtils::base64Decode(resp["encrypted_data"]);
            encrypted.iv = CryptoUtils::base64Decode(resp["iv"]);
            encrypted.tag = CryptoUtils::base64Decode(resp["tag"]);
            
            auto plaintext = CryptoUtils::decryptAES_GCM(encrypted, key);
            
            // Write to file
            std::ofstream out(output_file, std::ios::binary);
            out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
            out.close();
            
            std::cout << "✓ Note downloaded and decrypted: " << output_file << "\n";
            return true;
            
        } catch (const std::exception& e) {
            std::cout << "✗ Download failed: " << e.what() << "\n";
            return false;
        }
    }
};

void printMenu() {
    std::cout << "\n=== Secure Note Sharing Client ===\n";
    std::cout << "1. Register\n";
    std::cout << "2. Login\n";
    std::cout << "3. Upload Note\n";
    std::cout << "4. List Notes\n";
    std::cout << "5. Download Note\n";
    std::cout << "0. Exit\n";
    std::cout << "Choice: ";
}

int main() {
    NoteClient client;
    
    while (true) {
        printMenu();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        if (choice == 0) break;
        
        switch (choice) {
            case 1: {
                std::string username, password;
                std::cout << "Username: "; std::getline(std::cin, username);
                std::cout << "Password: "; std::getline(std::cin, password);
                client.registerUser(username, password);
                break;
            }
            case 2: {
                std::string username, password;
                std::cout << "Username: "; std::getline(std::cin, username);
                std::cout << "Password: "; std::getline(std::cin, password);
                client.login(username, password);
                break;
            }
            case 3: {
                std::string filepath;
                std::cout << "File path: "; std::getline(std::cin, filepath);
                client.uploadNote(filepath);
                break;
            }
            case 4: {
                client.listNotes();
                break;
            }
            case 5: {
                int note_id;
                std::string key_file, output_file;
                std::cout << "Note ID: "; std::cin >> note_id;
                std::cin.ignore();
                std::cout << "Key file: "; std::getline(std::cin, key_file);
                std::cout << "Output file: "; std::getline(std::cin, output_file);
                client.downloadNote(note_id, key_file, output_file);
                break;
            }
            default:
                std::cout << "Invalid choice\n";
        }
    }
    
    return 0;
}