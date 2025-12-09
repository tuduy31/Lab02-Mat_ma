#include "crypto_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include "include/json.hpp"
#include <curl/curl.h>
using json = nlohmann::json;

// Helper function cho CURL response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class NoteClient {
private:
    string server_url = "http://localhost:8080"; // Địa chỉ server (có thể thay đổi)
    string auth_token; // Lưu token sau khi login: Token này sẽ gửi trong mọi request sau, Nếu rỗng -> Chưa login
    
    string httpPost(const string& endpoint, const string& data, 
                        const string& token = "") {
        CURL* curl = curl_easy_init(); //  Khởi tạo CURL session
        string response; // String để lưu server response
        if (curl) {
            string url = server_url + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L); // Đặt request = POST
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str()); // Đặt request body
            
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            if (!token.empty()) {
                string auth_header = "Authorization: Bearer " + token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); // Đặt headers
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback); // Hàm để xử lý response
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response); // Pointer đến string lưu response
            
            CURLcode res = curl_easy_perform(curl);
            
            curl_slist_free_all(headers); // Giải phóng headers
            curl_easy_cleanup(curl); // Giải phóng CURL session
        }
        
        return response;
    }
    // Gửi GET Request
    string httpGet(const string& endpoint, const string& token = "") {
        CURL* curl = curl_easy_init();
        string response;
        
        if (curl) {
            string url = server_url + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            
            struct curl_slist* headers = nullptr;
            if (!token.empty()) {
                string auth_header = "Authorization: Bearer " + token; // Chỉ cần thêm Authorization header nếu có token
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
    // Đăng ký
    bool registerUser(const string& username, const string& password) {
        json body = {{"username", username}, {"password", password}};
        string response = httpPost("/api/auth/register", body.dump());
        
        try {
            json resp = json::parse(response); // String -> JSON object
            if (resp["success"] == true) { // Truy cập field
                cout << "✓ Registration successful!\n";
                return true;
            }
        } catch (...) {} // Bắt mọi exception 
        
        cout << "✗ Registration failed: " << response << "\n";
        return false;
    }
    // Đăng nhập 
    bool login(const string& username, const string& password) {
        json body = {{"username", username}, {"password", password}};
        
        // DEBUG: In ra request
        cout << "[DEBUG] Sending login request...\n";
        cout << "[DEBUG] Body: " << body.dump() << "\n";
        
        string response = httpPost("/api/auth/login", body.dump());
        
        // DEBUG: In ra response
        cout << "[DEBUG] Response: " << response << "\n";
        
        try {
            json resp = json::parse(response);
            if (resp.contains("token")) { // Kiểmn tra key tồn tại 
                auth_token = resp["token"];
                cout << "✓ Login successful! Token: " << auth_token.substr(0, 20) << "...\n";
                return true;
            } else {
                cout << "[DEBUG] No token in response\n";
            }
        } catch (const exception& e) {
            cout << "[DEBUG] JSON parse error: " << e.what() << "\n";
        }
        
        cout << "✗ Login failed\n";
        return false;
    }
    // Upload Note đã mã hoá
    bool uploadNote(const string& filepath) {
        if (auth_token.empty()) {
        cout << "✗ Not logged in! Please login first (Choice 2)\n";
        return false;
        }
    
        cout << "[DEBUG] Token length: " << auth_token.length() << "\n";
        cout << "[DEBUG] Token: " << auth_token.substr(0, 30) << "...\n";
        // Read file
        ifstream file(filepath, ios::binary);
        if (!file) {
            cout << "✗ Cannot open file: " << filepath << "\n";
            return false;
        }
        
        vector<uint8_t> plaintext((istreambuf_iterator<char>(file)),
                                       istreambuf_iterator<char>());
        file.close();
        
        cout << "📄 File size: " << plaintext.size() << " bytes\n";
        
        // Generate key and encrypt
        auto key = CryptoUtils::generateAESKey();
        auto encrypted = CryptoUtils::encryptAES_GCM(plaintext, key);
        
        cout << "🔒 Encrypted successfully\n";
        
        // Save key locally
        string key_file = filepath + ".key";
        ofstream key_out(key_file, ios::binary);
        key_out.write(reinterpret_cast<const char*>(key.data()), key.size());
        key_out.close();
        
        cout << "🔑 Key saved to: " << key_file << "\n";
        
        // Upload to server
        json body = {
            {"filename", filepath},
            {"encrypted_data", CryptoUtils::base64Encode(encrypted.ciphertext)},
            {"iv", CryptoUtils::base64Encode(encrypted.iv)},
            {"tag", CryptoUtils::base64Encode(encrypted.tag)}
        };
        cout << "[DEBUG] Sending request with token: " << auth_token.substr(0, 20) << "...\n";
        string response = httpPost("/api/notes/create", body.dump(), auth_token);
        cout << "[DEBUG] Response: " << response << "\n";
    
        
        string response = httpPost("/api/notes/create", body.dump(), auth_token);
        
        try {
            json resp = json::parse(response);
            if (resp.contains("note_id")) {
                cout << "✓ Note uploaded! ID: " << resp["note_id"] << "\n";
                return true;
            }
        } catch (...) {}
        
        cout << "✗ Upload failed: " << response << "\n";
        return false;
    }
    // Danh sách các Note của User
    void listNotes() {
        string response = httpGet("/api/notes/list", auth_token);
        
        try {
            json resp = json::parse(response);
            if (resp.contains("notes")) {
                auto notes = resp["notes"];
                cout << "\n📋 Your notes (" << notes.size() << "):\n";
                cout << "----------------------------------------\n";
                for (const auto& note : notes) {
                    cout << "  ID: " << note["note_id"] 
                             << " | File: " << note["filename"] << "\n";
                }
                cout << "----------------------------------------\n";
            }
        } catch (...) {
            cout << "✗ Failed to list notes\n";
        }
    }
    // Download Note 
    bool downloadNote(int note_id, const string& key_file, 
                     const string& output_file) {
        // Get note from server
        string response = httpGet("/api/notes/" + to_string(note_id), auth_token);
        
        try {
            json resp = json::parse(response);
            
            // Read key
            ifstream key_in(key_file, ios::binary);
            if (!key_in) {
                cout << "✗ Cannot open key file: " << key_file << "\n";
                return false;
            }
            vector<uint8_t> key(32);
            key_in.read(reinterpret_cast<char*>(key.data()), 32);
            key_in.close();
            
            // Decrypt
            CryptoUtils::EncryptedData encrypted;
            encrypted.ciphertext = CryptoUtils::base64Decode(resp["encrypted_data"]);
            encrypted.iv = CryptoUtils::base64Decode(resp["iv"]);
            encrypted.tag = CryptoUtils::base64Decode(resp["tag"]);
            
            auto plaintext = CryptoUtils::decryptAES_GCM(encrypted, key);
            
            // Write to file
            ofstream out(output_file, ios::binary);
            out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
            out.close();
            
            cout << "✓ Note downloaded and decrypted: " << output_file << "\n";
            return true;
            
        } catch (const exception& e) {
            cout << "✗ Download failed: " << e.what() << "\n";
            return false;
        }
    }
};

void printMenu() {
    cout << "\n=== Secure Note Sharing Client ===\n";
    cout << "1. Register\n";
    cout << "2. Login\n";
    cout << "3. Upload Note\n";
    cout << "4. List Notes\n";
    cout << "5. Download Note\n";
    cout << "0. Exit\n";
    cout << "Choice: ";
}

int main() {
    NoteClient client;
    
    while (true) {
        printMenu();
        
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice == 0) break;
        
        switch (choice) {
            case 1: {
                string username, password;
                cout << "Username: "; getline(cin, username);
                cout << "Password: "; getline(cin, password);
                client.registerUser(username, password);
                break;
            }
            case 2: {
                string username, password;
                cout << "Username: "; getline(cin, username);
                cout << "Password: "; getline(cin, password);
                client.login(username, password);
                break;
            }
            case 3: {
                string filepath;
                cout << "File path: "; getline(cin, filepath);
                client.uploadNote(filepath);
                break;
            }
            case 4: {
                client.listNotes();
                break;
            }
            case 5: {
                int note_id;
                string key_file, output_file;
                cout << "Note ID: "; cin >> note_id;
                cin.ignore();
                cout << "Key file: "; getline(cin, key_file);
                cout << "Output file: "; getline(cin, output_file);
                client.downloadNote(note_id, key_file, output_file);
                break;
            }
            default:
                cout << "Invalid choice\n";
        }
    }
    
    return 0;
}