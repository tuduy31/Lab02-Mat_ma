#pragma once
#include <string>
#include <vector> 
#include <openssl/evp.h> //High-level encrytion API
#include <openssl/rand.h> //Random number generator (tạo IV, salt, key)
#include <openssl/sha.h> //SHA-256 hashing (hash password)
using namespace std;
class CryptoUtils {
public:
    // Password hashing
    static string generateSalt(size_t length = 32); //Tạo chuỗi ngẫu nhiên để trộn với password 
    static string hashPassword(const string& password, const string& salt); //Hash password + salt để lưu vào database
    
    struct EncryptedData {
        vector<uint8_t> ciphertext; // Dữ liêụ mã hoá (không đọc được)
        vector<uint8_t> iv; // Giá trị ngẫu nhiên sau khi mã hoá
        vector<uint8_t> tag; // Chứng minh dữ liệu không bị sửa đổi
    };
    // AES-GCM encrytion 
    static vector<uint8_t> generateAESKey(); // Tạo mã hoá 256-bit ngẫu nhiên
    static EncryptedData encryptAES_GCM(const vector<uint8_t>& plaintext, const vector<uint8_t>& key); // Mã hoá dữ liệu, trả về  {ciphertext, iv, tag}
    static vector<uint8_t> decryptAES_GCM(const EncryptedData& encrypted, const vector<uint8_t>& key); // Giải mã, verify tag để đảm bảo dữ liệu không bị sửa
    // Base64 encoding/decoding: chuyển binary data -> text (để gửi qua json/http)
    static string base64Encode(const vector<uint8_t>& data); 
    static vector<uint8_t> base64Decode(const string& encoded); 
    // Random token generation 
    static string generateToken(size_t length = 32); // Tạo token ngẫu nhiên cho session hoặc share link
};