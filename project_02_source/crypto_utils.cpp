#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <cstring>
using namespace std;
string CryptoUtils::generateSalt(size_t length) {
    vector<uint8_t> salt(length); // Tạo vector 32 bytes
    if (RAND_bytes(salt.data(), length) != 1) { // Fill random bytes
        throw runtime_error("Failed to generate salt");
    }
    return base64Encode(salt); // Chuyển binary -> text
}

string CryptoUtils::hashPassword(const string& password, const string& salt) {
    string combined = password + salt; // "123" + "0v8s..."
    
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 32 bytes output
    SHA256_CTX sha256;
    SHA256_Init(&sha256); // Khởi tạo
    SHA256_Update(&sha256, combined.c_str(), combined.size()); // Hash
    SHA256_Final(hash, &sha256); // Hoàn thành
    
    return base64Encode(vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH));
}

vector<uint8_t> CryptoUtils::generateAESKey() {
    vector<uint8_t> key(32); //256 bit = 32 bytes
    if (RAND_bytes(key.data(), 32) != 1) { // Tạo ngẫu nhiên an toàn từ OpenSSL
        throw runtime_error("Failed to generate AES key");
    }
    return key;
}

CryptoUtils::EncryptedData CryptoUtils::encryptAES_GCM(
    const vector<uint8_t>& plaintext,
    const vector<uint8_t>& key) {
    // 1. Kiểm tra key
    if (key.size() != 32) {
        throw runtime_error("Key must be 256 bits");
    }
    // 2. Tạo struct kết quả
    EncryptedData result;
    result.iv.resize(12); // 96 bit IV cho GCM: đảm bảo mã hoá 1 plaintext cho kết quả khác nhau
    result.tag.resize(16); // 128-bit authentication tag: sẽ được tạo tự động, dùng verify dữ liệu không bị sửa
    // 3. Generate IV ngẫu nhiên
    if (RAND_bytes(result.iv.data(), 12) != 1) {
        throw runtime_error("Failed to generate IV");
    }
    // 4. Tạo Cipher Context: context chứa state của quá trình mã hoá
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("Failed to create cipher context");
    // 5. Khởi tạo mã hoá
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), result.iv.data()) != 1) { // Thuật toán AES-256 GCM
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption");
    }
    // 6. Mã hoá dữ liệu
    result.ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                         plaintext.data(), plaintext.size()) != 1) { // Mã hoá dữ liêụ thực tế
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed");
    }
    int ciphertext_len = len; // Số bytes đã mã hoá (có thể < plaintext do padding)
    // 7. Hoàn tất mã hoá
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) { // Xử lý phần dữ liệu cuối + padding 
        EVP_CIPHER_CTX_free(ctx); 
        throw runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);
    // 8. Lấy authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

vector<uint8_t> CryptoUtils::decryptAES_GCM(
    const EncryptedData& encrypted,
    const vector<uint8_t>& key) {
    
    if (key.size() != 32) {
        throw runtime_error("Key must be 256 bits");
    }
    // 1. Tạo context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("Failed to create cipher context");
    // 2. Khởi tạo giải mã
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          key.data(), encrypted.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }
    // 3. Giải mã dữ liệu
    vector<uint8_t> plaintext(encrypted.ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         encrypted.ciphertext.data(), 
                         encrypted.ciphertext.size()) != 1)  {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed");
    }
    int plaintext_len = len;
    // 4. Set tag để verify
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           const_cast<uint8_t*>(encrypted.tag.data())) != 1) { // Đưa tag vào để verify
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set authentication tag");
    }
    // 5. Hoàn tất & Verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { // Nếu tag không khớp -> Fail
        EVP_CIPHER_CTX_free(ctx); 
        throw runtime_error("Authentication failed");
    } // -> Đảm bảo dữ liệu không bị sửa đổi
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

string CryptoUtils::base64Encode(const vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem()); // Memory buffer
    BIO* b64 = BIO_new(BIO_f_base64()); // Base64 filter
    bio = BIO_push(b64, bio); // Chain filters
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Không xuống dòng
    // Bio: Basic I/O abstraction của OpenSSL
    // Chain: Memory buffer <- Base64 filter
    // Write binary -> Tự động encode sang base64
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(bio, &buffer);
    string result(buffer->data, buffer->length);
    
    BIO_free_all(bio);
    return result;
}

vector<uint8_t> CryptoUtils::base64Decode(const string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    vector<uint8_t> result(encoded.size());
    int decoded_len = BIO_read(bio, result.data(), encoded.size());
    if (decoded_len > 0) {
        result.resize(decoded_len);
    }
    // Base64 string -> Binary data
    BIO_free_all(bio);
    return result;
}

string CryptoUtils::generateToken(size_t length) {
    vector<uint8_t> token(length);
    if (RAND_bytes(token.data(), length) != 1) {
        throw runtime_error("Failed to generate token");
    }
    return base64Encode(token);
}