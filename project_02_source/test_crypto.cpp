#include "crypto_utils.h"
#include <iostream>
#include <cassert>
#include <vector>

void test_password_hashing() {
    std::cout << "=== Test 1: Password Hashing ===\n";
    
    // Test 1.1: Hash với cùng password và salt phải giống nhau
    std::string password = "mypassword123";
    std::string salt = CryptoUtils::generateSalt();
    
    std::string hash1 = CryptoUtils::hashPassword(password, salt);
    std::string hash2 = CryptoUtils::hashPassword(password, salt);
    
    assert(hash1 == hash2);
    std::cout << "✓ Test 1.1: Same password + salt → Same hash\n";
    
    // Test 1.2: Hash với khác salt phải khác nhau
    std::string salt2 = CryptoUtils::generateSalt();
    std::string hash3 = CryptoUtils::hashPassword(password, salt2);
    
    assert(hash1 != hash3);
    std::cout << "✓ Test 1.2: Same password + different salt → Different hash\n";
    
    // Test 1.3: Salt phải unique
    std::string salt3 = CryptoUtils::generateSalt();
    assert(salt != salt2);
    assert(salt2 != salt3);
    std::cout << "✓ Test 1.3: Generated salts are unique\n";
}

void test_aes_encryption() {
    std::cout << "\n=== Test 2: AES-GCM Encryption ===\n";
    
    // Test 2.1: Encrypt và decrypt phải trả về plaintext gốc
    std::string plaintext = "This is a secret message!";
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    
    auto key = CryptoUtils::generateAESKey();
    auto encrypted = CryptoUtils::encryptAES_GCM(data, key);
    auto decrypted = CryptoUtils::decryptAES_GCM(encrypted, key);
    
    std::string result(decrypted.begin(), decrypted.end());
    assert(result == plaintext);
    std::cout << "✓ Test 2.1: Encrypt → Decrypt = Original plaintext\n";
    
    // Test 2.2: IV phải unique mỗi lần encrypt
    auto encrypted2 = CryptoUtils::encryptAES_GCM(data, key);
    assert(encrypted.iv != encrypted2.iv);
    std::cout << "✓ Test 2.2: Different encryptions have different IVs\n";
    
    // Test 2.3: Ciphertext phải khác với plaintext
    assert(encrypted.ciphertext != data);
    std::cout << "✓ Test 2.3: Ciphertext differs from plaintext\n";
    
    // Test 2.4: Key sai phải fail
    try {
        auto wrong_key = CryptoUtils::generateAESKey();
        auto decrypted_wrong = CryptoUtils::decryptAES_GCM(encrypted, wrong_key);
        assert(false); // Không nên đến đây
    } catch (const std::exception& e) {
        std::cout << "✓ Test 2.4: Wrong key causes decryption failure\n";
    }
    
    // Test 2.5: Modified ciphertext phải fail (integrity check)
    try {
        auto modified = encrypted;
        modified.ciphertext[0] ^= 0xFF; // Flip bits
        auto decrypted_modified = CryptoUtils::decryptAES_GCM(modified, key);
        assert(false); // Không nên đến đây
    } catch (const std::exception& e) {
        std::cout << "✓ Test 2.5: Modified ciphertext detected (integrity check)\n";
    }
}

void test_base64() {
    std::cout << "\n=== Test 3: Base64 Encoding ===\n";
    
    // Test 3.1: Encode và decode phải trả về data gốc
    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    std::string encoded = CryptoUtils::base64Encode(data);
    auto decoded = CryptoUtils::base64Decode(encoded);
    
    assert(data == decoded);
    std::cout << "✓ Test 3.1: Base64 encode → decode = Original data\n";
    
    // Test 3.2: Binary data phải encode được
    std::vector<uint8_t> binary_data = {0x00, 0xFF, 0xAB, 0xCD, 0xEF};
    std::string encoded_binary = CryptoUtils::base64Encode(binary_data);
    auto decoded_binary = CryptoUtils::base64Decode(encoded_binary);
    
    assert(binary_data == decoded_binary);
    std::cout << "✓ Test 3.2: Binary data encodes/decodes correctly\n";
}

void test_token_generation() {
    std::cout << "\n=== Test 4: Token Generation ===\n";
    
    // Test 4.1: Tokens phải unique
    std::string token1 = CryptoUtils::generateToken(32);
    std::string token2 = CryptoUtils::generateToken(32);
    std::string token3 = CryptoUtils::generateToken(32);
    
    assert(token1 != token2);
    assert(token2 != token3);
    assert(token1 != token3);
    std::cout << "✓ Test 4.1: Generated tokens are unique\n";
    
    // Test 4.2: Token length phải đúng
    assert(token1.length() > 0);
    std::cout << "✓ Test 4.2: Token has non-zero length\n";
}

int main() {
    std::cout << "======================================\n";
    std::cout << "   CRYPTOGRAPHY UNIT TESTS\n";
    std::cout << "======================================\n\n";
    
    try {
        test_password_hashing();
        test_aes_encryption();
        test_base64();
        test_token_generation();
        
        std::cout << "\n======================================\n";
        std::cout << "✅ ALL TESTS PASSED!\n";
        std::cout << "======================================\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ TEST FAILED: " << e.what() << "\n";
        return 1;
    }
}