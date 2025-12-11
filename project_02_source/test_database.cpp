#include "database.h"
#include "crypto_utils.h"
#include <iostream>
#include <cassert>

void test_user_operations() {
    std::cout << "=== Test 1: User Operations ===\n";
    
    Database db("test.db");
    
    // Test 1.1: Tạo user mới
    std::string salt = CryptoUtils::generateSalt();
    std::string hash = CryptoUtils::hashPassword("testpass", salt);
    
    bool created = db.createUser("testuser", hash, salt);
    assert(created);
    std::cout << "✓ Test 1.1: Create user successful\n";
    
    // Test 1.2: Tạo user trùng username phải fail
    bool duplicate = db.createUser("testuser", hash, salt);
    assert(!duplicate);
    std::cout << "✓ Test 1.2: Duplicate username rejected\n";
    
    // Test 1.3: Get user phải trả về đúng hash và salt
    auto user_data = db.getUser("testuser");
    assert(user_data.has_value());
    assert(user_data->first == hash);
    assert(user_data->second == salt);
    std::cout << "✓ Test 1.3: Get user returns correct data\n";
    
    // Test 1.4: Get user không tồn tại
    auto no_user = db.getUser("nonexistent");
    assert(!no_user.has_value());
    std::cout << "✓ Test 1.4: Non-existent user returns nullopt\n";
    
    // Test 1.5: Get user ID
    int user_id = db.getUserId("testuser");
    assert(user_id > 0);
    std::cout << "✓ Test 1.5: Get user ID successful\n";
}

void test_note_operations() {
    std::cout << "\n=== Test 2: Note Operations ===\n";
    
    Database db("test.db");
    int user_id = db.getUserId("testuser");
    
    // Test 2.1: Tạo note
    int note_id = db.createNote(user_id, "encrypted_data", "iv", "tag", "test.txt");
    assert(note_id > 0);
    std::cout << "✓ Test 2.1: Create note successful (ID: " << note_id << ")\n";
    
    // Test 2.2: Get note
    auto note = db.getNote(note_id);
    assert(note.has_value());
    assert(note->filename == "test.txt");
    assert(note->encrypted_data == "encrypted_data");
    std::cout << "✓ Test 2.2: Get note returns correct data\n";
    
    // Test 2.3: List notes
    auto notes = db.listNotes(user_id);
    assert(notes.size() >= 1);
    std::cout << "✓ Test 2.3: List notes returns " << notes.size() << " note(s)\n";
    
    // Test 2.4: Get note owner
    int owner_id = db.getNoteOwner(note_id);
    assert(owner_id == user_id);
    std::cout << "✓ Test 2.4: Get note owner correct\n";
    
    // Test 2.5: Delete note
    bool deleted = db.deleteNote(note_id, user_id);
    assert(deleted);
    
    auto deleted_note = db.getNote(note_id);
    assert(!deleted_note.has_value());
    std::cout << "✓ Test 2.5: Delete note successful\n";
}

void test_share_links() {
    std::cout << "\n=== Test 3: Share Links ===\n";
    
    Database db("test.db");
    int user_id = db.getUserId("testuser");
    
    // Tạo note để share
    int note_id = db.createNote(user_id, "data", "iv", "tag", "share_test.txt");
    
    // Test 3.1: Tạo share link
    bool created = db.createShareLink(note_id, "test_token", "enc_key", 60, 5);
    assert(created);
    std::cout << "✓ Test 3.1: Create share link successful\n";
    
    // Test 3.2: Get share link
    auto share = db.getShareLink("test_token");
    assert(share.has_value());
    assert(share->note_id == note_id);
    assert(share->encrypted_key == "enc_key");
    assert(share->max_access == 5);
    assert(share->current_access == 0);
    assert(!share->is_expired);
    std::cout << "✓ Test 3.2: Get share link returns correct data\n";
    
    // Test 3.3: Increment access count
    db.incrementAccessCount("test_token");
    auto share2 = db.getShareLink("test_token");
    assert(share2->current_access == 1);
    std::cout << "✓ Test 3.3: Increment access count works\n";
    
    // Test 3.4: Test expired link (tạo link đã expired)
    bool expired_created = db.createShareLink(note_id, "expired_token", "key", -60, 5);
    // ⚠️ expire_minutes = -60 → datetime('now', '-60 minutes') = 60 phút trước
    auto expired_share = db.getShareLink("expired_token");

    if (!expired_share.has_value()) {
        std::cout << "✗ Test 3.4: Failed to create share link\n";
        throw std::runtime_error("Failed to create expired share link");
    }

    assert(expired_share->is_expired);
    std::cout << "✓ Test 3.4: Expired link detected\n";
}

int main() {
    std::cout << "======================================\n";
    std::cout << "     DATABASE UNIT TESTS\n";
    std::cout << "======================================\n\n";
    
    // Xóa test database cũ
    system("rm -f test.db");
    
    try {
        test_user_operations();
        test_note_operations();
        test_share_links();
        
        std::cout << "\n======================================\n";
        std::cout << "✅ ALL DATABASE TESTS PASSED!\n";
        std::cout << "======================================\n";
        
        // Cleanup
        system("rm -f test.db");
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ TEST FAILED: " << e.what() << "\n";
        system("rm -f test.db");
        return 1;
    }
}