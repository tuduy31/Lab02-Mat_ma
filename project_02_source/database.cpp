#include "database.h"
#include <iostream>
#include <stdexcept>
#include <ctime>      // time(), localtime(), strftime()
#include <cstring>    // strftime
using namespace std;
Database::Database(const string& db_path) {
    // Mở database file (tạo mới nếu chưa có)
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        throw runtime_error("Cannot open database");
    }
    // Tạo bảng nếu chưa tồn tại
    initTables();
}

Database::~Database() {
    if (db) {
        sqlite3_close(db); // Đóng connection
    }
}

void Database::checkError(int rc, const string& msg) {
    if (rc != SQLITE_OK) {
        string error = sqlite3_errmsg(db);
        throw runtime_error(msg + ": " + error);
    }
}

void Database::initTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );     
        CREATE TABLE IF NOT EXISTS notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_data TEXT NOT NULL,
            iv TEXT NOT NULL,
            tag TEXT NOT NULL,
            filename TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        
        CREATE TABLE IF NOT EXISTS share_links (
            link_id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id INTEGER NOT NULL,
            url_token TEXT UNIQUE NOT NULL,
            encrypted_key TEXT NOT NULL,
            expire_at DATETIME NOT NULL,
            max_access INTEGER DEFAULT -1,
            current_access INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(note_id) REFERENCES notes(note_id)
        );
    )";
    // Bảng User
/*user_id | username | password_hash           | salt      | created_at
--------|----------|------------------------|-----------|-------------------
1       | giatuan   | EF92b3... (base64)     | Ab3d2... | 2024-12-05 10:30:00
2       | duy tu    | 3D8fa1... (base64)     | 8Bc4e... | 2024-12-05 11:15:00 */
    // Bảng notes
/*note_id | user_id | encrypted_data | iv      | tag     | filename    | created_at
--------|---------|----------------|---------|---------|-------------|-------------------
1       | 1       | aGVsbG8=       | MTIz... | YWJj... | secret.txt  | 2024-12-05 10:35:00
2       | 1       | d29ybGQ=       | NDU2... | ZGVm... | data.csv    | 2024-12-05 10:40:00
3       | 2       | Zm9vYmFy       | Nzg5... | Z2hp... | report.pdf  | 2024-12-05 11:20:00 */
    //Bảng share_links
/*link_id | note_id | url_token | encrypted_key | expire_at           | max_access | current_access
--------|---------|-----------|---------------|---------------------|------------|---------------
1       | 1       | abc123xyz | qP5LY6...     | 2024-12-05 11:35:00 | 5          | 2
2       | 2       | def456uvw | 3kDrich...    | 2024-12-06 10:00:00 | -1         | 10 */    
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg); // Thực thi SQL command
    if (rc != SQLITE_OK) {
        string error = err_msg; // Nếu có lỗi, SQLite sẽ ghi message vào đây
        sqlite3_free(err_msg); // Giải phóng memory của error message
        throw runtime_error("SQL error: " + error);
    }
    
    cout << "✓ Database tables initialized\n";
}

bool Database::createUser(const string& username, 
                         const string& password_hash,
                         const string& salt) {
    // 1. Chuẩn bị SQL Statement
    const char* sql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)"; // Placeholder cho giá trị (prepared statement)
    sqlite3_stmt* stmt; // Statement handle
    // 2. Prepare statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    // 3. Bind Paremeters (Điền giá trị vào ?)
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
    // 4. Excute Statement
    int rc = sqlite3_step(stmt);
    // 5. Cleanup
    sqlite3_finalize(stmt);
    // 6. Check result
    return rc == SQLITE_DONE;
}

optional<pair<string, string>> Database::getUser(const string& username) { // Lấy thông tin user
    const char* sql = "SELECT password_hash, salt FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Có dữ liệu - Lấy columns
        // SQLITE_ROW: Có dữ liệu -> Đọc columns
        // SQLITE_DONE: Không có dữ liệu -> User không tồn tại
        string hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        string salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sqlite3_finalize(stmt);
        return make_pair(hash, salt);
    }
    
    sqlite3_finalize(stmt);
    return nullopt;
}

int Database::getUserId(const string& username) { // Lấy thông tin user_id
    const char* sql = "SELECT user_id FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1; 
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    int user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0); // Lấy giá trị integer từ column
    }
    
    sqlite3_finalize(stmt);
    return user_id;
}

int Database::createNote(int user_id, const string& encrypted_data,
                        const string& iv, const string& tag,
                        const string& filename) { // Lưu note đã mã hoá thành công
    const char* sql = "INSERT INTO notes (user_id, encrypted_data, iv, tag, filename) VALUES (?, ?, ?, ?, ?)"; // Insert vào bảng note
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, encrypted_data.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, iv.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, tag.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, filename.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        return sqlite3_last_insert_rowid(db); // Lấy id vừa tạo
    }
    return -1;
}

optional<NoteData> Database::getNote(int note_id) { // Lấy note theo ID
    const char* sql = "SELECT note_id, encrypted_data, iv, tag, filename FROM notes WHERE note_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        NoteData note;
        note.note_id = sqlite3_column_int(stmt, 0); // Lấy column 0 (note_id) dưới dạng integer
        note.encrypted_data = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));// Trả từ const unsigned char* cast sang const char*, tạo string từ đó
        note.iv = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        note.tag = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        note.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        sqlite3_finalize(stmt);
        return note;
    }
    /*
    SELECT note_id, encrypted_data, iv, tag, filename
       0        1                2   3    4  ← Column indices
    */
    sqlite3_finalize(stmt);
    return nullopt;
}

vector<NoteData> Database::listNotes(int user_id) { // List của tất cả notes của user
    vector<NoteData> notes;
    const char* sql = "SELECT note_id, encrypted_data, iv, tag, filename FROM notes WHERE user_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return notes; // Trả về vector rỗng nếu lỗi
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NoteData note;
        note.note_id = sqlite3_column_int(stmt, 0);
        note.encrypted_data = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        note.iv = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        note.tag = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        note.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        notes.push_back(note);
    }
    
    sqlite3_finalize(stmt);
    return notes;
}

bool Database::deleteNote(int note_id, int user_id) { // Xoá Note
    const char* sql = "DELETE FROM notes WHERE note_id = ? AND user_id = ?"; // Cần note_id và user_id để xoá
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    sqlite3_bind_int(stmt, 2, user_id);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool Database::createShareLink(int note_id, const string& url_token,
                               const string& encrypted_key,
                               int expire_minutes, int max_access) {
    // ✅ Tính expire_at trước, rồi bind như string
    time_t now = time(nullptr);
    time_t expire_time = now + (expire_minutes * 60);
    
    // Convert timestamp thành SQLite datetime format
    char expire_str[30];
    struct tm* timeinfo = localtime(&expire_time);
    strftime(expire_str, sizeof(expire_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    const char* sql = "INSERT INTO share_links (note_id, url_token, encrypted_key, expire_at, max_access) "
                     "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "[DB] Prepare error: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    sqlite3_bind_text(stmt, 2, url_token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encrypted_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, expire_str, -1, SQLITE_TRANSIENT);  // ✅ Bind datetime string
    sqlite3_bind_int(stmt, 5, max_access);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

optional<ShareLinkData> Database::getShareLink(const string& url_token) { // Lấy thông tin share link
    const char* sql = "SELECT link_id, note_id, url_token, encrypted_key, "
                     "(expire_at < datetime('now')) as expired, max_access, current_access "
                     "FROM share_links WHERE url_token = ?";
    sqlite3_stmt* stmt;
    // Kiểm tra xem còn hạn hay không
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, url_token.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ShareLinkData link;
        link.link_id = sqlite3_column_int(stmt, 0);
        link.note_id = sqlite3_column_int(stmt, 1);
        link.url_token = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        link.encrypted_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        link.is_expired = sqlite3_column_int(stmt, 4) == 1;
        link.max_access = sqlite3_column_int(stmt, 5);
        link.current_access = sqlite3_column_int(stmt, 6);
        sqlite3_finalize(stmt);
        return link;
    }
    /*
    SELECT link_id, note_id, url_token, encrypted_key, (expire_at < datetime('now')) as expired, max_access, current_access
       ↑        ↑        ↑           ↑              ↑                                          ↑           ↑
       0        1        2           3              4                                          5           6
    */
    sqlite3_finalize(stmt);
    return nullopt;
}

void Database::incrementAccessCount(const string& url_token) {
    const char* sql = "UPDATE share_links SET current_access = current_access + 1 WHERE url_token = ?"; // Tăng số lần truy cập lên 1
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, url_token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}
int Database::getNoteOwner(int note_id) {
    const char* sql = "SELECT user_id FROM notes WHERE note_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    
    int user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return user_id;
}