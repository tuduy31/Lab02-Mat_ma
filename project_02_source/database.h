#pragma once
#include <sqlite3.h> // Thư viện SQLite để làm việc với database
#include <string>
#include <optional> // Container có thể chứa hoặc không chứa giá trị (dùng cho query có thể fail)
#include <vector> // Dùng cho list notes
using namespace std;
struct NoteData {
    int note_id;
    string encrypted_data; // Đã được base64 encode
    string iv; // Đã được base64 encode
    string tag; // Đã được base64 encode
    string filename; 
};

struct ShareLinkData {
    int link_id;
    int note_id;
    string url_token; // Token duy nhất trong URL 
    string encrypted_key; // AES key đã được mã hoá để share
    bool is_expired; // True nếu link đã hết hạn
    int max_access; // Giới hạn số lần truy cập (-1 = unlimited)
    int current_access; // Đã truy cập nhiều lần
};

class Database {
public:
    Database(const string& db_path);
    ~Database();
    
    bool createUser(const string& username, 
                   const string& password_hash,
                   const string& salt); // Tạo user mới, trả về true/false
    optional<pair<string, string>> getUser(const string& username); // Lấy (password_hash, salt) của user: 
    // optional: có thể trả về  "không tìm thấy"
    // pair: trả về 2 giá trị cùng lúc
    int getUserId(const string& username); // Lấy user_id từ username 
    // Note operations
    int createNote(int user_id, const string& encrypted_data,
                   const string& iv, const string& tag,
                   const string& filename); // Tạo Note mới, trả về note_id (hoặc -1 nếu fail)
    optional<NoteData> getNote(int note_id); // Lấy note theo ID
    vector<NoteData> listNotes(int user_id); // Lấy tất cả notes của 1 user
    bool deleteNote(int note_id, int user_id); // Xoá note
    
    bool createShareLink(int note_id, const string& url_token,
                        const string& encrypted_key,
                        int expire_minutes, int max_access); // Tạo share link với thời gian expire
    optional<ShareLinkData> getShareLink(const string& url_token); // Lấy thông tin share link theo token
    void incrementAccessCount(const string& url_token); // Tăng số lần truy cập
    
private:
    sqlite3* db; // Con trỏ đến SQLite database
    void initTables(); // Tạo bảng nếu chưa tồn tại
    void checkError(int rc, const string& msg);
};