#pragma once
#include <sqlite3.h>
#include <string>
#include <optional>
#include <vector>

struct NoteData {
    int note_id;
    std::string encrypted_data;
    std::string iv;
    std::string tag;
    std::string filename;
};

struct ShareLinkData {
    int link_id;
    int note_id;
    std::string url_token;
    std::string encrypted_key;
    bool is_expired;
    int max_access;
    int current_access;
};

class Database {
public:
    Database(const std::string& db_path);
    ~Database();
    
    bool createUser(const std::string& username, 
                   const std::string& password_hash,
                   const std::string& salt);
    std::optional<std::pair<std::string, std::string>> getUser(const std::string& username);
    int getUserId(const std::string& username);
    
    int createNote(int user_id, const std::string& encrypted_data,
                   const std::string& iv, const std::string& tag,
                   const std::string& filename);
    std::optional<NoteData> getNote(int note_id);
    std::vector<NoteData> listNotes(int user_id);
    bool deleteNote(int note_id, int user_id);
    
    bool createShareLink(int note_id, const std::string& url_token,
                        const std::string& encrypted_key,
                        int expire_minutes, int max_access);
    std::optional<ShareLinkData> getShareLink(const std::string& url_token);
    void incrementAccessCount(const std::string& url_token);
    
private:
    sqlite3* db;
    void initTables();
    void checkError(int rc, const std::string& msg);
};