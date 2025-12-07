#include "database.h"
#include <iostream>
#include <stdexcept>

Database::Database(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        throw std::runtime_error("Cannot open database");
    }
    initTables();
}

Database::~Database() {
    if (db) {
        sqlite3_close(db);
    }
}

void Database::checkError(int rc, const std::string& msg) {
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db);
        throw std::runtime_error(msg + ": " + error);
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
    
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string error = err_msg;
        sqlite3_free(err_msg);
        throw std::runtime_error("SQL error: " + error);
    }
    
    std::cout << "✓ Database tables initialized\n";
}

bool Database::createUser(const std::string& username, 
                         const std::string& password_hash,
                         const std::string& salt) {
    const char* sql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::optional<std::pair<std::string, std::string>> Database::getUser(const std::string& username) {
    const char* sql = "SELECT password_hash, salt FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sqlite3_finalize(stmt);
        return std::make_pair(hash, salt);
    }
    
    sqlite3_finalize(stmt);
    return std::nullopt;
}

int Database::getUserId(const std::string& username) {
    const char* sql = "SELECT user_id FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    int user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return user_id;
}

int Database::createNote(int user_id, const std::string& encrypted_data,
                        const std::string& iv, const std::string& tag,
                        const std::string& filename) {
    const char* sql = "INSERT INTO notes (user_id, encrypted_data, iv, tag, filename) VALUES (?, ?, ?, ?, ?)";
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
        return sqlite3_last_insert_rowid(db);
    }
    return -1;
}

std::optional<NoteData> Database::getNote(int note_id) {
    const char* sql = "SELECT note_id, encrypted_data, iv, tag, filename FROM notes WHERE note_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        NoteData note;
        note.note_id = sqlite3_column_int(stmt, 0);
        note.encrypted_data = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        note.iv = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        note.tag = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        note.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        sqlite3_finalize(stmt);
        return note;
    }
    
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<NoteData> Database::listNotes(int user_id) {
    std::vector<NoteData> notes;
    const char* sql = "SELECT note_id, encrypted_data, iv, tag, filename FROM notes WHERE user_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return notes;
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

bool Database::deleteNote(int note_id, int user_id) {
    const char* sql = "DELETE FROM notes WHERE note_id = ? AND user_id = ?";
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

bool Database::createShareLink(int note_id, const std::string& url_token,
                               const std::string& encrypted_key,
                               int expire_minutes, int max_access) {
    const char* sql = "INSERT INTO share_links (note_id, url_token, encrypted_key, expire_at, max_access) "
                     "VALUES (?, ?, ?, datetime('now', '+' || ? || ' minutes'), ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, note_id);
    sqlite3_bind_text(stmt, 2, url_token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encrypted_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, expire_minutes);
    sqlite3_bind_int(stmt, 5, max_access);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::optional<ShareLinkData> Database::getShareLink(const std::string& url_token) {
    const char* sql = "SELECT link_id, note_id, url_token, encrypted_key, "
                     "(expire_at < datetime('now')) as expired, max_access, current_access "
                     "FROM share_links WHERE url_token = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
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
    
    sqlite3_finalize(stmt);
    return std::nullopt;
}

void Database::incrementAccessCount(const std::string& url_token) {
    const char* sql = "UPDATE share_links SET current_access = current_access + 1 WHERE url_token = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, url_token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}