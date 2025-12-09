#include "include/httplib.h" // Thư viện HTTP server đơn giản, xử lý request/response
#include "include/json.hpp"// Parse và tạo JSON (API communication)
#include "crypto_utils.h" // Các hàm mã hoá
#include "database.h" // Tương tác với SQLitea
#include <iostream>
#include <map>
#include <chrono> // Xử lý thời gian (cho session expire)

using json = nlohmann::json;
using namespace std;
// Quản lý đăng nhập
struct Session { // Lưu thông tin user đã login 
    int user_id; // ID dùng trong database
    string username; // Tên user
    chrono::system_clock::time_point expire_at; // Thời điểm token hết hạn
};

map<string, Session> sessions;

string createSession(int user_id, const string& username) { // Tạo session sau khi login
    // 1. Tạo token ngẫu nhiên
    string token = CryptoUtils::generateToken(32);
    // 2. Tạo session object
    Session session;
    session.user_id = user_id; // Lưu user_id
    session.username = username; // Lưu username
    session.expire_at = chrono::system_clock::now() + chrono::hours(24); // Lưu expire_at = now + 24
    // 3. Lưu vào map
    sessions[token] = session;
    // 4. Trả về token
    return token;
}

bool validateToken(const string& token, int& user_id) { // Kiểm tra token hợp lệ
    // 1. Tìm token trong Map
    auto it = sessions.find(token); //Tìm token trong map
    if (it == sessions.end()) return false; // Không tìm thấy -> Token không hợp lệ
    
    if (chrono::system_clock::now() > it->second.expire_at) {
        sessions.erase(it);
        return false;
    }
    
    user_id = it->second.user_id;
    return true;
}

string extractToken(const httplib::Request& req) { // Lấy Token từ HTTP header
    // 1. Lấy Header "Authorization"
    string auth_header = req.get_header_value("Authorization");
    // 2. KIỂM TRA FORMAT "Bearer <token>"
    if (auth_header.substr(0, 7) == "Bearer ") {
        return auth_header.substr(7);
    }
    return "";
}

int main() {
    try {
        // 1. MỞ DATABASE
        Database db("notes.db");
        httplib::Server svr;
        // 2. TẠO HTTP SERVER
        cout << "=== Secure Note Sharing Server ===\n";
        cout << "Starting server on http://localhost:8080\n\n";
        // 3. SET CORS HEADERS (Cho phép cross-origin requests)
        svr.set_default_headers({
            {"Access-Control-Allow-Origin", "*"},
            {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
            {"Access-Control-Allow-Headers", "Content-Type, Authorization"}
        });
        
        // POST /api/auth/register
        svr.Post("/api/auth/register", [&](const httplib::Request& req, httplib::Response& res) {
            // svr.Post(): Define endpoint nhận POST request
            // "/api/auth/register": URL path
            // Lambda function [&]: Capture tất cả biến bên ngoài by reference
            // req: Request object (chứa body, headers)
            // res: Response object (set status, body)
            try {
                // 1. PARSE JSON BODY
                json body = json::parse(req.body);
                string username = body["username"];
                string password = body["password"];
                
                cout << "[REGISTER] Username: " << username << "\n";
                // 2. HASH PASSWORD
                string salt = CryptoUtils::generateSalt();
                string hash = CryptoUtils::hashPassword(password, salt);
                 // 3. LƯU VÀO DATABASE
                if (db.createUser(username, hash, salt)) {
                    json response = {{"success", true}, {"message", "User created"}};
                    res.set_content(response.dump(), "application/json"); // Set response body
                    cout << "[REGISTER] Success\n";
                } else {
                    res.status = 400; // Set HTTP status 400 (Bad Request)
                    json response = {{"error", "Username already exists"}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[REGISTER] Failed - user exists\n";
                }
            } catch (const exception& e) {
                res.status = 500; // HTTP 500 (Internal Server Error)
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
                cerr << "[REGISTER] Error: " << e.what() << "\n";
            }
        });
        
        // POST /api/auth/login
        svr.Post("/api/auth/login", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. PARSE REQUEST
                json body = json::parse(req.body);
                string username = body["username"];
                string password = body["password"];
                
                cout << "[LOGIN] Username: " << username << "\n";
                // 2. LẤY USER TỪ DATABASE
                auto user_data = db.getUser(username);
                if (!user_data) {
                    res.status = 401;
                    json response = {{"error", "Invalid credentials"}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[LOGIN] Failed - user not found\n";
                    return;
                }
                // 3. UNPACK HASH VÀ SALT
                auto [stored_hash, salt] = *user_data;
                // 4. HASH PASSWORD NHẬP VÀO
                string computed_hash = CryptoUtils::hashPassword(password, salt);
                 // 5. SO SÁNH HASH
                if (computed_hash == stored_hash) {
                    // LOGIN THÀNH CÔNG
                    int user_id = db.getUserId(username);
                    string token = createSession(user_id, username);
                    json response = {{"token", token}, {"user_id", user_id}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[LOGIN] Success\n";
                } else {
                    // PASSWORD SAI
                    res.status = 401;
                    json response = {{"error", "Invalid credentials"}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[LOGIN] Failed - wrong password\n";
                }
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
                cerr << "[LOGIN] Error: " << e.what() << "\n";
            }
        });
        
        // POST /api/notes/create
        svr.Post("/api/notes/create", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. VALIDATE TOKEN
                string token = extractToken(req); // Lấy token từ header
                int user_id;
                if (!validateToken(token, user_id)) { // Kiểm tra + lấy user_id
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                // 2. PARSE NOTE DATA
                json body = json::parse(req.body);
                string filename = body["filename"];
                string encrypted_data = body["encrypted_data"];
                string iv = body["iv"];
                string tag = body["tag"];
                // 3. LƯU VÀO DATABASE
                int note_id = db.createNote(user_id, encrypted_data, iv, tag, filename);
                
                if (note_id > 0) {
                    json response = {{"note_id", note_id}, {"message", "Note created"}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[NOTE] Created note_id=" << note_id << "\n"; // Response trả về note_id cho client
                } else {
                    res.status = 500;
                    json response = {{"error", "Failed to create note"}};
                    res.set_content(response.dump(), "application/json");
                }
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /api/notes/list
        svr.Get("/api/notes/list", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. VALIDATE TOKEN
                string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                // 2. LẤY DANH SÁCH NOTES
                auto notes = db.listNotes(user_id);
                // 3. TẠO JSON ARRAY
                json notes_json = json::array(); // Tạo JSON array rổng []
                // Loop qua từng note
                for (const auto& note : notes) { 
                    // Tạo JSON object cho mỗi note
                    json note_obj = {
                        {"note_id", note.note_id},
                        {"filename", note.filename}
                    };
                    notes_json.push_back(note_obj);
                }
                // 4. TRẢ VỀ RESPONSE
                json response = {{"notes", notes_json}};
                res.set_content(response.dump(), "application/json");
                cout << "[LIST] Returned " << notes.size() << " notes\n";
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /api/notes/:id
        svr.Get(R"(/api/notes/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. VALIDATE TOKEN
                string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                // 2. EXTRACT NOTE_ID TỪ URL
                int note_id = stoi(req.matches[1]);
                // 3. LẤY NOTE TỪ DATABASE
                auto note = db.getNote(note_id);
                
                if (note) {
                    // CHECK OWNER
                    int note_owner_id = db.getNoteOwner(note_id);
                    if (note_owner_id != user_id) {
                        res.status = 403;  // Forbidden
                        json response = {{"error", "Access denied"}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                    // 4. TẠO JSON RESPONSE
                    json response = {
                        {"note_id", note->note_id},
                        {"filename", note->filename},
                        {"encrypted_data", note->encrypted_data},
                        {"iv", note->iv},
                        {"tag", note->tag}
                    };
                    res.set_content(response.dump(), "application/json");
                } else {
                    res.status = 404;
                    json response = {{"error", "Note not found"}};
                    res.set_content(response.dump(), "application/json");
                }
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // POST /api/share/create
        svr.Post("/api/share/create", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. VALIDATE TOKEN
                string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                // 2. PARSE REQUEST BODY
                json body = json::parse(req.body);
                int note_id = body["note_id"];
                string encrypted_key = body["encrypted_key"];
                int expire_minutes = body.value("expire_minutes", 60);
                int max_access = body.value("max_access", -1);
                // 3. GENERATE UNIQUE URL TOKEN
                string url_token = CryptoUtils::generateToken(32);
                // 4. TẠO SHARE LINK TRONG DATABASE
                if (db.createShareLink(note_id, url_token, encrypted_key, expire_minutes, max_access)) {
                    /*
                    link_id | note_id | url_token    | encrypted_key | expire_at           | max_access | current_access
                    --------|---------|--------------|---------------|---------------------|------------|---------------
                    1       | 5       | abc123xyz... | qP5LY6Mw...   | 2024-12-07 23:00:00 | 10         | 0
                    */
                   // 5. TẠO SHARE URL
                    string share_url = "http://localhost:8080/share/" + url_token;
                    json response = {{"share_url", share_url}, {"token", url_token}};
                    res.set_content(response.dump(), "application/json");
                    cout << "[SHARE] Created link for note_id=" << note_id << "\n";
                } else {
                    res.status = 500;
                    json response = {{"error", "Failed to create share link"}};
                    res.set_content(response.dump(), "application/json");
                }
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /share/:token
        svr.Get(R"(/share/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                // 1. EXTRACT TOKEN TỪ URL
                string token = req.matches[1];
                // 2. LẤY SHARE LINK INFO TỪ DATABASE
                auto share_data = db.getShareLink(token);
                if (!share_data) {
                    res.status = 404;
                    res.set_content("Share link not found", "text/plain");
                    return;
                }
                // 3. KIỂM TRA HẾT HẠN
                if (share_data->is_expired) {
                    res.status = 410;
                    res.set_content("Share link has expired", "text/plain");
                    return;
                }
                // 4. KIỂM TRA SỐ LẦN TRUY CẬP
                if (share_data->max_access > 0 && share_data->current_access >= share_data->max_access) {
                    res.status = 410;
                    res.set_content("Share link has reached maximum access count", "text/plain");
                    return;
                }
                // 5. TĂNG ACCESS COUNT
                db.incrementAccessCount(token);
                 // 6. LẤY NOTE DATA
                auto note = db.getNote(share_data->note_id);
                if (note) {
                    // 7. TẠO RESPONSE VỚI NOTE + ENCRYPTED KEY
                    json response = {
                        {"encrypted_data", note->encrypted_data},
                        {"iv", note->iv},
                        {"tag", note->tag},
                        {"encrypted_key", share_data->encrypted_key},
                        {"filename", note->filename}
                    };
                    res.set_content(response.dump(), "application/json");
                    cout << "[SHARE] Accessed note via token\n";
                }
            } catch (const exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("Secure Note Sharing Server is running", "text/plain");
        });
        
        cout << "Server listening on http://localhost:8080\n";
        cout << "Press Ctrl+C to stop\n\n";
        
        svr.listen("0.0.0.0", 8080);
        
    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
