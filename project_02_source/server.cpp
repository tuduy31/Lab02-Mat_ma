#include "include/httplib.h"
#include "include/json.hpp"
#include "crypto_utils.h"
#include "database.h"
#include <iostream>
#include <map>
#include <chrono>

using json = nlohmann::json;

struct Session {
    int user_id;
    std::string username;
    std::chrono::system_clock::time_point expire_at;
};

std::map<std::string, Session> sessions;

std::string createSession(int user_id, const std::string& username) {
    std::string token = CryptoUtils::generateToken(32);
    Session session;
    session.user_id = user_id;
    session.username = username;
    session.expire_at = std::chrono::system_clock::now() + std::chrono::hours(24);
    sessions[token] = session;
    return token;
}

bool validateToken(const std::string& token, int& user_id) {
    auto it = sessions.find(token);
    if (it == sessions.end()) return false;
    
    if (std::chrono::system_clock::now() > it->second.expire_at) {
        sessions.erase(it);
        return false;
    }
    
    user_id = it->second.user_id;
    return true;
}

std::string extractToken(const httplib::Request& req) {
    std::string auth_header = req.get_header_value("Authorization");
    if (auth_header.substr(0, 7) == "Bearer ") {
        return auth_header.substr(7);
    }
    return "";
}

int main() {
    try {
        Database db("notes.db");
        httplib::Server svr;
        
        std::cout << "=== Secure Note Sharing Server ===\n";
        std::cout << "Starting server on http://localhost:8080\n\n";
        
        svr.set_default_headers({
            {"Access-Control-Allow-Origin", "*"},
            {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
            {"Access-Control-Allow-Headers", "Content-Type, Authorization"}
        });
        
        // POST /api/auth/register
        svr.Post("/api/auth/register", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                json body = json::parse(req.body);
                std::string username = body["username"];
                std::string password = body["password"];
                
                std::cout << "[REGISTER] Username: " << username << "\n";
                
                std::string salt = CryptoUtils::generateSalt();
                std::string hash = CryptoUtils::hashPassword(password, salt);
                
                if (db.createUser(username, hash, salt)) {
                    json response = {{"success", true}, {"message", "User created"}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[REGISTER] Success\n";
                } else {
                    res.status = 400;
                    json response = {{"error", "Username already exists"}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[REGISTER] Failed - user exists\n";
                }
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
                std::cerr << "[REGISTER] Error: " << e.what() << "\n";
            }
        });
        
        // POST /api/auth/login
        svr.Post("/api/auth/login", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                json body = json::parse(req.body);
                std::string username = body["username"];
                std::string password = body["password"];
                
                std::cout << "[LOGIN] Username: " << username << "\n";
                
                auto user_data = db.getUser(username);
                if (!user_data) {
                    res.status = 401;
                    json response = {{"error", "Invalid credentials"}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[LOGIN] Failed - user not found\n";
                    return;
                }
                
                auto [stored_hash, salt] = *user_data;
                std::string computed_hash = CryptoUtils::hashPassword(password, salt);
                
                if (computed_hash == stored_hash) {
                    int user_id = db.getUserId(username);
                    std::string token = createSession(user_id, username);
                    json response = {{"token", token}, {"user_id", user_id}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[LOGIN] Success\n";
                } else {
                    res.status = 401;
                    json response = {{"error", "Invalid credentials"}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[LOGIN] Failed - wrong password\n";
                }
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
                std::cerr << "[LOGIN] Error: " << e.what() << "\n";
            }
        });
        
        // POST /api/notes/create
        svr.Post("/api/notes/create", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                std::string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                
                json body = json::parse(req.body);
                std::string filename = body["filename"];
                std::string encrypted_data = body["encrypted_data"];
                std::string iv = body["iv"];
                std::string tag = body["tag"];
                
                int note_id = db.createNote(user_id, encrypted_data, iv, tag, filename);
                
                if (note_id > 0) {
                    json response = {{"note_id", note_id}, {"message", "Note created"}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[NOTE] Created note_id=" << note_id << "\n";
                } else {
                    res.status = 500;
                    json response = {{"error", "Failed to create note"}};
                    res.set_content(response.dump(), "application/json");
                }
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /api/notes/list
        svr.Get("/api/notes/list", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                std::string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                
                auto notes = db.listNotes(user_id);
                json notes_json = json::array();
                
                for (const auto& note : notes) {
                    json note_obj = {
                        {"note_id", note.note_id},
                        {"filename", note.filename}
                    };
                    notes_json.push_back(note_obj);
                }
                
                json response = {{"notes", notes_json}};
                res.set_content(response.dump(), "application/json");
                std::cout << "[LIST] Returned " << notes.size() << " notes\n";
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /api/notes/:id
        svr.Get(R"(/api/notes/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                std::string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                
                int note_id = std::stoi(req.matches[1]);
                auto note = db.getNote(note_id);
                
                if (note) {
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
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // POST /api/share/create
        svr.Post("/api/share/create", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                std::string token = extractToken(req);
                int user_id;
                if (!validateToken(token, user_id)) {
                    res.status = 401;
                    json response = {{"error", "Unauthorized"}};
                    res.set_content(response.dump(), "application/json");
                    return;
                }
                
                json body = json::parse(req.body);
                int note_id = body["note_id"];
                std::string encrypted_key = body["encrypted_key"];
                int expire_minutes = body.value("expire_minutes", 60);
                int max_access = body.value("max_access", -1);
                
                std::string url_token = CryptoUtils::generateToken(32);
                
                if (db.createShareLink(note_id, url_token, encrypted_key, expire_minutes, max_access)) {
                    std::string share_url = "http://localhost:8080/share/" + url_token;
                    json response = {{"share_url", share_url}, {"token", url_token}};
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[SHARE] Created link for note_id=" << note_id << "\n";
                } else {
                    res.status = 500;
                    json response = {{"error", "Failed to create share link"}};
                    res.set_content(response.dump(), "application/json");
                }
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        // GET /share/:token
        svr.Get(R"(/share/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                std::string token = req.matches[1];
                
                auto share_data = db.getShareLink(token);
                if (!share_data) {
                    res.status = 404;
                    res.set_content("Share link not found", "text/plain");
                    return;
                }
                
                if (share_data->is_expired) {
                    res.status = 410;
                    res.set_content("Share link has expired", "text/plain");
                    return;
                }
                
                if (share_data->max_access > 0 && share_data->current_access >= share_data->max_access) {
                    res.status = 410;
                    res.set_content("Share link has reached maximum access count", "text/plain");
                    return;
                }
                
                db.incrementAccessCount(token);
                
                auto note = db.getNote(share_data->note_id);
                if (note) {
                    json response = {
                        {"encrypted_data", note->encrypted_data},
                        {"iv", note->iv},
                        {"tag", note->tag},
                        {"encrypted_key", share_data->encrypted_key},
                        {"filename", note->filename}
                    };
                    res.set_content(response.dump(), "application/json");
                    std::cout << "[SHARE] Accessed note via token\n";
                }
            } catch (const std::exception& e) {
                res.status = 500;
                json response = {{"error", e.what()}};
                res.set_content(response.dump(), "application/json");
            }
        });
        
        svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("Secure Note Sharing Server is running", "text/plain");
        });
        
        std::cout << "Server listening on http://localhost:8080\n";
        std::cout << "Press Ctrl+C to stop\n\n";
        
        svr.listen("0.0.0.0", 8080);
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
