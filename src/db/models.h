#include <string>

struct User {
    int32_t id;
    std::string username;
    std::string email;
    std::string password_hash;
    int32_t visit_count = 0;
    std::string created_at;
    std::string last_login;
};

struct UserSession {
    int32_t id;
    std::string session_token;
    std::string username;
    std::string created_at;
    std::string expires_at;
};