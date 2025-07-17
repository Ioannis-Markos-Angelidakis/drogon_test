#ifndef DATABASE_H
#define DATABASE_H

#include <drogon/utils/coroutine.h>
#include <sqlite_orm/sqlite_orm.h>
#include <string>

// Define structs to match original schema
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

// Define initStorage inline to avoid deduced return type issue
inline auto initStorage(const std::string& path) {
    using namespace sqlite_orm;
    return make_storage(path,
        make_table("users",
            make_column("id", &User::id, primary_key().autoincrement()),
            make_column("username", &User::username, unique()),
            make_column("email", &User::email),
            make_column("password_hash", &User::password_hash),
            make_column("visit_count", &User::visit_count),
            make_column("created_at", &User::created_at),
            make_column("last_login", &User::last_login)
        ),
        make_table("user_sessions",
            make_column("id", &UserSession::id, primary_key().autoincrement()),
            make_column("session_token", &UserSession::session_token, unique()),
            make_column("username", &UserSession::username),
            make_column("created_at", &UserSession::created_at),
            make_column("expires_at", &UserSession::expires_at)
        )
    );
}

// Define Storage type after initStorage
using Storage = decltype(initStorage(""));

// Declare initializeDatabase
using namespace drogon;
Task<void> initializeDatabase(std::shared_ptr<Storage> storage);

#endif