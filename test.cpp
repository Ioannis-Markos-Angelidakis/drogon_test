#include <drogon/drogon.h>
#include <drogon/utils/coroutine.h>
#include <drogon/HttpResponse.h>
#include <drogon/utils/Utilities.h>
#include <sqlite_orm/sqlite_orm.h>
#include <random>
#include <sstream>
#include <unordered_map>
#include <chrono>
#include <mutex>

using namespace drogon;
using namespace std::chrono_literals;
using namespace sqlite_orm; 

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

struct RateLimitInfo {
    int32_t requests = 0;
    std::chrono::steady_clock::time_point window_start;
    std::chrono::steady_clock::time_point last_request;
};

class CustomRateLimiter {
private:
    std::unordered_map<std::string, RateLimitInfo> rate_limit_map;
    std::mutex rate_limit_mutex;
    int max_requests_per_window = 100;  
    std::chrono::seconds window_duration = std::chrono::seconds(60);  
    
public:
    bool isAllowed(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(rate_limit_mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto& info = rate_limit_map[client_ip];
        
        // If this is the first request or window has expired
        if (info.requests == 0 || (now - info.window_start) >= window_duration) {
            info.requests = 1;
            info.window_start = now;
            info.last_request = now;
            return true;
        }
        
        // Check if within rate limit
        if (info.requests < max_requests_per_window) {
            info.requests++;
            info.last_request = now;
            return true;
        }
        
        return false;
    }
    
    void setRateLimit(int32_t requests, int32_t seconds) {
        std::lock_guard<std::mutex> lock(rate_limit_mutex);
        max_requests_per_window = requests;
        window_duration = std::chrono::seconds(seconds);
    }
    
    void cleanupOldEntries() {
        std::lock_guard<std::mutex> lock(rate_limit_mutex);
        auto now = std::chrono::steady_clock::now();
        auto cleanup_threshold = std::chrono::minutes(5);
        
        for (auto it = rate_limit_map.begin(); it != rate_limit_map.end();) {
            if ((now - it->second.last_request) > cleanup_threshold) {
                it = rate_limit_map.erase(it);
            } else {
                ++it;
            }
        }
    }
};

CustomRateLimiter global_rate_limiter;

auto initStorage(const std::string& path) {
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

using Storage = decltype(initStorage(""));
std::shared_ptr<Storage> storage;

Task<HttpResponsePtr> rateLimitMiddleware(HttpRequestPtr req, std::function<Task<HttpResponsePtr>()> next) {
    std::string client_ip = req->getPeerAddr().toIp();
    
    if (!global_rate_limiter.isAllowed(client_ip)) {
        Json::Value response;
        response["message"] = "Rate limit exceeded. Please try again later.";
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k429TooManyRequests);
        resp->addHeader("Retry-After", "60");
        co_return resp;
    }
    
    co_return co_await next();
}

std::string hashPassword(const std::string& password) {
    return drogon::utils::getMd5(password + "salt_secret_key");
}

std::string generateSessionToken() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int32_t i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

Task<void> initializeDatabase() {
    storage->sync_schema();
    
    // Enable WAL mode for better concurrent performance
    storage->pragma.journal_mode(journal_mode::WAL);
    
    // Check if table is empty - using atomic count operation
    if (co_await [&]() -> Task<size_t> {
        co_return storage->count<User>();
    }() == 0) {
        User initialUser{0, "admin", "admin@example.com", 
                        hashPassword("admin123"), 1, "2023-01-01", ""};
        co_await [&]() -> Task<void> {
            storage->insert(initialUser);
            co_return;
        }();
    }
    LOG_INFO << "Database initialized";
    co_return;
}

Task<HttpResponsePtr> loginHandler(HttpRequestPtr req) {
    co_return co_await rateLimitMiddleware(req, [&]() -> Task<HttpResponsePtr> {
        std::shared_ptr<Json::Value> json = req->getJsonObject();
        if (!json) {
            Json::Value response;
            response["message"] = "Invalid JSON";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k400BadRequest);
            co_return resp;
        }

        std::string username = (*json)["username"].asString();
        std::string password = (*json)["password"].asString();
        std::string passwordHash = hashPassword(password);

        std::vector<User> users = co_await [&]() -> Task<std::vector<User>> {
            co_return storage->get_all<User>(
                where(is_equal(&User::username, username) and 
                      is_equal(&User::password_hash, passwordHash)),
                limit(1)
            );
        }();

        if (users.empty()) {
            Json::Value response;
            response["message"] = "Invalid username or password";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k401Unauthorized);
            co_return resp;
        }

        User& user = users[0];

        std::string currentTime = trantor::Date::now().toFormattedString("%Y-%m-%d %H:%M:%S");
        co_await [&]() -> Task<void> {
            storage->update_all(
                set(assign(&User::visit_count, c(&User::visit_count) + 1),
                    assign(&User::last_login, currentTime)),
                where(is_equal(&User::username, username))
            );
            co_return;
        }();

        std::string sessionToken = generateSessionToken();
        std::string expiresAt = trantor::Date::now().after(24 * 3600).toFormattedString("%Y-%m-%d %H:%M:%S");
        
        UserSession session{0, sessionToken, username, currentTime, expiresAt};
        co_await [&]() -> Task<void> {
            storage->insert(session);
            co_return;
        }();

        user.visit_count++;
        user.last_login = currentTime;

        Json::Value response;
        response["message"] = "Login successful";
        response["session_token"] = sessionToken;
        response["user"]["username"] = user.username;
        response["user"]["email"] = user.email;
        response["user"]["visit_count"] = user.visit_count;
        response["user"]["created_at"] = user.created_at;
        response["user"]["last_login"] = user.last_login;

        co_return HttpResponse::newHttpJsonResponse(response);
    });
}

Task<HttpResponsePtr> registerHandler(HttpRequestPtr req) {
    co_return co_await rateLimitMiddleware(req, [&]() -> Task<HttpResponsePtr> {
        std::shared_ptr<Json::Value> json = req->getJsonObject();
        if (!json) {
            Json::Value response;
            response["message"] = "Invalid JSON";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k400BadRequest);
            co_return resp;
        }

        std::string username = (*json)["username"].asString();
        std::string email = (*json)["email"].asString();
        std::string password = (*json)["password"].asString();

        if (username.empty() || email.empty() || password.empty()) {
            Json::Value response;
            response["message"] = "All fields are required";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k400BadRequest);
            co_return resp;
        }

        auto existingUsers = co_await [&]() -> Task<std::vector<std::tuple<std::string>>> {
            co_return storage->select(
                columns(&User::username),
                where(is_equal(&User::username, username)),
                limit(1)
            );
        }();

        if (!existingUsers.empty()) {
            Json::Value response;
            response["message"] = "Username already exists";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k409Conflict);
            co_return resp;
        }

        User newUser{
            0,
            username,
            email,
            hashPassword(password),
            1,
            trantor::Date::now().toFormattedString("%Y-%m-%d"),
            ""
        };
        
        co_await [&]() -> Task<void> {
            storage->insert(newUser);
            co_return;
        }();
        
        Json::Value response;
        response["message"] = "User registered successfully";
        response["username"] = newUser.username;
        
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k201Created);
        co_return resp;
    });
}

Task<HttpResponsePtr> profileHandler(HttpRequestPtr req) {
    std::string authHeader = req->getHeader("authorization");
    if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ") {
        Json::Value response;
        response["message"] = "Unauthorized";
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k401Unauthorized);
        co_return resp;
    }

    std::string sessionToken = authHeader.substr(7);
    
    // Check session validity
    std::vector<UserSession> sessions = co_await [&]() -> Task<std::vector<UserSession>> {
        co_return storage->get_all<UserSession>(
            where(is_equal(&UserSession::session_token, sessionToken)),
            limit(1)
        );
    }();

    if (sessions.empty()) {
        Json::Value response;
        response["message"] = "Invalid session";
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k401Unauthorized);
        co_return resp;
    }

    UserSession& session = sessions[0];
    
     std::vector<User> users = co_await [&]() -> Task<std::vector<User>> {
        co_return storage->get_all<User>(
            where(is_equal(&User::username, session.username)),
            limit(1)
        );
    }();

    if (users.empty()) {
        Json::Value response;
        response["message"] = "User not found";
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k404NotFound);
        co_return resp;
    }

    User& user = users[0];
    Json::Value response;
    response["username"] = user.username;
    response["email"] = user.email;
    response["visit_count"] = user.visit_count;
    response["created_at"] = user.created_at;
    response["last_login"] = user.last_login;

    co_return HttpResponse::newHttpJsonResponse(response);
}

Task<HttpResponsePtr> userHandler(HttpRequestPtr, std::string username) {
    std::vector<User> result = co_await [&]() -> Task<std::vector<User>> {
        co_return storage->get_all<User>(
            where(is_equal(&User::username, username)),
            limit(1)
        );
    }();

    if (result.empty()) {
        HttpResponsePtr resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k404NotFound);
        resp->setBody("User not found");
        co_return resp;
    }

    User& user = result[0];
    Json::Value json;
    json["username"] = user.username;
    json["email"] = user.email;
    json["visit_count"] = user.visit_count;
    json["created_at"] = user.created_at;
    json["last_login"] = user.last_login;

    co_return HttpResponse::newHttpJsonResponse(json);
}

void setupRateLimitCleanup() {
    // Cleanup old rate limit entries every 5 minutes
    drogon::app().getLoop()->runEvery(300.0, [&]() {
        global_rate_limiter.cleanupOldEntries();
    });
}

int32_t main() {
    storage = std::make_shared<Storage>(initStorage("users.db"));

    drogon::async_run([&]() -> Task<void> {
        co_await initializeDatabase();
    });

    global_rate_limiter.setRateLimit(100, 60);
    
    // Periodic cleanup
    setupRateLimitCleanup();

    app().registerHandler("/login", &loginHandler, {Post});
    app().registerHandler("/register", &registerHandler, {Post});
    app().registerHandler("/profile", &profileHandler, {Get});
    app().registerHandler("/user/{username}", &userHandler, {Get});

    app().setDocumentRoot("./");
    
    app().setLogLevel(trantor::Logger::kInfo)
         .addListener("192.168.0.13", 5000)
         .setThreadNum(4)
         .run();
}

// clang++ -Wall -Wextra -Wpedantic -fsanitize=address -std=c++26 server.cpp -o server -ldrogon -ljsoncpp -ltrantor -lssl -lcrypto -lbrotlienc -lbrotlidec -lbrotlicommon -lsqlite3 -lcares -luuid -lz