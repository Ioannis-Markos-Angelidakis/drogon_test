#include "handlers.h"
#include "../db/database.h"
#include "../auth/auth_utils.h"
#include "../middleware/middleware.h"
#include "../Bcrypt.cpp/include/bcrypt.h"
#include <drogon/HttpResponse.h>
#include <drogon/utils/Utilities.h>
#include <sqlite_orm/sqlite_orm.h>
#include <vector>
#include <string>

using namespace sqlite_orm;

extern std::shared_ptr<Storage> storage;

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

        std::vector<User> users = co_await [&]() -> Task<std::vector<User>> {
            co_return storage->get_all<User>(
                where(is_equal(&User::username, username)), limit(1));
        }();

        if (users.empty() || !bcrypt::validatePassword(password, users.at(0).password_hash)) {
            Json::Value response;
            response["message"] = "Invalid username or password";
            HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k401Unauthorized);
            co_return resp;
        }

        User &user = users.at(0);

        std::string currentTime = trantor::Date::now().toFormattedString("%Y-%m-%d %H:%M:%S");
        co_await [&]() -> Task<void> {
            storage->update_all(
                set(assign(&User::visit_count, c(&User::visit_count) + 1),
                    assign(&User::last_login, currentTime)),
                where(is_equal(&User::username, username))
            );
            co_return;
        }();

        std::string sessionToken = generateSessionToken(users.at(0).username);
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

    if (authHeader.empty() || !authHeader.starts_with("Bearer ")) {
        Json::Value response;
        response["message"] = "Unauthorized";
        HttpResponsePtr resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k401Unauthorized);
        co_return resp;
    }

    std::string sessionToken = authHeader.substr(7);
    
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