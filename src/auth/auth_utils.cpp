#include "auth_utils.h"
#include "../Bcrypt.cpp/include/bcrypt.h"
#include <jwt-cpp/jwt.h>
#include <chrono>

const std::string JWT_SECRET = "secret_key";

std::string hashPassword(const std::string& password) {
    return bcrypt::generateHash(password, 10);
}

std::string generateSessionToken(const std::string& username) {
    return jwt::create()
        .set_issuer("auth0")
        .set_type("JWT")
        .set_payload_claim("username", jwt::claim(username))
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24})
        .sign(jwt::algorithm::hs256{JWT_SECRET});
}