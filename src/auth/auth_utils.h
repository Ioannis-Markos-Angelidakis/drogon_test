#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#include <string>

std::string hashPassword(const std::string& password);
std::string generateSessionToken(const std::string& username);

#endif