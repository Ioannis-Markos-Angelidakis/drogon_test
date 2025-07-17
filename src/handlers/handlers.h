#ifndef HANDLERS_H
#define HANDLERS_H

#include <drogon/drogon.h>
#include <drogon/utils/coroutine.h>
#include <string>

using namespace drogon;

Task<HttpResponsePtr> loginHandler(HttpRequestPtr req);
Task<HttpResponsePtr> registerHandler(HttpRequestPtr req);
Task<HttpResponsePtr> profileHandler(HttpRequestPtr req);
Task<HttpResponsePtr> userHandler(HttpRequestPtr req, std::string username);

#endif