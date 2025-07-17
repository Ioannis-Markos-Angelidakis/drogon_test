#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <drogon/drogon.h>
#include <drogon/utils/coroutine.h>
#include <functional>

using namespace drogon;

Task<HttpResponsePtr> rateLimitMiddleware(HttpRequestPtr req, std::function<Task<HttpResponsePtr>()> next);

#endif