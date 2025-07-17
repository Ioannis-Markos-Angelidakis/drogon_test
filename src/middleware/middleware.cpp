#include "middleware.h"
#include "../rate_limiter/rate_limiter.h"
#include <drogon/HttpResponse.h>

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