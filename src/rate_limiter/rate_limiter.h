#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <unordered_map>
#include <chrono>
#include <mutex>
#include <string>

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
    bool isAllowed(const std::string& client_ip);
    void setRateLimit(int32_t requests, int32_t seconds);
    void cleanupOldEntries();
};

extern CustomRateLimiter global_rate_limiter;

#endif