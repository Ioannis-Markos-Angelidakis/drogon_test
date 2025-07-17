#include "rate_limiter.h"

CustomRateLimiter global_rate_limiter;

bool CustomRateLimiter::isAllowed(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto& info = rate_limit_map[client_ip];
    
    if (info.requests == 0 || (now - info.window_start) >= window_duration) {
        info.requests = 1;
        info.window_start = now;
        info.last_request = now;
        return true;
    }
    
    if (info.requests < max_requests_per_window) {
        info.requests++;
        info.last_request = now;
        return true;
    }
    
    return false;
}

void CustomRateLimiter::setRateLimit(int32_t requests, int32_t seconds) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    max_requests_per_window = requests;
    window_duration = std::chrono::seconds(seconds);
}

void CustomRateLimiter::cleanupOldEntries() {
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