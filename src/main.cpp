#include <drogon/drogon.h>
#include "db/database.h"
#include "rate_limiter/rate_limiter.h"
#include "handlers/handlers.h"

std::shared_ptr<Storage> storage;

void setupRateLimitCleanup() {
    drogon::app().getLoop()->runEvery(300.0, [&]() {
        global_rate_limiter.cleanupOldEntries();
    });
}

int32_t main() {
    storage = std::make_shared<Storage>(initStorage("users.db"));

    drogon::async_run([&]() -> Task<void> {
        co_await initializeDatabase(storage);
    });

    global_rate_limiter.setRateLimit(100, 60);
    setupRateLimitCleanup();

    app().registerHandler("/login", &loginHandler, {Post});
    app().registerHandler("/register", &registerHandler, {Post});
    app().registerHandler("/profile", &profileHandler, {Get});
    app().registerHandler("/user/{username}", &userHandler, {Get});

    app().setDocumentRoot("./");
    app().setLogLevel(trantor::Logger::kInfo)
         .addListener("192.168.0.14", 5000)
         .setThreadNum(4)
         .run();
}