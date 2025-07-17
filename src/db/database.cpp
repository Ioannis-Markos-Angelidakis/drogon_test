#include "database.h"
#include "../auth/auth_utils.h"
#include <drogon/drogon.h>

Task<void> initializeDatabase(std::shared_ptr<Storage> storage) {
    storage->sync_schema();
    storage->pragma.journal_mode(sqlite_orm::journal_mode::WAL);
    
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