#include <drogon/HttpTypes.h>
#include <drogon/drogon.h>
#include <trantor/net/EventLoop.h>
#include <string>
#include <memory>
#include <format>
#include <chrono>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <drogon/utils/coroutine.h>

using namespace drogon;

struct ChatMessage {
    std::string username;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    
    std::string toSSEData() const {
        const std::chrono::time_zone* tz = std::chrono::current_zone();
        auto local_time = tz->to_local(timestamp);
        return std::format("data: [{:%H:%M:%S}] {}: {}\n\n", std::chrono::floor<std::chrono::seconds>(local_time),username, message);
    }
};

class ChatRoom {
private:
    std::vector<ChatMessage> messageHistory;
    std::unordered_set<std::shared_ptr<ResponseStream>> activeStreams;
    mutable std::mutex mutex;
    std::atomic<uint32_t> userCounter{0};

public:
    void addMessage(const std::string& username, const std::string& message) {
        ChatMessage msg{username, message, std::chrono::system_clock::now()};
        
        std::lock_guard<std::mutex> lock(mutex);
        messageHistory.push_back(msg);
        
        // Keep only last 100 messages
        if (messageHistory.size() > 100) {
            messageHistory.erase(messageHistory.begin());
        }
        
        // Broadcast to all connected clients
        std::string sseData = msg.toSSEData();
        auto it = activeStreams.begin();
        while (it != activeStreams.end()) {
            if (!(*it)->send(sseData)) {
                // Client disconnected, remove from active streams
                it = activeStreams.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    void addStream(std::shared_ptr<ResponseStream> stream) {
        std::lock_guard<std::mutex> lock(mutex);
        
        // Send connection message
        if (!stream->send("data: === Connected to chat ===\n\n")) {
            return;
        }
        
        // Send message history
        for (const auto& msg : messageHistory) {
            if (!stream->send(msg.toSSEData())) {
                return;
            }
        }
        
        // Send current users count
        std::string userCountMsg = std::format("data: === {} users online ===\n\n", activeStreams.size() + 1);
        stream->send(userCountMsg);
        
        activeStreams.insert(stream);
        
        // Broadcast user joined message
        std::string joinMsg = std::format("data: === User {} joined ===\n\n", userCounter.load());
        for (auto& s : activeStreams) {
            if (s != stream) {
                s->send(joinMsg);
            }
        }
        
        userCounter++;
    }
    
    void removeStream(std::shared_ptr<ResponseStream> stream) {
        std::lock_guard<std::mutex> lock(mutex);
        activeStreams.erase(stream);
        
        // Broadcast user left message
        std::string leaveMsg = std::format("data: === A user left ({} users online) ===\n\n", activeStreams.size());
        for (auto& s : activeStreams) {
            s->send(leaveMsg);
        }
    }
    
    size_t getActiveStreamsCount() const {
        std::lock_guard<std::mutex> lock(mutex);
        return activeStreams.size();
    }
};

// Global chat room instance
ChatRoom chatRoom;

Task<HttpResponsePtr> handleSSE(HttpRequestPtr req) {
    LOG_DEBUG << "Received SSE request from: " << req->getPeerAddr().toIpPort();

    auto sse_data = [](ResponseStreamPtr stream) {
        std::shared_ptr<ResponseStream> sharedStream = std::shared_ptr<ResponseStream>(std::move(stream));
        
        // Add stream to chat room
        chatRoom.addStream(sharedStream);
        
        // Keep the stream alive by sending periodic keepalive messages
        trantor::EventLoop *loop = trantor::EventLoop::getEventLoopOfCurrentThread();
        std::shared_ptr<trantor::TimerId> timer = std::make_shared<trantor::TimerId>();
        
        *timer = loop->runEvery(1.0, [sharedStream, timer, loop]() {
            // Send keepalive and check if stream is still valid
            if (!sharedStream->send("data: keepalive\n\n")) {
                // Stream is dead, cleanup
                chatRoom.removeStream(sharedStream);
                loop->invalidateTimer(*timer);
            }
        });
    };

    std::shared_ptr<HttpResponse> resp = HttpResponse::newAsyncStreamResponse(sse_data, true);

    resp->addHeader("Content-Type", "text/event-stream");
    resp->addHeader("Cache-Control", "no-cache");
    resp->addHeader("Connection", "keep-alive");
    resp->addHeader("Access-Control-Allow-Origin", "*");
    resp->addHeader("Access-Control-Allow-Headers", "Cache-Control");

    co_return resp;
}

Task<HttpResponsePtr> handleSendMessage(HttpRequestPtr req) {
    try {
        auto json = req->getJsonObject();
        if (!json) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k400BadRequest);
            resp->setBody("Invalid JSON");
            co_return resp;
        }

        std::string username = json->get("username", "Anonymous").asString();
        std::string message = json->get("message", "").asString();

        if (message.empty()) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k400BadRequest);
            resp->setBody("Message cannot be empty");
            co_return resp;
        }

        // Trim username and message
        username = username.substr(0, 50); // Max 50 chars
        message = message.substr(0, 500);  // Max 500 chars

        // Add message to chat room
        chatRoom.addMessage(username, message);

        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Message sent"));
        resp->addHeader("Access-Control-Allow-Origin", "*");
        co_return resp;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing message: " << e.what();
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k500InternalServerError);
        resp->setBody("Internal server error");
        co_return resp;
    }
}

Task<HttpResponsePtr> handleOptions(HttpRequestPtr /*req*/) {
    auto resp = HttpResponse::newHttpResponse();
    resp->addHeader("Access-Control-Allow-Origin", "*");
    resp->addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Cache-Control");
    co_return resp;
}

int32_t main() {
    app().setDocumentRoot("./"); 

    // SSE endpoint
    app().registerHandler("/sse", &handleSSE, {Get});
    
    // Message sending endpoint
    app().registerHandler("/send", &handleSendMessage, {Post});
    app().registerHandler("/send", &handleOptions, {Options});

    app().addListener("192.168.0.14", 8080);
    
    LOG_INFO << "Chat server starting on http://192.168.0.14:8080";
    LOG_INFO << "SSE endpoint: http://192.168.0.14:8080/sse";
    LOG_INFO << "Send endpoint: POST http://192.168.0.14:8080/send";
    LOG_INFO << "Press Ctrl+C to stop the server";
    
    try {
        app().run();
    } catch (const std::exception& e) {
        LOG_ERROR << "Server error: " << e.what();
        return 1;
    }
    
    LOG_INFO << "Server stopped gracefully";
}

// 00:42
// clang++ -Wall -Wextra -Wpedantic -fsanitize=address -std=c++26 test.cpp -o test -ldrogon -ljsoncpp -ltrantor -lssl -lcrypto -lbrotlienc -lbrotlidec -lbrotlicommon -lcares -luuid -lz -lsqlite3