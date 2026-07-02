#pragma once

// ThreatOne Core - Thread-safe Event Bus
// Publish/subscribe pattern with priority, typed events, and async dispatch

#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <typeindex>
#include <algorithm>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>

#include "core/Event.h"
#include <mutex>
#include <type_traits>
#include <utility>

namespace ThreatOne::Core {

// Subscription handle - used to unsubscribe
using SubscriptionId = u64;

// Subscriber options
struct SubscribeOptions {
    EventPriority minPriority = EventPriority::Low;
    bool async = false; // If true, handler runs on worker thread
};

// Type-erased event handler
class IEventHandler {
public:
    virtual ~IEventHandler() = default;
    virtual void handle(const Event& event) = 0;
    [[nodiscard]] virtual std::type_index eventType() const = 0;
};

// Typed event handler
template<typename EventType>
class TypedEventHandler : public IEventHandler {
public:
    using HandlerFn = std::function<void(const EventType&)>;

    explicit TypedEventHandler(HandlerFn handler)
        : handler_(std::move(handler)) {}

    void handle(const Event& event) override {
        handler_(static_cast<const EventType&>(event));
    }

    [[nodiscard]] std::type_index eventType() const override {
        return std::type_index(typeid(EventType));
    }

private:
    HandlerFn handler_;
};

// Subscription record
struct Subscription {
    SubscriptionId id;
    std::shared_ptr<IEventHandler> handler;
    EventPriority minPriority;
    bool async;
};

// Thread-safe event bus
class EventBus {
public:
    // Singleton access
    static EventBus& instance();

    // Subscribe to a specific event type
    template<typename EventType>
    SubscriptionId subscribe(
        std::function<void(const EventType&)> handler,
        SubscribeOptions options = {}) {

        auto typedHandler = std::make_shared<TypedEventHandler<EventType>>(std::move(handler));

        Subscription sub{};
        sub.id = nextId();
        sub.handler = typedHandler;
        sub.minPriority = options.minPriority;
        sub.async = options.async;

        std::unique_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(EventType));
        subscribers_[typeIdx].push_back(sub);

        return sub.id;
    }

    // Unsubscribe by ID
    void unsubscribe(SubscriptionId id);

    // Publish an event synchronously to all matching subscribers
    template<typename EventType>
    void publish(const EventType& event) {
        static_assert(std::is_base_of_v<Event, EventType>,
                      "EventType must derive from Event");

        std::vector<Subscription> matchingSubscribers;

        {
            std::shared_lock lock(mutex_);
            auto typeIdx = std::type_index(typeid(EventType));
            auto it = subscribers_.find(typeIdx);
            if (it != subscribers_.end()) {
                for (const auto& sub : it->second) {
                    if (event.priority() >= sub.minPriority) {
                        matchingSubscribers.push_back(sub);
                    }
                }
            }

            // Also check base Event subscribers
            auto baseIdx = std::type_index(typeid(Event));
            auto baseIt = subscribers_.find(baseIdx);
            if (baseIt != subscribers_.end()) {
                for (const auto& sub : baseIt->second) {
                    if (event.priority() >= sub.minPriority) {
                        matchingSubscribers.push_back(sub);
                    }
                }
            }
        }

        // Sort by priority (higher priority handlers first)
        std::sort(matchingSubscribers.begin(), matchingSubscribers.end(),
            [](const Subscription& a, const Subscription& b) {
                return a.minPriority > b.minPriority;
            });

        // Dispatch to handlers
        for (const auto& sub : matchingSubscribers) {
            if (event.isPropagationStopped()) break;

            if (sub.async) {
                enqueueAsync(sub.handler, event);
            } else {
                sub.handler->handle(event);
            }
        }
    }

    // Start async event processing thread
    void startAsyncProcessing();

    // Stop async event processing
    void stopAsyncProcessing();

    // Get subscriber count for a type
    template<typename EventType>
    [[nodiscard]] size_t subscriberCount() const {
        std::shared_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(EventType));
        auto it = subscribers_.find(typeIdx);
        if (it == subscribers_.end()) return 0;
        return it->second.size();
    }

    // Clear all subscriptions
    void clear();

    // Non-copyable, non-movable
    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus(EventBus&&) = delete;
    EventBus& operator=(EventBus&&) = delete;

private:
    EventBus() = default;
    ~EventBus();

    static SubscriptionId nextId();

    // Async event queue item
    struct AsyncEvent {
        std::shared_ptr<IEventHandler> handler;
        std::shared_ptr<Event> event;
    };

    void enqueueAsync(const std::shared_ptr<IEventHandler>& handler, const Event& event);
    void asyncWorker();

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::type_index, std::vector<Subscription>> subscribers_;

    // Async processing
    std::mutex asyncMutex_;
    std::condition_variable asyncCv_;
    std::queue<AsyncEvent> asyncQueue_;
    std::thread asyncThread_;
    std::atomic<bool> asyncRunning_{false};
};

} // namespace ThreatOne::Core
