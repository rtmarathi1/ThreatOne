#include "core/EventBus.h"
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace ThreatOne::Core {

EventBus& EventBus::instance() {
    static EventBus instance;
    return instance;
}

EventBus::~EventBus() {
    stopAsyncProcessing();
}

SubscriptionId EventBus::nextId() {
    static std::atomic<SubscriptionId> counter{0};
    return ++counter;
}

void EventBus::unsubscribe(SubscriptionId id) {
    std::unique_lock lock(mutex_);
    for (auto& [typeIdx, subs] : subscribers_) {
        auto it = std::remove_if(subs.begin(), subs.end(),
            [id](const Subscription& sub) { return sub.id == id; });
        subs.erase(it, subs.end());
    }
}

void EventBus::clear() {
    std::unique_lock lock(mutex_);
    subscribers_.clear();
}

void EventBus::startAsyncProcessing() {
    if (asyncRunning_.exchange(true)) return; // Already running

    asyncThread_ = std::thread(&EventBus::asyncWorker, this);
}

void EventBus::stopAsyncProcessing() {
    if (!asyncRunning_.exchange(false)) return; // Not running

    asyncCv_.notify_all();
    if (asyncThread_.joinable()) {
        asyncThread_.join();
    }

    // Process remaining events
    std::lock_guard lock(asyncMutex_);
    while (!asyncQueue_.empty()) {
        auto& item = asyncQueue_.front();
        item.handler->handle(*item.event);
        asyncQueue_.pop();
    }
}

void EventBus::enqueueAsync(const std::shared_ptr<IEventHandler>& handler, const Event& event) {
    // KNOWN LIMITATION (Phase 1): Async dispatch falls back to synchronous execution.
    //
    // To truly dispatch asynchronously, we would need to clone the polymorphic Event
    // so it outlives the publish() call's stack frame. This requires adding a virtual
    // clone() method to Event and all derived types. Until that is implemented, all
    // subscribers marked async=true still execute synchronously on the publisher's thread.
    //
    // The async worker thread is started but its queue is never populated.
    // This will be resolved in a future phase.
    handler->handle(event);
}

void EventBus::asyncWorker() {
    while (asyncRunning_) {
        std::unique_lock lock(asyncMutex_);
        asyncCv_.wait(lock, [this] {
            return !asyncQueue_.empty() || !asyncRunning_;
        });

        while (!asyncQueue_.empty()) {
            auto item = std::move(asyncQueue_.front());
            asyncQueue_.pop();
            lock.unlock();

            item.handler->handle(*item.event);

            lock.lock();
        }
    }
}

} // namespace ThreatOne::Core
