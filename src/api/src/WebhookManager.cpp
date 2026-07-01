#include "api/WebhookManager.h"
#include <algorithm>
#include <random>

namespace ThreatOne::Api {

WebhookManager::WebhookManager()
    : sender_([](const std::string& /*url*/, const std::string& /*payload*/,
                 const std::map<std::string, std::string>& /*headers*/) -> int {
        // Default sender simulates a successful delivery
        return 200;
    }) {}

WebhookManager::WebhookManager(WebhookSender sender)
    : sender_(std::move(sender)) {}

std::string WebhookManager::generateId() const {
    static const char chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 15);

    std::string id;
    id.reserve(16);
    for (int i = 0; i < 16; ++i) {
        id += chars[dist(gen)];
    }
    return id;
}

std::string WebhookManager::subscribe(const std::string& url,
                                       const std::vector<std::string>& events,
                                       const std::string& secret,
                                       RetryPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    WebhookSubscription sub;
    sub.id = generateId();
    sub.url = url;
    sub.events = events;
    sub.secret = secret;
    sub.active = true;
    sub.createdAt = std::chrono::system_clock::now();
    sub.retryPolicy = policy;

    subscriptions_[sub.id] = sub;
    return sub.id;
}

bool WebhookManager::unsubscribe(const std::string& subscriptionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriptions_.erase(subscriptionId) > 0;
}

std::vector<WebhookSubscription> WebhookManager::listSubscriptions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WebhookSubscription> result;
    result.reserve(subscriptions_.size());
    for (const auto& [id, sub] : subscriptions_) {
        result.push_back(sub);
    }
    return result;
}

std::optional<WebhookSubscription> WebhookManager::getSubscription(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = subscriptions_.find(id);
    if (it == subscriptions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool WebhookManager::matchesEvent(const WebhookSubscription& sub, const std::string& event) const {
    // Check if subscription matches the event
    for (const auto& subEvent : sub.events) {
        if (subEvent == event) {
            return true;
        }
        // Support wildcard matching (e.g., "scan.*" matches "scan.completed")
        if (!subEvent.empty() && subEvent.back() == '*') {
            std::string prefix = subEvent.substr(0, subEvent.size() - 1);
            if (event.substr(0, prefix.size()) == prefix) {
                return true;
            }
        }
    }
    return false;
}

void WebhookManager::deliverWebhook(const WebhookSubscription& sub,
                                     const std::string& event,
                                     const std::string& payload) {
    WebhookDelivery delivery;
    delivery.id = generateId();
    delivery.subscriptionId = sub.id;
    delivery.event = event;
    delivery.payload = payload;
    delivery.attempts = 1;
    delivery.lastAttemptAt = std::chrono::system_clock::now();

    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";
    headers["X-Webhook-Event"] = event;
    if (!sub.secret.empty()) {
        headers["X-Webhook-Secret"] = sub.secret;
    }

    int responseCode = sender_(sub.url, payload, headers);
    delivery.responseCode = responseCode;

    if (responseCode >= 200 && responseCode < 300) {
        delivery.status = DeliveryStatus::Delivered;
    } else if (delivery.attempts < sub.retryPolicy.maxRetries) {
        delivery.status = DeliveryStatus::Retrying;
    } else {
        delivery.status = DeliveryStatus::Failed;
    }

    deliveries_.push_back(delivery);
}

void WebhookManager::triggerEvent(const std::string& event, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [id, sub] : subscriptions_) {
        if (!sub.active) continue;
        if (matchesEvent(sub, event)) {
            deliverWebhook(sub, event, payload);
        }
    }
}

std::vector<WebhookDelivery> WebhookManager::getDeliveryHistory(const std::string& subscriptionId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WebhookDelivery> result;
    for (const auto& delivery : deliveries_) {
        if (delivery.subscriptionId == subscriptionId) {
            result.push_back(delivery);
        }
    }
    return result;
}

bool WebhookManager::retryDelivery(const std::string& deliveryId) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& delivery : deliveries_) {
        if (delivery.id == deliveryId) {
            if (delivery.status != DeliveryStatus::Failed &&
                delivery.status != DeliveryStatus::Retrying) {
                return false;
            }

            auto subIt = subscriptions_.find(delivery.subscriptionId);
            if (subIt == subscriptions_.end()) {
                return false;
            }

            delivery.attempts++;
            delivery.lastAttemptAt = std::chrono::system_clock::now();

            std::map<std::string, std::string> headers;
            headers["Content-Type"] = "application/json";
            headers["X-Webhook-Event"] = delivery.event;
            if (!subIt->second.secret.empty()) {
                headers["X-Webhook-Secret"] = subIt->second.secret;
            }

            int responseCode = sender_(subIt->second.url, delivery.payload, headers);
            delivery.responseCode = responseCode;

            if (responseCode >= 200 && responseCode < 300) {
                delivery.status = DeliveryStatus::Delivered;
            } else if (delivery.attempts >= subIt->second.retryPolicy.maxRetries) {
                delivery.status = DeliveryStatus::Failed;
            } else {
                delivery.status = DeliveryStatus::Retrying;
            }

            return true;
        }
    }
    return false;
}

void WebhookManager::processRetryQueue() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& delivery : deliveries_) {
        if (delivery.status != DeliveryStatus::Retrying) {
            continue;
        }

        auto subIt = subscriptions_.find(delivery.subscriptionId);
        if (subIt == subscriptions_.end()) {
            delivery.status = DeliveryStatus::Failed;
            continue;
        }

        const auto& sub = subIt->second;
        if (delivery.attempts >= sub.retryPolicy.maxRetries) {
            delivery.status = DeliveryStatus::Failed;
            continue;
        }

        delivery.attempts++;
        delivery.lastAttemptAt = std::chrono::system_clock::now();

        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-Webhook-Event"] = delivery.event;
        if (!sub.secret.empty()) {
            headers["X-Webhook-Secret"] = sub.secret;
        }

        int responseCode = sender_(sub.url, delivery.payload, headers);
        delivery.responseCode = responseCode;

        if (responseCode >= 200 && responseCode < 300) {
            delivery.status = DeliveryStatus::Delivered;
        } else if (delivery.attempts >= sub.retryPolicy.maxRetries) {
            delivery.status = DeliveryStatus::Failed;
        }
    }
}

std::vector<WebhookDelivery> WebhookManager::getAllDeliveries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return deliveries_;
}

} // namespace ThreatOne::Api
