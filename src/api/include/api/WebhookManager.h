#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <mutex>
#include <unordered_map>
#include <functional>

namespace ThreatOne::Api {

enum class DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying
};

struct RetryPolicy {
    int maxRetries = 3;
    int backoffSeconds = 5;
    double backoffMultiplier = 2.0;
};

struct WebhookSubscription {
    std::string id;
    std::string url;
    std::vector<std::string> events;
    std::string secret;
    bool active = true;
    std::chrono::system_clock::time_point createdAt;
    RetryPolicy retryPolicy;
};

struct WebhookDelivery {
    std::string id;
    std::string subscriptionId;
    std::string event;
    std::string payload;
    DeliveryStatus status = DeliveryStatus::Pending;
    int attempts = 0;
    std::chrono::system_clock::time_point lastAttemptAt;
    int responseCode = 0;
};

// Callback type for actually sending webhooks (allows mocking in tests)
using WebhookSender = std::function<int(const std::string& url, const std::string& payload,
                                         const std::map<std::string, std::string>& headers)>;

class IWebhookManager {
public:
    virtual ~IWebhookManager() = default;

    virtual std::string subscribe(const std::string& url, const std::vector<std::string>& events,
                                  const std::string& secret, RetryPolicy policy = RetryPolicy{}) = 0;
    virtual bool unsubscribe(const std::string& subscriptionId) = 0;
    virtual std::vector<WebhookSubscription> listSubscriptions() const = 0;
    virtual std::optional<WebhookSubscription> getSubscription(const std::string& id) const = 0;

    virtual void triggerEvent(const std::string& event, const std::string& payload) = 0;
    virtual std::vector<WebhookDelivery> getDeliveryHistory(const std::string& subscriptionId) const = 0;
    virtual bool retryDelivery(const std::string& deliveryId) = 0;
    virtual void processRetryQueue() = 0;
};

class WebhookManager : public IWebhookManager {
public:
    WebhookManager();
    explicit WebhookManager(WebhookSender sender);

    std::string subscribe(const std::string& url, const std::vector<std::string>& events,
                          const std::string& secret, RetryPolicy policy = RetryPolicy{}) override;
    bool unsubscribe(const std::string& subscriptionId) override;
    std::vector<WebhookSubscription> listSubscriptions() const override;
    std::optional<WebhookSubscription> getSubscription(const std::string& id) const override;

    void triggerEvent(const std::string& event, const std::string& payload) override;
    std::vector<WebhookDelivery> getDeliveryHistory(const std::string& subscriptionId) const override;
    bool retryDelivery(const std::string& deliveryId) override;
    void processRetryQueue() override;

    // For testing
    std::vector<WebhookDelivery> getAllDeliveries() const;

private:
    std::string generateId() const;
    bool matchesEvent(const WebhookSubscription& sub, const std::string& event) const;
    void deliverWebhook(const WebhookSubscription& sub, const std::string& event, const std::string& payload);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, WebhookSubscription> subscriptions_;
    std::vector<WebhookDelivery> deliveries_;
    WebhookSender sender_;
};

} // namespace ThreatOne::Api
