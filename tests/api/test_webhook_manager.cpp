#include <doctest/doctest.h>
#include <api/WebhookManager.h>
#include <map>
#include <string>

using namespace ThreatOne::Api;

TEST_CASE("WebhookManager - Subscribe to events") {
    WebhookManager mgr;
    std::string id = mgr.subscribe("https://example.com/hook",
                                    {"scan.completed", "alert.created"},
                                    "secret123");
    CHECK_FALSE(id.empty());

    auto sub = mgr.getSubscription(id);
    REQUIRE(sub.has_value());
    CHECK(sub->url == "https://example.com/hook");
    CHECK(sub->events.size() == 2);
    CHECK(sub->secret == "secret123");
    CHECK(sub->active == true);
}

TEST_CASE("WebhookManager - List subscriptions") {
    WebhookManager mgr;
    mgr.subscribe("https://a.com/hook", {"event.a"}, "s1");
    mgr.subscribe("https://b.com/hook", {"event.b"}, "s2");

    auto subs = mgr.listSubscriptions();
    CHECK(subs.size() == 2);
}

TEST_CASE("WebhookManager - Unsubscribe") {
    WebhookManager mgr;
    std::string id = mgr.subscribe("https://remove.com/hook",
                                    {"event.x"}, "secret");
    CHECK(mgr.unsubscribe(id));
    CHECK_FALSE(mgr.getSubscription(id).has_value());
}

TEST_CASE("WebhookManager - Unsubscribe nonexistent returns false") {
    WebhookManager mgr;
    CHECK_FALSE(mgr.unsubscribe("nonexistent-id"));
}

TEST_CASE("WebhookManager - Trigger event delivers to matching subscription") {
    int deliveryCount = 0;
    WebhookSender sender = [&](const std::string& /*url*/,
                               const std::string& /*payload*/,
                               const std::map<std::string, std::string>& /*headers*/) -> int {
        deliveryCount++;
        return 200;
    };

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://hook.com/endpoint",
                                    {"scan.completed"}, "sec");

    mgr.triggerEvent("scan.completed", R"({"scanId":"s1"})");
    CHECK(deliveryCount == 1);

    auto history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    CHECK(history[0].event == "scan.completed");
    CHECK(history[0].status == DeliveryStatus::Delivered);
    CHECK(history[0].responseCode == 200);
}

TEST_CASE("WebhookManager - No delivery for non-matching event") {
    int deliveryCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        deliveryCount++;
        return 200;
    };

    WebhookManager mgr(sender);
    mgr.subscribe("https://hook.com/ep", {"scan.completed"}, "s");

    mgr.triggerEvent("alert.created", R"({"alertId":"a1"})");
    CHECK(deliveryCount == 0);
}

TEST_CASE("WebhookManager - Wildcard event matching") {
    int deliveryCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        deliveryCount++;
        return 200;
    };

    WebhookManager mgr(sender);
    mgr.subscribe("https://hook.com/ep", {"scan.*"}, "s");

    mgr.triggerEvent("scan.completed", "{}");
    mgr.triggerEvent("scan.started", "{}");
    mgr.triggerEvent("alert.created", "{}");

    CHECK(deliveryCount == 2);
}

TEST_CASE("WebhookManager - Failed delivery marked as retrying") {
    WebhookSender sender = [](const std::string&, const std::string&,
                              const std::map<std::string, std::string>&) -> int {
        return 500;
    };

    RetryPolicy policy;
    policy.maxRetries = 3;

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://fail.com/hook",
                                    {"event.x"}, "s", policy);

    mgr.triggerEvent("event.x", "{}");

    auto history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    CHECK(history[0].status == DeliveryStatus::Retrying);
    CHECK(history[0].attempts == 1);
}

TEST_CASE("WebhookManager - Retry delivery succeeds") {
    int callCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        callCount++;
        if (callCount <= 1) return 500;
        return 200;
    };

    RetryPolicy policy;
    policy.maxRetries = 3;

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://retry.com/hook",
                                    {"event.y"}, "s", policy);

    mgr.triggerEvent("event.y", "{}");

    auto history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    std::string deliveryId = history[0].id;

    CHECK(mgr.retryDelivery(deliveryId));

    history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    CHECK(history[0].status == DeliveryStatus::Delivered);
    CHECK(history[0].attempts == 2);
}

TEST_CASE("WebhookManager - Max retries exhausted marks failed") {
    WebhookSender sender = [](const std::string&, const std::string&,
                              const std::map<std::string, std::string>&) -> int {
        return 500;
    };

    RetryPolicy policy;
    policy.maxRetries = 2;

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://exhaust.com/hook",
                                    {"event.z"}, "s", policy);

    mgr.triggerEvent("event.z", "{}");

    // First attempt done, status is retrying (1 attempt < 2 max)
    auto history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    std::string deliveryId = history[0].id;
    CHECK(history[0].status == DeliveryStatus::Retrying);

    // Retry - now at 2 attempts == maxRetries, should be Failed
    mgr.retryDelivery(deliveryId);

    history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    CHECK(history[0].status == DeliveryStatus::Failed);
    CHECK(history[0].attempts == 2);
}

TEST_CASE("WebhookManager - Process retry queue") {
    int callCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        callCount++;
        if (callCount <= 1) return 500;
        return 200;
    };

    RetryPolicy policy;
    policy.maxRetries = 3;

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://queue.com/hook",
                                    {"event.q"}, "s", policy);

    mgr.triggerEvent("event.q", "{}");
    CHECK(callCount == 1);

    mgr.processRetryQueue();
    CHECK(callCount == 2);

    auto history = mgr.getDeliveryHistory(id);
    REQUIRE(history.size() == 1);
    CHECK(history[0].status == DeliveryStatus::Delivered);
}

TEST_CASE("WebhookManager - Inactive subscription not triggered") {
    int deliveryCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        deliveryCount++;
        return 200;
    };

    WebhookManager mgr(sender);
    std::string id = mgr.subscribe("https://inactive.com/hook",
                                    {"event.i"}, "s");
    // Unsubscribe and re-subscribe inactive is tested via unsubscribe
    mgr.unsubscribe(id);

    mgr.triggerEvent("event.i", "{}");
    CHECK(deliveryCount == 0);
}

TEST_CASE("WebhookManager - Retry nonexistent delivery returns false") {
    WebhookManager mgr;
    CHECK_FALSE(mgr.retryDelivery("nonexistent-delivery"));
}

TEST_CASE("WebhookManager - Multiple subscribers receive same event") {
    int deliveryCount = 0;
    WebhookSender sender = [&](const std::string&, const std::string&,
                               const std::map<std::string, std::string>&) -> int {
        deliveryCount++;
        return 200;
    };

    WebhookManager mgr(sender);
    mgr.subscribe("https://a.com/hook", {"event.m"}, "s1");
    mgr.subscribe("https://b.com/hook", {"event.m"}, "s2");

    mgr.triggerEvent("event.m", "{}");
    CHECK(deliveryCount == 2);
}
