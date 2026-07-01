#include <doctest/doctest.h>
#include <core/EventBus.h>
#include <core/Event.h>

using namespace ThreatOne::Core;

// Custom test event
class TestEvent : public Event {
public:
    explicit TestEvent(std::string msg, EventPriority p = EventPriority::Normal)
        : message_(std::move(msg)), priority_(p) {}

    [[nodiscard]] std::string eventType() const override { return "TestEvent"; }
    [[nodiscard]] EventPriority priority() const override { return priority_; }
    [[nodiscard]] const std::string& message() const { return message_; }

private:
    std::string message_;
    EventPriority priority_;
};

// Another test event type
class AnotherEvent : public Event {
public:
    explicit AnotherEvent(int val) : value_(val) {}

    [[nodiscard]] std::string eventType() const override { return "AnotherEvent"; }
    [[nodiscard]] int value() const { return value_; }

private:
    int value_;
};

// Helper to reset EventBus state between tests
struct EventBusFixture {
    EventBusFixture() {
        EventBus::instance().clear();
    }
    ~EventBusFixture() {
        EventBus::instance().clear();
    }
};

TEST_CASE_FIXTURE(EventBusFixture, "EventBus subscribe and publish") {
    auto& bus = EventBus::instance();

    SUBCASE("Handler is called when event is published") {
        bool handlerCalled = false;
        std::string receivedMessage;

        bus.subscribe<TestEvent>([&](const TestEvent& event) {
            handlerCalled = true;
            receivedMessage = event.message();
        });

        TestEvent event("hello");
        bus.publish(event);

        CHECK(handlerCalled);
        CHECK(receivedMessage == "hello");
    }

    SUBCASE("Handler receives correct typed data") {
        int receivedValue = 0;

        bus.subscribe<AnotherEvent>([&](const AnotherEvent& event) {
            receivedValue = event.value();
        });

        AnotherEvent event(42);
        bus.publish(event);

        CHECK(receivedValue == 42);
    }

    SUBCASE("No handler called for unsubscribed event type") {
        bool called = false;
        bus.subscribe<TestEvent>([&](const TestEvent&) {
            called = true;
        });

        AnotherEvent event(1);
        bus.publish(event);

        CHECK_FALSE(called);
    }
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus multiple subscribers") {
    auto& bus = EventBus::instance();

    int callCount = 0;

    bus.subscribe<TestEvent>([&](const TestEvent&) { callCount++; });
    bus.subscribe<TestEvent>([&](const TestEvent&) { callCount++; });
    bus.subscribe<TestEvent>([&](const TestEvent&) { callCount++; });

    TestEvent event("multi");
    bus.publish(event);

    CHECK(callCount == 3);
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus unsubscribe") {
    auto& bus = EventBus::instance();

    int callCount = 0;

    auto subId = bus.subscribe<TestEvent>([&](const TestEvent&) {
        callCount++;
    });

    TestEvent event1("first");
    bus.publish(event1);
    CHECK(callCount == 1);

    bus.unsubscribe(subId);

    TestEvent event2("second");
    bus.publish(event2);
    CHECK(callCount == 1); // Should not increment
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus subscriber count") {
    auto& bus = EventBus::instance();

    CHECK(bus.subscriberCount<TestEvent>() == 0);

    auto id1 = bus.subscribe<TestEvent>([](const TestEvent&) {});
    CHECK(bus.subscriberCount<TestEvent>() == 1);

    auto id2 = bus.subscribe<TestEvent>([](const TestEvent&) {});
    CHECK(bus.subscriberCount<TestEvent>() == 2);

    bus.unsubscribe(id1);
    CHECK(bus.subscriberCount<TestEvent>() == 1);

    bus.unsubscribe(id2);
    CHECK(bus.subscriberCount<TestEvent>() == 0);
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus event priority filtering") {
    auto& bus = EventBus::instance();

    bool lowCalled = false;
    bool highCalled = false;

    // Subscribe with minPriority High - should only receive High and Critical events
    SubscribeOptions highOnlyOpts;
    highOnlyOpts.minPriority = EventPriority::High;
    bus.subscribe<TestEvent>([&](const TestEvent&) {
        highCalled = true;
    }, highOnlyOpts);

    // Subscribe with minPriority Low - should receive all events
    SubscribeOptions allOpts;
    allOpts.minPriority = EventPriority::Low;
    bus.subscribe<TestEvent>([&](const TestEvent&) {
        lowCalled = true;
    }, allOpts);

    SUBCASE("High priority event reaches both subscribers") {
        TestEvent highEvent("high", EventPriority::High);
        bus.publish(highEvent);
        CHECK(highCalled);
        CHECK(lowCalled);
    }

    SUBCASE("Low priority event only reaches low-threshold subscriber") {
        TestEvent lowEvent("low", EventPriority::Low);
        bus.publish(lowEvent);
        CHECK_FALSE(highCalled);
        CHECK(lowCalled);
    }
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus propagation stop") {
    auto& bus = EventBus::instance();

    int callOrder = 0;
    int firstHandlerOrder = 0;
    int secondHandlerOrder = 0;

    // Both subscribe at same priority level
    bus.subscribe<TestEvent>([&](const TestEvent& event) {
        firstHandlerOrder = ++callOrder;
        const_cast<TestEvent&>(event).stopPropagation();
    });

    bus.subscribe<TestEvent>([&](const TestEvent&) {
        secondHandlerOrder = ++callOrder;
    });

    TestEvent event("stop");
    bus.publish(event);

    CHECK(firstHandlerOrder == 1);
    CHECK(secondHandlerOrder == 0); // Should not have been called
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus clear removes all subscriptions") {
    auto& bus = EventBus::instance();

    bus.subscribe<TestEvent>([](const TestEvent&) {});
    bus.subscribe<AnotherEvent>([](const AnotherEvent&) {});

    CHECK(bus.subscriberCount<TestEvent>() == 1);
    CHECK(bus.subscriberCount<AnotherEvent>() == 1);

    bus.clear();

    CHECK(bus.subscriberCount<TestEvent>() == 0);
    CHECK(bus.subscriberCount<AnotherEvent>() == 0);
}

TEST_CASE_FIXTURE(EventBusFixture, "EventBus with SystemEvent") {
    auto& bus = EventBus::instance();

    SystemEvent::Type receivedType = SystemEvent::Type::Started;
    std::string receivedMsg;

    bus.subscribe<SystemEvent>([&](const SystemEvent& event) {
        receivedType = event.systemType();
        receivedMsg = event.message();
    });

    SystemEvent event(SystemEvent::Type::ConfigChanged, "config updated");
    bus.publish(event);

    CHECK(receivedType == SystemEvent::Type::ConfigChanged);
    CHECK(receivedMsg == "config updated");
}

TEST_CASE_FIXTURE(EventBusFixture, "Event base class features") {
    SUBCASE("Event has unique incrementing IDs") {
        TestEvent e1("a");
        TestEvent e2("b");
        CHECK(e1.id() != e2.id());
        CHECK(e2.id() > e1.id());
    }

    SUBCASE("Event has timestamp") {
        TestEvent event("ts");
        auto now = SystemClock::now();
        // Event timestamp should be close to now (within 1 second)
        auto diff = std::chrono::duration_cast<Seconds>(now - event.timestamp());
        CHECK(diff.count() < 1);
    }

    SUBCASE("Event data payload") {
        TestEvent event("data");
        event.setData("key1", std::string("value1"));
        event.setData("key2", 42);

        CHECK(event.hasData("key1"));
        CHECK(event.hasData("key2"));
        CHECK_FALSE(event.hasData("key3"));

        CHECK(event.getData<std::string>("key1") == "value1");
        CHECK(event.getData<int>("key2") == 42);
    }
}
