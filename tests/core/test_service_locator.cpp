#include <doctest/doctest.h>
#include <core/ServiceLocator.h>
#include <memory>

using namespace ThreatOne::Core;

// Test interfaces and implementations
class ITestService {
public:
    virtual ~ITestService() = default;
    virtual std::string name() const = 0;
    virtual int getValue() const = 0;
};

class TestServiceImpl : public ITestService {
public:
    explicit TestServiceImpl(std::string name, int value)
        : name_(std::move(name)), value_(value) {}

    std::string name() const override { return name_; }
    int getValue() const override { return value_; }

private:
    std::string name_;
    int value_;
};

class IAnotherService {
public:
    virtual ~IAnotherService() = default;
    virtual double compute() const = 0;
};

class AnotherServiceImpl : public IAnotherService {
public:
    explicit AnotherServiceImpl(double val) : val_(val) {}
    double compute() const override { return val_ * 2.0; }

private:
    double val_;
};

TEST_CASE("ServiceLocator register and resolve a service") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto service = std::make_shared<TestServiceImpl>("primary", 10);
    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(service));

    auto resolved = locator.resolve<ITestService>();
    REQUIRE(resolved != nullptr);
    CHECK(resolved->name() == "primary");
    CHECK(resolved->getValue() == 10);

    locator.clear();
}

TEST_CASE("ServiceLocator resolve unregistered returns nullptr") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto resolved = locator.resolve<ITestService>();
    CHECK(resolved == nullptr);

    locator.clear();
}

TEST_CASE("ServiceLocator resolveRequired throws for unregistered") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    CHECK_THROWS_AS(locator.resolveRequired<ITestService>(), std::runtime_error);

    locator.clear();
}

TEST_CASE("ServiceLocator multiple services") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto testService = std::make_shared<TestServiceImpl>("test", 5);
    auto anotherService = std::make_shared<AnotherServiceImpl>(3.14);

    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(testService));
    locator.registerService<IAnotherService>(std::static_pointer_cast<IAnotherService>(anotherService));

    SUBCASE("Both services resolve correctly") {
        auto t = locator.resolve<ITestService>();
        auto a = locator.resolve<IAnotherService>();
        REQUIRE(t != nullptr);
        REQUIRE(a != nullptr);
        CHECK(t->name() == "test");
        CHECK(a->compute() == doctest::Approx(6.28));
    }

    SUBCASE("Service count is correct") {
        CHECK(locator.serviceCount() == 2);
    }

    locator.clear();
}

TEST_CASE("ServiceLocator override registration") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto original = std::make_shared<TestServiceImpl>("original", 1);
    auto replacement = std::make_shared<TestServiceImpl>("replacement", 2);

    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(original));
    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(replacement));

    auto resolved = locator.resolve<ITestService>();
    REQUIRE(resolved != nullptr);
    CHECK(resolved->name() == "replacement");
    CHECK(resolved->getValue() == 2);

    locator.clear();
}

TEST_CASE("ServiceLocator hasService") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    CHECK_FALSE(locator.hasService<ITestService>());

    auto service = std::make_shared<TestServiceImpl>("svc", 0);
    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(service));

    CHECK(locator.hasService<ITestService>());
    CHECK_FALSE(locator.hasService<IAnotherService>());

    locator.clear();
}

TEST_CASE("ServiceLocator unregister") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto service = std::make_shared<TestServiceImpl>("remove_me", 0);
    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(service));
    CHECK(locator.hasService<ITestService>());

    locator.unregister<ITestService>();
    CHECK_FALSE(locator.hasService<ITestService>());
    CHECK(locator.resolve<ITestService>() == nullptr);

    locator.clear();
}

TEST_CASE("ServiceLocator factory transient") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    int createCount = 0;
    locator.registerFactory<ITestService>([&]() -> std::shared_ptr<ITestService> {
        createCount++;
        return std::make_shared<TestServiceImpl>("transient_" + std::to_string(createCount), createCount);
    });

    auto first = locator.resolve<ITestService>();
    auto second = locator.resolve<ITestService>();
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    CHECK(first->name() == "transient_1");
    CHECK(second->name() == "transient_2");
    CHECK(createCount == 2);

    locator.clear();
}

TEST_CASE("ServiceLocator clear") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto service = std::make_shared<TestServiceImpl>("clearable", 0);
    locator.registerService<ITestService>(std::static_pointer_cast<ITestService>(service));
    auto another = std::make_shared<AnotherServiceImpl>(1.0);
    locator.registerService<IAnotherService>(std::static_pointer_cast<IAnotherService>(another));

    CHECK(locator.serviceCount() == 2);

    locator.clear();

    CHECK(locator.serviceCount() == 0);
    CHECK(locator.resolve<ITestService>() == nullptr);
    CHECK(locator.resolve<IAnotherService>() == nullptr);
}

TEST_CASE("ServiceLocator registerAs interface") {
    auto& locator = ServiceLocator::instance();
    locator.clear();

    auto impl = std::make_shared<TestServiceImpl>("via_registerAs", 99);
    locator.registerAs<ITestService, TestServiceImpl>(impl);

    auto resolved = locator.resolve<ITestService>();
    REQUIRE(resolved != nullptr);
    CHECK(resolved->name() == "via_registerAs");
    CHECK(resolved->getValue() == 99);

    locator.clear();
}
