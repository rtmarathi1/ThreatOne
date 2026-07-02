#include <doctest/doctest.h>
#include <core/Config.h>
#include <string>

using namespace ThreatOne::Core;

TEST_CASE("Config load from JSON string") {
    auto& config = Config::instance();
    config.clear();

    SUBCASE("Load valid JSON") {
        auto result = config.loadFromString(R"({
            "app": {
                "name": "ThreatOne",
                "version": 1
            },
            "debug": true
        })");
        CHECK(result.isOk());
    }

    SUBCASE("Load invalid JSON returns error") {
        auto result = config.loadFromString("{ invalid json }");
        CHECK(result.isErr());
        CHECK(result.error().category() == ErrorCategory::Configuration);
    }

    SUBCASE("Load empty object") {
        auto result = config.loadFromString("{}");
        CHECK(result.isOk());
    }

    config.clear();
}

TEST_CASE("Config dot-notation access") {
    auto& config = Config::instance();
    config.clear();
    auto result = config.loadFromString(R"({
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "threatone_db",
            "ssl": true,
            "timeout": 30.5
        },
        "app": {
            "name": "ThreatOne"
        }
    })");
    REQUIRE(result.isOk());

    SUBCASE("Access nested string value") {
        auto val = config.getString("database.host");
        REQUIRE(val.has_value());
        CHECK(*val == "localhost");
    }

    SUBCASE("Access nested int value") {
        auto val = config.getInt("database.port");
        REQUIRE(val.has_value());
        CHECK(*val == 5432);
    }

    SUBCASE("Access nested bool value") {
        auto val = config.getBool("database.ssl");
        REQUIRE(val.has_value());
        CHECK(*val == true);
    }

    SUBCASE("Access nested double value") {
        auto val = config.getDouble("database.timeout");
        REQUIRE(val.has_value());
        CHECK(*val == doctest::Approx(30.5));
    }

    SUBCASE("Access top-level object child") {
        auto val = config.getString("app.name");
        REQUIRE(val.has_value());
        CHECK(*val == "ThreatOne");
    }

    config.clear();
}

TEST_CASE("Config default values") {
    auto& config = Config::instance();
    config.clear();
    config.loadFromString(R"({"existing": "value"})");

    SUBCASE("getString returns default when key missing") {
        auto val = config.getString("nonexistent.key", "default_val");
        CHECK(val == "default_val");
    }

    SUBCASE("getInt returns default when key missing") {
        auto val = config.getInt("nonexistent.key", 42);
        CHECK(val == 42);
    }

    SUBCASE("getDouble returns default when key missing") {
        auto val = config.getDouble("nonexistent.key", 3.14);
        CHECK(val == doctest::Approx(3.14));
    }

    SUBCASE("getBool returns default when key missing") {
        auto val = config.getBool("nonexistent.key", true);
        CHECK(val == true);
    }

    SUBCASE("Optional getString returns nullopt when key missing") {
        auto val = config.getString("nonexistent.key");
        CHECK_FALSE(val.has_value());
    }

    SUBCASE("Optional getInt returns nullopt when key missing") {
        auto val = config.getInt("nonexistent.key");
        CHECK_FALSE(val.has_value());
    }

    config.clear();
}

TEST_CASE("Config set values") {
    auto& config = Config::instance();
    config.clear();

    SUBCASE("Set and get string") {
        config.setString("server.host", "192.168.1.1");
        auto val = config.getString("server.host");
        REQUIRE(val.has_value());
        CHECK(*val == "192.168.1.1");
    }

    SUBCASE("Set and get int") {
        config.setInt("server.port", 8080);
        auto val = config.getInt("server.port");
        REQUIRE(val.has_value());
        CHECK(*val == 8080);
    }

    SUBCASE("Set and get double") {
        config.setDouble("threshold.score", 0.95);
        auto val = config.getDouble("threshold.score");
        REQUIRE(val.has_value());
        CHECK(*val == doctest::Approx(0.95));
    }

    SUBCASE("Set and get bool") {
        config.setBool("features.enabled", false);
        auto val = config.getBool("features.enabled");
        REQUIRE(val.has_value());
        CHECK(*val == false);
    }

    SUBCASE("Set creates nested path automatically") {
        config.setString("deeply.nested.path.value", "test");
        auto val = config.getString("deeply.nested.path.value");
        REQUIRE(val.has_value());
        CHECK(*val == "test");
    }

    SUBCASE("Overwrite existing value") {
        config.setString("key", "original");
        config.setString("key", "updated");
        auto val = config.getString("key");
        REQUIRE(val.has_value());
        CHECK(*val == "updated");
    }

    config.clear();
}

TEST_CASE("Config has and remove") {
    auto& config = Config::instance();
    config.clear();
    config.loadFromString(R"({"section": {"key": "value"}})");

    SUBCASE("has returns true for existing key") {
        CHECK(config.has("section.key"));
        CHECK(config.has("section"));
    }

    SUBCASE("has returns false for missing key") {
        CHECK_FALSE(config.has("nonexistent"));
        CHECK_FALSE(config.has("section.missing"));
    }

    SUBCASE("remove deletes key") {
        config.remove("section.key");
        CHECK_FALSE(config.has("section.key"));
    }

    config.clear();
}

TEST_CASE("Config merge") {
    auto& config = Config::instance();
    config.clear();
    config.loadFromString(R"({"a": 1, "b": {"c": 2}})");

    nlohmann::json overlay = {{"b", {{"d", 3}}}, {"e", 4}};
    config.merge(overlay);

    SUBCASE("New keys are added") {
        auto val = config.getInt("e");
        REQUIRE(val.has_value());
        CHECK(*val == 4);
    }

    SUBCASE("Nested merge adds to existing object") {
        auto val = config.getInt("b.d");
        REQUIRE(val.has_value());
        CHECK(*val == 3);
    }

    SUBCASE("Original top-level keys preserved") {
        auto val = config.getInt("a");
        REQUIRE(val.has_value());
        CHECK(*val == 1);
    }

    config.clear();
}

TEST_CASE("Config raw JSON access") {
    auto& config = Config::instance();
    config.clear();
    config.loadFromString(R"({"x": [1, 2, 3]})");

    SUBCASE("getJson returns full node") {
        auto val = config.getJson("x");
        REQUIRE(val.has_value());
        CHECK(val->is_array());
        CHECK(val->size() == 3);
    }

    SUBCASE("raw returns entire config") {
        const auto& raw = config.raw();
        CHECK(raw.contains("x"));
    }

    config.clear();
}

TEST_CASE("Config change notification") {
    auto& config = Config::instance();
    config.clear();

    bool notified = false;
    std::string notifiedKey;

    config.onChanged("server", [&](const std::string& key) {
        notified = true;
        notifiedKey = key;
    });

    config.setString("server.host", "127.0.0.1");

    CHECK(notified);
    CHECK(notifiedKey == "server.host");

    config.clear();
}

TEST_CASE("Config typed value mismatch") {
    auto& config = Config::instance();
    config.clear();
    config.loadFromString(R"({"name": "text", "count": 42})");

    SUBCASE("getInt on string value returns nullopt") {
        auto val = config.getInt("name");
        CHECK_FALSE(val.has_value());
    }

    SUBCASE("getString on int value returns nullopt") {
        auto val = config.getString("count");
        CHECK_FALSE(val.has_value());
    }

    config.clear();
}
