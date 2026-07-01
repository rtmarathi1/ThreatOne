#include <doctest/doctest.h>
#include <core/Logger.h>

using namespace ThreatOne::Core;

TEST_CASE("Logger initialization") {
    auto& logger = Logger::instance();

    SUBCASE("Logger initializes without error") {
        LogConfig config;
        config.enableConsole = false;
        config.enableFile = false;
        config.consoleLevel = LogLevel::Trace;
        logger.initialize(config);
        CHECK(true); // No exception thrown
    }

    SUBCASE("Global level defaults to configured level") {
        LogConfig config;
        config.consoleLevel = LogLevel::Warn;
        config.enableConsole = false;
        config.enableFile = false;
        // Shutdown and re-initialize to apply new config
        logger.shutdown();
        logger.initialize(config);
        CHECK(logger.getGlobalLevel() == LogLevel::Warn);
    }

    // Cleanup
    logger.shutdown();
}

TEST_CASE("Logger level control") {
    auto& logger = Logger::instance();
    LogConfig config;
    config.enableConsole = false;
    config.enableFile = false;
    config.consoleLevel = LogLevel::Trace;
    logger.shutdown();
    logger.initialize(config);

    SUBCASE("Set and get global level") {
        logger.setGlobalLevel(LogLevel::Error);
        CHECK(logger.getGlobalLevel() == LogLevel::Error);

        logger.setGlobalLevel(LogLevel::Debug);
        CHECK(logger.getGlobalLevel() == LogLevel::Debug);
    }

    SUBCASE("All log levels can be set") {
        logger.setGlobalLevel(LogLevel::Trace);
        CHECK(logger.getGlobalLevel() == LogLevel::Trace);

        logger.setGlobalLevel(LogLevel::Info);
        CHECK(logger.getGlobalLevel() == LogLevel::Info);

        logger.setGlobalLevel(LogLevel::Warn);
        CHECK(logger.getGlobalLevel() == LogLevel::Warn);

        logger.setGlobalLevel(LogLevel::Critical);
        CHECK(logger.getGlobalLevel() == LogLevel::Critical);

        logger.setGlobalLevel(LogLevel::Off);
        CHECK(logger.getGlobalLevel() == LogLevel::Off);
    }

    logger.shutdown();
}

TEST_CASE("Module Logger") {
    auto& logger = Logger::instance();
    LogConfig config;
    config.enableConsole = false;
    config.enableFile = false;
    config.consoleLevel = LogLevel::Trace;
    logger.shutdown();
    logger.initialize(config);

    SUBCASE("Create module logger with name") {
        auto moduleLogger = logger.getModuleLogger("TestModule");
        CHECK(moduleLogger.moduleName() == "TestModule");
    }

    SUBCASE("Module logger can log at all levels without crashing") {
        auto moduleLogger = logger.getModuleLogger("TestModule2");
        moduleLogger.setLevel(LogLevel::Trace);

        // These should not throw
        moduleLogger.trace("trace message {}", 1);
        moduleLogger.debug("debug message {}", 2);
        moduleLogger.info("info message {}", 3);
        moduleLogger.warn("warn message {}", 4);
        moduleLogger.error("error message {}", 5);
        moduleLogger.critical("critical message {}", 6);
        CHECK(true); // No exception thrown
    }

    SUBCASE("Module logger level can be set independently") {
        auto moduleLogger = logger.getModuleLogger("IndependentModule");
        moduleLogger.setLevel(LogLevel::Error);
        CHECK(moduleLogger.getLevel() == LogLevel::Error);

        moduleLogger.setLevel(LogLevel::Trace);
        CHECK(moduleLogger.getLevel() == LogLevel::Trace);
    }

    SUBCASE("Multiple module loggers can coexist") {
        auto loggerA = logger.getModuleLogger("ModuleA");
        auto loggerB = logger.getModuleLogger("ModuleB");

        CHECK(loggerA.moduleName() == "ModuleA");
        CHECK(loggerB.moduleName() == "ModuleB");

        loggerA.setLevel(LogLevel::Warn);
        loggerB.setLevel(LogLevel::Debug);

        CHECK(loggerA.getLevel() == LogLevel::Warn);
        CHECK(loggerB.getLevel() == LogLevel::Debug);
    }

    logger.shutdown();
}

TEST_CASE("Logger spdlog level conversion") {
    CHECK(Logger::toSpdlogLevel(LogLevel::Trace) == spdlog::level::trace);
    CHECK(Logger::toSpdlogLevel(LogLevel::Debug) == spdlog::level::debug);
    CHECK(Logger::toSpdlogLevel(LogLevel::Info) == spdlog::level::info);
    CHECK(Logger::toSpdlogLevel(LogLevel::Warn) == spdlog::level::warn);
    CHECK(Logger::toSpdlogLevel(LogLevel::Error) == spdlog::level::err);
    CHECK(Logger::toSpdlogLevel(LogLevel::Critical) == spdlog::level::critical);
    CHECK(Logger::toSpdlogLevel(LogLevel::Off) == spdlog::level::off);
}

TEST_CASE("Logger direct logging") {
    auto& logger = Logger::instance();
    LogConfig config;
    config.enableConsole = false;
    config.enableFile = false;
    config.consoleLevel = LogLevel::Trace;
    logger.shutdown();
    logger.initialize(config);

    // Direct logging on the default logger should not throw
    logger.trace("direct trace {}", "msg");
    logger.debug("direct debug {}", 42);
    logger.info("direct info {}", 3.14);
    logger.warn("direct warn");
    logger.error("direct error");
    logger.critical("direct critical");
    CHECK(true);

    logger.shutdown();
}
