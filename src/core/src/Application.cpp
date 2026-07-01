#include "core/Application.h"
#include "core/Logger.h"
#include "core/Config.h"
#include "core/EventBus.h"
#include "core/ServiceLocator.h"
#include "core/PluginLoader.h"
#include "core/Event.h"

#include <csignal>
#include <thread>
#include <chrono>

namespace ThreatOne::Core {

// Static member initialization
Application* Application::instancePtr_ = nullptr;

Application& Application::instance() {
    static Application app;
    instancePtr_ = &app;
    return app;
}

Result<void> Application::initialize(const AppConfig& config) {
    if (state_ != AppState::Uninitialized) {
        return Result<void>::err(
            Error("Application already initialized",
                  ErrorCategory::Internal,
                  ErrorSeverity::Warning));
    }

    state_ = AppState::Initializing;
    config_ = config;

    // Initialize subsystems in order
    auto logResult = initLogger();
    if (!logResult) {
        state_ = AppState::Error;
        return logResult;
    }

    auto configResult = initConfig();
    if (!configResult) {
        state_ = AppState::Error;
        return configResult;
    }

    auto eventResult = initEventBus();
    if (!eventResult) {
        state_ = AppState::Error;
        return eventResult;
    }

    auto serviceResult = initServiceLocator();
    if (!serviceResult) {
        state_ = AppState::Error;
        return serviceResult;
    }

    if (config_.enablePlugins) {
        auto pluginResult = initPlugins();
        if (!pluginResult) {
            // Plugin init failure is non-fatal - log and continue
            Logger::instance().warn("Plugin initialization failed: {}",
                                    pluginResult.error().message());
        }
    }

    // Install signal handlers
    if (config_.enableSignalHandling) {
        installSignalHandlers();
    }

    state_ = AppState::Running;

    // Notify initialization callbacks
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        for (const auto& callback : initCallbacks_) {
            callback();
        }
    }

    // Publish system started event
    EventBus::instance().publish(SystemEvent(SystemEvent::Type::Started, "Application initialized"));

    Logger::instance().info("ThreatOne {} initialized successfully", version_.toString());

    return Result<void>::ok();
}

Result<void> Application::run() {
    if (state_ != AppState::Running) {
        return Result<void>::err(
            Error("Application not in running state",
                  ErrorCategory::Internal,
                  ErrorSeverity::Error));
    }

    Logger::instance().info("Application entering main loop");

    // Main event loop - wait until shutdown is requested
    while (state_ == AppState::Running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return Result<void>::ok();
}

void Application::shutdown() {
    AppState expected = AppState::Running;
    if (!state_.compare_exchange_strong(expected, AppState::ShuttingDown)) {
        // Already shutting down or not running
        return;
    }

    Logger::instance().info("Application shutdown initiated");

    // Publish shutdown event
    EventBus::instance().publish(SystemEvent(SystemEvent::Type::Stopping, "Application shutting down"));

    // Notify shutdown callbacks (in reverse order)
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        for (auto it = shutdownCallbacks_.rbegin(); it != shutdownCallbacks_.rend(); ++it) {
            (*it)();
        }
    }

    // Shutdown in reverse initialization order
    if (config_.enablePlugins) {
        PluginLoader::instance().shutdownAll();
    }

    // Stop async event processing
    EventBus::instance().stopAsyncProcessing();
    EventBus::instance().clear();

    // Clear service locator
    ServiceLocator::instance().clear();

    // Shutdown logger last
    Logger::instance().info("Application shutdown complete");
    Logger::instance().shutdown();

    state_ = AppState::Stopped;
}

void Application::requestShutdown() {
    if (state_ == AppState::Running) {
        state_ = AppState::ShuttingDown;
    }
}

void Application::onInitialized(LifecycleCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    initCallbacks_.push_back(std::move(callback));
}

void Application::onShutdown(LifecycleCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    shutdownCallbacks_.push_back(std::move(callback));
}

Result<void> Application::initLogger() {
    LogConfig logConfig;
    logConfig.consoleLevel = LogLevel::Info;
    logConfig.logDirectory = config_.logDirectory;
    logConfig.enableConsole = true;
    logConfig.enableFile = false; // Disabled by default for startup

    Logger::instance().initialize(logConfig);
    Logger::instance().info("Logger initialized");
    return Result<void>::ok();
}

Result<void> Application::initConfig() {
    auto& config = Config::instance();
    config.enableEnvOverrides(true);

    // Try to load config file - it's OK if it doesn't exist
    if (!config_.configFile.empty()) {
        auto result = config.loadFromFile(config_.configFile);
        if (!result) {
            // Config file not found is non-fatal on first run
            Logger::instance().debug("Config file not found, using defaults: {}",
                                     config_.configFile);
        }
    }

    Logger::instance().info("Configuration manager initialized");
    return Result<void>::ok();
}

Result<void> Application::initEventBus() {
    EventBus::instance().startAsyncProcessing();
    Logger::instance().info("Event bus initialized");
    return Result<void>::ok();
}

Result<void> Application::initServiceLocator() {
    // ServiceLocator is ready as-is (static singleton)
    Logger::instance().info("Service locator initialized");
    return Result<void>::ok();
}

Result<void> Application::initPlugins() {
    auto& loader = PluginLoader::instance();

    if (!config_.pluginDirectory.empty()) {
        loader.addSearchPath(config_.pluginDirectory);
    }

    // Discover and load plugins
    auto discovered = loader.discover();
    if (discovered && !discovered.value().empty()) {
        Logger::instance().info("Discovered {} plugins", discovered.value().size());

        for (const auto& pluginName : discovered.value()) {
            auto result = loader.load(pluginName);
            if (!result) {
                Logger::instance().warn("Failed to load plugin {}: {}",
                                        pluginName, result.error().message());
            }
        }

        // Initialize all loaded plugins
        auto initResult = loader.initializeAll();
        if (!initResult) {
            return initResult;
        }
    }

    Logger::instance().info("Plugin loader initialized");
    return Result<void>::ok();
}

void Application::installSignalHandlers() {
    std::signal(SIGINT, &Application::signalHandler);
    std::signal(SIGTERM, &Application::signalHandler);
}

void Application::signalHandler(int signal) {
    if (instancePtr_) {
        instancePtr_->requestShutdown();
    }
    // Re-install default handler for second signal (force quit)
    std::signal(signal, SIG_DFL);
}

} // namespace ThreatOne::Core
