#pragma once

// ThreatOne Core - Application Lifecycle Manager
// Manages the overall application lifecycle: initialization, run loop, and shutdown.
// Handles OS signal registration and proper RAII-based cleanup ordering.

#include <string>
#include <memory>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>

#include "core/Types.h"
#include "core/Error.h"

namespace ThreatOne::Core {

// Application state
enum class AppState {
    Uninitialized,
    Initializing,
    Running,
    ShuttingDown,
    Stopped,
    Error
};

// Application configuration
struct AppConfig {
    std::string appName = "ThreatOne";
    std::string configFile = "config.json";
    std::string logDirectory = "logs";
    std::string pluginDirectory = "plugins";
    bool enableSignalHandling = true;
    bool enablePlugins = true;
};

class Application {
public:
    // Singleton access
    static Application& instance();

    // Lifecycle methods
    [[nodiscard]] Result<void> initialize(const AppConfig& config = AppConfig{});
    [[nodiscard]] Result<void> run();
    void shutdown();

    // State queries
    [[nodiscard]] AppState state() const noexcept { return state_.load(); }
    [[nodiscard]] bool isRunning() const noexcept { return state_ == AppState::Running; }
    [[nodiscard]] const std::string& appName() const noexcept { return config_.appName; }
    [[nodiscard]] const AppConfig& appConfig() const noexcept { return config_; }
    [[nodiscard]] Version version() const noexcept { return version_; }

    // Request application exit
    void requestShutdown();

    // Register callbacks for lifecycle events
    using LifecycleCallback = std::function<void()>;
    void onInitialized(LifecycleCallback callback);
    void onShutdown(LifecycleCallback callback);

    // Non-copyable, non-movable
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;
    Application(Application&&) = delete;
    Application& operator=(Application&&) = delete;

private:
    Application() = default;
    ~Application() = default;

    // Initialization sub-steps
    Result<void> initLogger();
    Result<void> initConfig();
    Result<void> initEventBus();
    Result<void> initServiceLocator();
    Result<void> initPlugins();
    void installSignalHandlers();

    // Signal handler (static for OS callback)
    static void signalHandler(int signal);

    std::atomic<AppState> state_{AppState::Uninitialized};
    AppConfig config_;
    Version version_{1, 0, 0};

    std::mutex callbackMutex_;
    std::vector<LifecycleCallback> initCallbacks_;
    std::vector<LifecycleCallback> shutdownCallbacks_;

    // Global pointer for signal handler access
    static Application* instancePtr_;
};

} // namespace ThreatOne::Core
