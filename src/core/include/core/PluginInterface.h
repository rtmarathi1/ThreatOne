#pragma once

// ThreatOne Core - Plugin Interface
// Pure virtual interface that all plugins must implement

#include <string>
#include <vector>
#include <memory>

#include "core/Types.h"
#include "core/Error.h"

namespace ThreatOne::Core {

// Plugin state lifecycle
enum class PluginState {
    Unloaded,
    Loaded,
    Initialized,
    Running,
    Stopped,
    Error
};

// Plugin metadata
struct PluginMetadata {
    std::string name;
    std::string displayName;
    std::string description;
    Version version;
    std::string author;
    std::string license;
    std::vector<std::string> dependencies; // Names of required plugins
    std::vector<std::string> optionalDeps; // Names of optional plugins
    std::vector<std::string> categories;   // Plugin categories
};

// Pure virtual plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;

    // Identity
    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual Version version() const = 0;
    [[nodiscard]] virtual PluginMetadata metadata() const = 0;

    // Lifecycle
    [[nodiscard]] virtual Result<void> initialize() = 0;
    [[nodiscard]] virtual Result<void> start() = 0;
    [[nodiscard]] virtual Result<void> stop() = 0;
    virtual void shutdown() = 0;

    // Dependencies
    [[nodiscard]] virtual std::vector<std::string> dependencies() const = 0;

    // State
    [[nodiscard]] virtual PluginState state() const = 0;

    // Health check (optional, returns true by default)
    [[nodiscard]] virtual bool isHealthy() const { return state() == PluginState::Running; }
};

// Plugin factory function type (exported by shared libraries)
using PluginCreateFn = IPlugin* (*)();
using PluginDestroyFn = void (*)(IPlugin*);

// Plugin entry point macro for shared libraries
#define THREATONE_PLUGIN_ENTRY(PluginClass)                         \
    extern "C" {                                                     \
        ThreatOne::Core::IPlugin* threatone_plugin_create() {        \
            return new PluginClass();                                 \
        }                                                            \
        void threatone_plugin_destroy(ThreatOne::Core::IPlugin* p) { \
            delete p;                                                 \
        }                                                            \
    }

} // namespace ThreatOne::Core
