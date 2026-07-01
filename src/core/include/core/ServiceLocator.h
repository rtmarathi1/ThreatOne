#pragma once

// ThreatOne Core - Service Locator / Dependency Injection Container
// Thread-safe registration and resolution of services by type

#include <any>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <typeindex>
#include <unordered_map>
#include <string>
#include <functional>
#include <stdexcept>

#include "core/Types.h"

namespace ThreatOne::Core {

// Service lifetime options
enum class ServiceLifetime {
    Singleton,  // One instance shared across all resolutions
    Transient   // New instance created each time (via factory)
};

class ServiceLocator {
public:
    // Singleton access
    static ServiceLocator& instance();

    // Register a service instance (singleton)
    template<typename T>
    void registerService(std::shared_ptr<T> service) {
        std::unique_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(T));
        services_[typeIdx] = ServiceEntry{
            std::any(std::move(service)),
            ServiceLifetime::Singleton,
            {}
        };
    }

    // Register a service with a factory function (transient)
    template<typename T>
    void registerFactory(std::function<std::shared_ptr<T>()> factory) {
        std::unique_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(T));
        // Wrap the typed factory in a type-erased one
        auto erasedFactory = [f = std::move(factory)]() -> std::any {
            return std::any(f());
        };
        services_[typeIdx] = ServiceEntry{
            std::any{},
            ServiceLifetime::Transient,
            std::move(erasedFactory)
        };
    }

    // Register a service by interface type
    template<typename Interface, typename Implementation>
    void registerAs(std::shared_ptr<Implementation> service) {
        static_assert(std::is_base_of_v<Interface, Implementation>,
                      "Implementation must derive from Interface");
        std::unique_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(Interface));
        services_[typeIdx] = ServiceEntry{
            std::any(std::static_pointer_cast<Interface>(service)),
            ServiceLifetime::Singleton,
            {}
        };
    }

    // Resolve a service by type (returns nullptr if not registered)
    template<typename T>
    [[nodiscard]] std::shared_ptr<T> resolve() const {
        std::shared_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(T));
        auto it = services_.find(typeIdx);
        if (it == services_.end()) return nullptr;

        const auto& entry = it->second;
        if (entry.lifetime == ServiceLifetime::Singleton) {
            try {
                return std::any_cast<std::shared_ptr<T>>(entry.instance);
            } catch (const std::bad_any_cast&) {
                return nullptr;
            }
        } else {
            // Transient - create new instance via factory
            if (entry.factory) {
                try {
                    auto result = entry.factory();
                    return std::any_cast<std::shared_ptr<T>>(result);
                } catch (const std::bad_any_cast&) {
                    return nullptr;
                }
            }
            return nullptr;
        }
    }

    // Resolve or throw if not found
    template<typename T>
    [[nodiscard]] std::shared_ptr<T> resolveRequired() const {
        auto service = resolve<T>();
        if (!service) {
            throw std::runtime_error(
                std::string("Required service not registered: ") +
                typeid(T).name());
        }
        return service;
    }

    // Check if a service is registered
    template<typename T>
    [[nodiscard]] bool hasService() const {
        std::shared_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(T));
        return services_.find(typeIdx) != services_.end();
    }

    // Unregister a service
    template<typename T>
    void unregister() {
        std::unique_lock lock(mutex_);
        auto typeIdx = std::type_index(typeid(T));
        services_.erase(typeIdx);
    }

    // Clear all registrations
    void clear();

    // Get count of registered services
    [[nodiscard]] size_t serviceCount() const;

    // Non-copyable, non-movable
    ServiceLocator(const ServiceLocator&) = delete;
    ServiceLocator& operator=(const ServiceLocator&) = delete;
    ServiceLocator(ServiceLocator&&) = delete;
    ServiceLocator& operator=(ServiceLocator&&) = delete;

private:
    ServiceLocator() = default;
    ~ServiceLocator() = default;

    struct ServiceEntry {
        std::any instance;
        ServiceLifetime lifetime;
        std::function<std::any()> factory;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::type_index, ServiceEntry> services_;
};

} // namespace ThreatOne::Core
