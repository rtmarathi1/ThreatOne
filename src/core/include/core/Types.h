#pragma once

// ThreatOne Core - Common type aliases, platform macros, forward declarations

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <optional>
#include <functional>
#include <chrono>

// Platform detection macros
#if defined(_WIN32) || defined(_WIN64)
    #define THREATONE_PLATFORM_WINDOWS 1
    #define THREATONE_PLATFORM_LINUX 0
    #define THREATONE_PLATFORM_MACOS 0
#elif defined(__linux__)
    #define THREATONE_PLATFORM_WINDOWS 0
    #define THREATONE_PLATFORM_LINUX 1
    #define THREATONE_PLATFORM_MACOS 0
#elif defined(__APPLE__)
    #define THREATONE_PLATFORM_WINDOWS 0
    #define THREATONE_PLATFORM_LINUX 0
    #define THREATONE_PLATFORM_MACOS 1
#else
    #define THREATONE_PLATFORM_WINDOWS 0
    #define THREATONE_PLATFORM_LINUX 0
    #define THREATONE_PLATFORM_MACOS 0
#endif

// Export/import macros for shared library support
#if defined(THREATONE_SHARED_LIBRARY)
    #if THREATONE_PLATFORM_WINDOWS
        #if defined(THREATONE_BUILDING_LIBRARY)
            #define THREATONE_API __declspec(dllexport)
        #else
            #define THREATONE_API __declspec(dllimport)
        #endif
    #else
        #define THREATONE_API __attribute__((visibility("default")))
    #endif
#else
    #define THREATONE_API
#endif

// Compiler feature detection
#if __has_cpp_attribute(nodiscard)
    #define THREATONE_NODISCARD [[nodiscard]]
#else
    #define THREATONE_NODISCARD
#endif

#if __has_cpp_attribute(maybe_unused)
    #define THREATONE_UNUSED [[maybe_unused]]
#else
    #define THREATONE_UNUSED
#endif

#if __has_cpp_attribute(likely)
    #define THREATONE_LIKELY [[likely]]
    #define THREATONE_UNLIKELY [[unlikely]]
#else
    #define THREATONE_LIKELY
    #define THREATONE_UNLIKELY
#endif

namespace ThreatOne::Core {

// Common type aliases
using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

using f32 = float;
using f64 = double;

using StringView = std::string_view;
using String = std::string;

// Time types
using Clock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;
using TimePoint = Clock::time_point;
using SystemTimePoint = SystemClock::time_point;
using Duration = Clock::duration;
using Milliseconds = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;

// Smart pointer aliases
template<typename T>
using UniquePtr = std::unique_ptr<T>;

template<typename T>
using SharedPtr = std::shared_ptr<T>;

template<typename T>
using WeakPtr = std::weak_ptr<T>;

// Optional type
template<typename T>
using Optional = std::optional<T>;

// Callback types
template<typename Signature>
using Callback = std::function<Signature>;

// Forward declarations for core types
class Application;
class Logger;
class Config;
class EventBus;
class ServiceLocator;
class PluginLoader;

// Version information
struct Version {
    u32 major = 1;
    u32 minor = 0;
    u32 patch = 0;

    constexpr auto operator<=>(const Version&) const = default;

    THREATONE_NODISCARD std::string toString() const {
        return std::to_string(major) + "." +
               std::to_string(minor) + "." +
               std::to_string(patch);
    }
};

// UUID type (simple string-based for now)
using UUID = std::string;

} // namespace ThreatOne::Core
