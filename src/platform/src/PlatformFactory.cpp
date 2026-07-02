// ThreatOne Platform - PlatformFactory implementation
// Returns the appropriate platform driver based on compile-time OS detection.

#include "platform/PlatformFactory.h"
#include "core/Logger.h"
#include <memory>
#include <string>

#ifdef __linux__
#include "LinuxDriver.h"
#elif defined(_WIN32)
#include "WindowsDriver.h"
#elif defined(__APPLE__)
#include "MacOSDriver.h"
#endif

namespace ThreatOne::Platform {

std::unique_ptr<IPlatformDriver> PlatformFactory::createDriver() {
    auto logger = Core::Logger::instance().getModuleLogger("PlatformFactory");

#ifdef __linux__
    logger.info("Creating Linux platform driver");
    return std::make_unique<LinuxDriver>();
#elif defined(_WIN32)
    logger.info("Creating Windows platform driver");
    return std::make_unique<WindowsDriver>();
#elif defined(__APPLE__)
    logger.info("Creating macOS platform driver");
    return std::make_unique<MacOSDriver>();
#else
    logger.error("No platform driver available for this OS");
    return nullptr;
#endif
}

std::string PlatformFactory::currentPlatformName() {
#ifdef __linux__
    return "Linux";
#elif defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "Unknown";
#endif
}

} // namespace ThreatOne::Platform
