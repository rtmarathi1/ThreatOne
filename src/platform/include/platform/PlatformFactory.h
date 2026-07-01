#pragma once

// ThreatOne Platform - PlatformFactory
// Factory to create the appropriate platform driver for the current OS.

#include <memory>
#include "platform/IPlatformDriver.h"

namespace ThreatOne::Platform {

class PlatformFactory {
public:
    // Creates and returns the platform-appropriate driver.
    // Returns a Linux, Windows, or macOS driver based on compile-time detection.
    static std::unique_ptr<IPlatformDriver> createDriver();

    // Returns the name of the current platform
    static std::string currentPlatformName();
};

} // namespace ThreatOne::Platform
