#pragma once

#include "network/INetworkManager.h"
#include "network/IPBlocklist.h"
#include "network/GeoIPDatabase.h"
#include "network/DNSFilter.h"
#include "network/BandwidthMonitor.h"
#include "network/IntrusionDetector.h"
#include "network/NetworkIsolation.h"
#include "network/ConnectionLogger.h"
#include "network/ApplicationControl.h"
#include "core/Logger.h"

#include <memory>
#include <mutex>

namespace ThreatOne::Network {

/// NetworkManager is a composition root that owns eight independent security
/// sub-components and exposes them via typed accessors.
///
/// Design intent: This class provides a "bag of tools" architecture where each
/// security component (IntrusionDetector, BandwidthMonitor, ApplicationControl,
/// ConnectionLogger, etc.) is a standalone, independently testable library.
///
/// Only dnsLookup() and ping() integrate inline checks (DNSFilter, IPBlocklist,
/// NetworkIsolation). The remaining sub-components are intentionally NOT consulted
/// during sendRequest/openWebSocket. Application-layer code is responsible for
/// wiring these into actual traffic paths by:
///   - Calling getIntrusionDetector().evaluate() on incoming packets.
///   - Calling getBandwidthMonitor().checkRateLimit() before transmitting data.
///   - Calling getApplicationControl().isAllowed() before launching connections.
///   - Calling getConnectionLogger().log() at connection open/close events.
///
/// This design keeps the library layer free from assumptions about the host's
/// network stack and packet interception mechanism, which vary across platforms.
class NetworkManager : public INetworkManager {
public:
    NetworkManager();
    ~NetworkManager() override = default;

    HttpResponse sendRequest(const HttpRequest& request) override;
    bool openWebSocket(const std::string& url) override;
    std::vector<NetworkConnection> getConnections() override;
    TrafficStats getTraffic() override;
    DNSResult dnsLookup(const std::string& hostname) override;
    PingResult ping(const std::string& host) override;

    // Sub-component access
    IPBlocklist& getBlocklist() override;
    GeoBlocker& getGeoBlocker() override;
    DNSFilter& getDNSFilter() override;
    BandwidthMonitor& getBandwidthMonitor() override;
    IntrusionDetector& getIntrusionDetector() override;
    NetworkIsolation& getNetworkIsolation() override;
    ConnectionLogger& getConnectionLogger() override;
    ApplicationControl& getApplicationControl() override;

private:
    mutable std::mutex mutex_;
    ThreatOne::Core::ModuleLogger logger_;

    // Sub-components
    IPBlocklist blocklist_;
    std::shared_ptr<GeoIPDatabase> geoDatabase_;
    GeoBlocker geoBlocker_;
    DNSFilter dnsFilter_;
    BandwidthMonitor bandwidthMonitor_;
    IntrusionDetector intrusionDetector_;
    NetworkIsolation networkIsolation_;
    ConnectionLogger connectionLogger_;
    ApplicationControl applicationControl_;
};

} // namespace ThreatOne::Network
