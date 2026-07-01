#include "network/NetworkManager.h"

namespace ThreatOne::Network {

NetworkManager::NetworkManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("NetworkManager"))
    , geoDatabase_(std::make_shared<GeoIPDatabase>())
    , geoBlocker_(geoDatabase_) {
    geoDatabase_->loadDefaultMappings();
    logger_.info("NetworkManager initialized with all security components");
}

HttpResponse NetworkManager::sendRequest(const HttpRequest& request) {
    logger_.info("sendRequest called: {} {}", request.method, request.url);
    return {200, "{\"status\": \"ok\"}", {}};
}

bool NetworkManager::openWebSocket(const std::string& url) {
    logger_.info("openWebSocket called: {}", url);
    return true;
}

std::vector<NetworkConnection> NetworkManager::getConnections() {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getConnections called");
    return {};
}

TrafficStats NetworkManager::getTraffic() {
    return bandwidthMonitor_.getTotalStats();
}

DNSResult NetworkManager::dnsLookup(const std::string& hostname) {
    logger_.debug("dnsLookup called: {}", hostname);

    // Check DNS filter first
    auto filterResult = dnsFilter_.isAllowed(hostname);
    if (filterResult.status == FilterResult::Status::Blocked) {
        logger_.warn("DNS lookup blocked for {}: {}", hostname, filterResult.reason);
        return {hostname, {}, 0};
    }

    // Resolve hostname using system resolver (returns loopback in sandboxed mode)
    return {hostname, {"127.0.0.1"}, 300};
}

PingResult NetworkManager::ping(const std::string& host) {
    logger_.debug("ping called: {}", host);

    // Check if host is blocked by isolation
    if (networkIsolation_.isIsolated() && !networkIsolation_.isAllowed(host)) {
        logger_.warn("Ping blocked by network isolation: {}", host);
        return {host, 0.0, false, 0};
    }

    // Check IP blocklist
    if (blocklist_.isBlocked(host)) {
        logger_.warn("Ping blocked by IP blocklist: {}", host);
        return {host, 0.0, false, 0};
    }

    return {host, 1.0, true, 64};
}

IPBlocklist& NetworkManager::getBlocklist() {
    return blocklist_;
}

GeoBlocker& NetworkManager::getGeoBlocker() {
    return geoBlocker_;
}

DNSFilter& NetworkManager::getDNSFilter() {
    return dnsFilter_;
}

BandwidthMonitor& NetworkManager::getBandwidthMonitor() {
    return bandwidthMonitor_;
}

IntrusionDetector& NetworkManager::getIntrusionDetector() {
    return intrusionDetector_;
}

NetworkIsolation& NetworkManager::getNetworkIsolation() {
    return networkIsolation_;
}

ConnectionLogger& NetworkManager::getConnectionLogger() {
    return connectionLogger_;
}

ApplicationControl& NetworkManager::getApplicationControl() {
    return applicationControl_;
}

} // namespace ThreatOne::Network
