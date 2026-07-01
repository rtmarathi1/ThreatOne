#include "network/NetworkManager.h"

namespace ThreatOne::Network {

NetworkManager::NetworkManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("NetworkManager")) {
    logger_.info("NetworkManager initialized (stub)");
}

HttpResponse NetworkManager::sendRequest(const HttpRequest& request) {
    logger_.info("sendRequest called: {} {}", request.method, request.url);
    return {200, "{\"status\": \"stub\"}", {}};
}

bool NetworkManager::openWebSocket(const std::string& url) {
    logger_.info("openWebSocket called: {}", url);
    return true;
}

std::vector<NetworkConnection> NetworkManager::getConnections() {
    logger_.info("getConnections called");
    return {};
}

TrafficStats NetworkManager::getTraffic() {
    logger_.info("getTraffic called");
    return {0, 0, 0, 0};
}

DNSResult NetworkManager::dnsLookup(const std::string& hostname) {
    logger_.info("dnsLookup called: {}", hostname);
    return {hostname, {"127.0.0.1"}, 300};
}

PingResult NetworkManager::ping(const std::string& host) {
    logger_.info("ping called: {}", host);
    return {host, 1.0, true, 64};
}

} // namespace ThreatOne::Network
