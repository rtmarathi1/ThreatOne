#include "sandbox/NetworkSandbox.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

NetworkSandbox::NetworkSandbox()
    : logger_(Core::Logger::instance().getModuleLogger("NetworkSandbox")) {
    logger_.info("NetworkSandbox initialized");
}

std::string NetworkSandbox::generateId(const std::string& prefix) {
    if (prefix == "DNS") {
        return "DNS-" + std::to_string(nextDnsId_++);
    } else if (prefix == "HTTP") {
        return "HTTP-" + std::to_string(nextHttpId_++);
    }
    return "C2-" + std::to_string(nextC2Id_++);
}

std::string NetworkSandbox::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

void NetworkSandbox::setSimulationConfig(const NetworkSimConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    logger_.info("Network simulation config updated");
}

NetworkSimConfig NetworkSandbox::getSimulationConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

std::string NetworkSandbox::recordDNSQuery(const std::string& sampleId,
                                            const std::string& domain,
                                            const std::string& queryType) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (domain.empty()) {
        return "";
    }

    DNSQuery query;
    query.id = generateId("DNS");
    query.domain = domain;
    query.queryType = queryType;
    query.timestamp = getCurrentTimestamp();
    query.simulated = true;

    // Resolve with overrides or default
    auto overrideIt = dnsOverrides_.find(domain);
    if (overrideIt != dnsOverrides_.end()) {
        query.response = overrideIt->second;
    } else {
        query.response = config_.defaultDNSResponse;
    }

    dnsQueries_[sampleId].push_back(query);
    logger_.info("Recorded DNS query for {}: {} ({})", sampleId, domain, queryType);
    return query.id;
}

std::vector<DNSQuery> NetworkSandbox::getDNSQueries(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = dnsQueries_.find(sampleId);
    if (it == dnsQueries_.end()) {
        return {};
    }
    return it->second;
}

void NetworkSandbox::setDNSResponse(const std::string& domain, const std::string& response) {
    std::lock_guard<std::mutex> lock(mutex_);
    dnsOverrides_[domain] = response;
}

std::string NetworkSandbox::resolveDNS(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = dnsOverrides_.find(domain);
    if (it != dnsOverrides_.end()) {
        return it->second;
    }
    return config_.defaultDNSResponse;
}

std::string NetworkSandbox::recordHTTPRequest(const std::string& sampleId,
                                              const std::string& method,
                                              const std::string& url) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (url.empty()) {
        return "";
    }

    HTTPRequest request;
    request.id = generateId("HTTP");
    request.method = method;
    request.url = url;
    request.statusCode = config_.defaultHTTPStatus;
    request.timestamp = getCurrentTimestamp();

    // Extract host from URL
    auto hostStart = url.find("://");
    if (hostStart != std::string::npos) {
        hostStart += 3;
        auto hostEnd = url.find('/', hostStart);
        request.host = url.substr(hostStart, hostEnd - hostStart);
    } else {
        request.host = url;
    }

    httpRequests_[sampleId].push_back(request);
    logger_.info("Recorded HTTP request for {}: {} {}", sampleId, method, url);
    return request.id;
}

std::vector<HTTPRequest> NetworkSandbox::getHTTPRequests(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = httpRequests_.find(sampleId);
    if (it == httpRequests_.end()) {
        return {};
    }
    return it->second;
}

std::string NetworkSandbox::recordC2Communication(const std::string& sampleId,
                                                   const std::string& server,
                                                   int port,
                                                   const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (server.empty()) {
        return "";
    }

    C2Communication comm;
    comm.id = generateId("C2");
    comm.serverAddress = server;
    comm.port = port;
    comm.protocol = protocol;
    comm.timestamp = getCurrentTimestamp();
    comm.confidence = 0.75;  // Default confidence

    c2Communications_[sampleId].push_back(comm);
    logger_.info("Recorded C2 communication for {}: {}:{} ({})", sampleId, server, port, protocol);
    return comm.id;
}

std::vector<C2Communication> NetworkSandbox::getC2Communications(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = c2Communications_.find(sampleId);
    if (it == c2Communications_.end()) {
        return {};
    }
    return it->second;
}

bool NetworkSandbox::detectC2Pattern(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = c2Communications_.find(sampleId);
    if (it == c2Communications_.end()) {
        return false;
    }
    // If any C2 communication detected, pattern exists
    return !it->second.empty();
}

std::vector<NetworkActivity> NetworkSandbox::getNetworkActivities(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<NetworkActivity> activities;

    // Convert DNS queries
    auto dnsIt = dnsQueries_.find(sampleId);
    if (dnsIt != dnsQueries_.end()) {
        for (const auto& query : dnsIt->second) {
            NetworkActivity activity;
            activity.protocol = "DNS";
            activity.destination = query.domain;
            activity.port = 53;
            activity.data = query.queryType + " query";
            activity.timestamp = query.timestamp;
            activities.push_back(activity);
        }
    }

    // Convert HTTP requests
    auto httpIt = httpRequests_.find(sampleId);
    if (httpIt != httpRequests_.end()) {
        for (const auto& req : httpIt->second) {
            NetworkActivity activity;
            activity.protocol = "HTTP";
            activity.destination = req.host;
            activity.port = 80;
            activity.data = req.method + " " + req.url;
            activity.timestamp = req.timestamp;
            activities.push_back(activity);
        }
    }

    // Convert C2 communications
    auto c2It = c2Communications_.find(sampleId);
    if (c2It != c2Communications_.end()) {
        for (const auto& comm : c2It->second) {
            NetworkActivity activity;
            activity.protocol = comm.protocol;
            activity.destination = comm.serverAddress;
            activity.port = comm.port;
            activity.data = "C2 communication";
            activity.timestamp = comm.timestamp;
            activities.push_back(activity);
        }
    }

    return activities;
}

uint64_t NetworkSandbox::getTotalDNSQueries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& [id, queries] : dnsQueries_) {
        total += queries.size();
    }
    return total;
}

uint64_t NetworkSandbox::getTotalHTTPRequests() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& [id, requests] : httpRequests_) {
        total += requests.size();
    }
    return total;
}

uint64_t NetworkSandbox::getTotalC2Detected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& [id, comms] : c2Communications_) {
        total += comms.size();
    }
    return total;
}

} // namespace ThreatOne::Sandbox
