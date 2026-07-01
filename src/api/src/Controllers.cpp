#include "api/Controllers.h"
#include <nlohmann/json.hpp>

namespace ThreatOne::Api {

using json = nlohmann::json;

// ApiController base class methods
HttpResponse ApiController::jsonResponse(int statusCode, const std::string& body) const {
    HttpResponse response;
    response.statusCode = statusCode;
    response.contentType = "application/json";
    response.body = body;
    response.headers["Content-Type"] = "application/json";
    return response;
}

HttpResponse ApiController::errorResponse(int statusCode, const std::string& message) const {
    json error;
    error["error"] = true;
    error["message"] = message;
    error["statusCode"] = statusCode;
    return jsonResponse(statusCode, error.dump());
}

HttpResponse ApiController::notFoundResponse(const std::string& resource) const {
    return errorResponse(404, resource + " not found");
}

HttpResponse ApiController::createdResponse(const std::string& body) const {
    return jsonResponse(201, body);
}

HttpResponse ApiController::noContentResponse() const {
    HttpResponse response;
    response.statusCode = 204;
    response.body = "";
    response.contentType = "";
    return response;
}

// ScanController
void ScanController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listScans(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getScan(req); });
    router.addRoute(HttpMethod::POST, basePath(), [this](const HttpRequest& req) { return createScan(req); });
    router.addRoute(HttpMethod::PUT, basePath() + "/:id", [this](const HttpRequest& req) { return updateScan(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deleteScan(req); });
}

HttpResponse ScanController::listScans(const HttpRequest& /*request*/) {
    json response = json::array();
    json scan1;
    scan1["id"] = "scan-001";
    scan1["type"] = "full";
    scan1["status"] = "completed";
    scan1["target"] = "/home/user";
    response.push_back(scan1);
    return jsonResponse(200, response.dump());
}

HttpResponse ScanController::getScan(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing scan ID");
    }
    json scan;
    scan["id"] = it->second;
    scan["type"] = "full";
    scan["status"] = "completed";
    scan["target"] = "/home/user";
    scan["threatsFound"] = 0;
    return jsonResponse(200, scan.dump());
}

HttpResponse ScanController::createScan(const HttpRequest& request) {
    json body;
    if (!request.body.empty()) {
        try {
            body = json::parse(request.body);
        } catch (const std::exception&) {
            return errorResponse(400, "Invalid JSON body");
        }
    }
    json response;
    response["id"] = "scan-new";
    response["type"] = body.value("type", "quick");
    response["status"] = "pending";
    response["target"] = body.value("target", "/");
    return createdResponse(response.dump());
}

HttpResponse ScanController::updateScan(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing scan ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "updated";
    return jsonResponse(200, response.dump());
}

HttpResponse ScanController::deleteScan(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing scan ID");
    }
    return noContentResponse();
}

// AlertController
void AlertController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listAlerts(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getAlert(req); });
    router.addRoute(HttpMethod::POST, basePath() + "/:id/acknowledge", [this](const HttpRequest& req) { return acknowledgeAlert(req); });
    router.addRoute(HttpMethod::POST, basePath() + "/:id/resolve", [this](const HttpRequest& req) { return resolveAlert(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deleteAlert(req); });
}

HttpResponse AlertController::listAlerts(const HttpRequest& /*request*/) {
    json response = json::array();
    json alert;
    alert["id"] = "alert-001";
    alert["severity"] = "high";
    alert["type"] = "malware_detected";
    alert["status"] = "active";
    response.push_back(alert);
    return jsonResponse(200, response.dump());
}

HttpResponse AlertController::getAlert(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing alert ID");
    }
    json alert;
    alert["id"] = it->second;
    alert["severity"] = "high";
    alert["type"] = "malware_detected";
    alert["status"] = "active";
    return jsonResponse(200, alert.dump());
}

HttpResponse AlertController::acknowledgeAlert(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing alert ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "acknowledged";
    return jsonResponse(200, response.dump());
}

HttpResponse AlertController::resolveAlert(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing alert ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "resolved";
    return jsonResponse(200, response.dump());
}

HttpResponse AlertController::deleteAlert(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing alert ID");
    }
    return noContentResponse();
}

// AssetController
void AssetController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listAssets(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getAsset(req); });
    router.addRoute(HttpMethod::POST, basePath(), [this](const HttpRequest& req) { return createAsset(req); });
    router.addRoute(HttpMethod::PUT, basePath() + "/:id", [this](const HttpRequest& req) { return updateAsset(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deleteAsset(req); });
}

HttpResponse AssetController::listAssets(const HttpRequest& /*request*/) {
    json response = json::array();
    json asset;
    asset["id"] = "asset-001";
    asset["hostname"] = "workstation-01";
    asset["type"] = "endpoint";
    asset["status"] = "active";
    response.push_back(asset);
    return jsonResponse(200, response.dump());
}

HttpResponse AssetController::getAsset(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing asset ID");
    }
    json asset;
    asset["id"] = it->second;
    asset["hostname"] = "workstation-01";
    asset["type"] = "endpoint";
    asset["status"] = "active";
    return jsonResponse(200, asset.dump());
}

HttpResponse AssetController::createAsset(const HttpRequest& request) {
    json body;
    if (!request.body.empty()) {
        try {
            body = json::parse(request.body);
        } catch (const std::exception&) {
            return errorResponse(400, "Invalid JSON body");
        }
    }
    json response;
    response["id"] = "asset-new";
    response["hostname"] = body.value("hostname", "unknown");
    response["type"] = body.value("type", "endpoint");
    response["status"] = "active";
    return createdResponse(response.dump());
}

HttpResponse AssetController::updateAsset(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing asset ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "updated";
    return jsonResponse(200, response.dump());
}

HttpResponse AssetController::deleteAsset(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing asset ID");
    }
    return noContentResponse();
}

// UserController
void UserController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listUsers(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getUser(req); });
    router.addRoute(HttpMethod::POST, basePath(), [this](const HttpRequest& req) { return createUser(req); });
    router.addRoute(HttpMethod::PUT, basePath() + "/:id", [this](const HttpRequest& req) { return updateUser(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deleteUser(req); });
}

HttpResponse UserController::listUsers(const HttpRequest& /*request*/) {
    json response = json::array();
    json user;
    user["id"] = "user-001";
    user["username"] = "admin";
    user["email"] = "admin@example.com";
    user["role"] = "administrator";
    response.push_back(user);
    return jsonResponse(200, response.dump());
}

HttpResponse UserController::getUser(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing user ID");
    }
    json user;
    user["id"] = it->second;
    user["username"] = "admin";
    user["email"] = "admin@example.com";
    user["role"] = "administrator";
    return jsonResponse(200, user.dump());
}

HttpResponse UserController::createUser(const HttpRequest& request) {
    json body;
    if (!request.body.empty()) {
        try {
            body = json::parse(request.body);
        } catch (const std::exception&) {
            return errorResponse(400, "Invalid JSON body");
        }
    }
    json response;
    response["id"] = "user-new";
    response["username"] = body.value("username", "newuser");
    response["email"] = body.value("email", "user@example.com");
    response["role"] = body.value("role", "viewer");
    return createdResponse(response.dump());
}

HttpResponse UserController::updateUser(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing user ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "updated";
    return jsonResponse(200, response.dump());
}

HttpResponse UserController::deleteUser(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing user ID");
    }
    return noContentResponse();
}

// PolicyController
void PolicyController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listPolicies(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getPolicy(req); });
    router.addRoute(HttpMethod::POST, basePath(), [this](const HttpRequest& req) { return createPolicy(req); });
    router.addRoute(HttpMethod::PUT, basePath() + "/:id", [this](const HttpRequest& req) { return updatePolicy(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deletePolicy(req); });
}

HttpResponse PolicyController::listPolicies(const HttpRequest& /*request*/) {
    json response = json::array();
    json policy;
    policy["id"] = "policy-001";
    policy["name"] = "Default Security Policy";
    policy["enabled"] = true;
    policy["type"] = "security";
    response.push_back(policy);
    return jsonResponse(200, response.dump());
}

HttpResponse PolicyController::getPolicy(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing policy ID");
    }
    json policy;
    policy["id"] = it->second;
    policy["name"] = "Default Security Policy";
    policy["enabled"] = true;
    policy["type"] = "security";
    return jsonResponse(200, policy.dump());
}

HttpResponse PolicyController::createPolicy(const HttpRequest& request) {
    json body;
    if (!request.body.empty()) {
        try {
            body = json::parse(request.body);
        } catch (const std::exception&) {
            return errorResponse(400, "Invalid JSON body");
        }
    }
    json response;
    response["id"] = "policy-new";
    response["name"] = body.value("name", "New Policy");
    response["enabled"] = body.value("enabled", true);
    response["type"] = body.value("type", "security");
    return createdResponse(response.dump());
}

HttpResponse PolicyController::updatePolicy(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing policy ID");
    }
    json response;
    response["id"] = it->second;
    response["status"] = "updated";
    return jsonResponse(200, response.dump());
}

HttpResponse PolicyController::deletePolicy(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing policy ID");
    }
    return noContentResponse();
}

// ReportController
void ReportController::registerRoutes(IRouter& router) {
    router.addRoute(HttpMethod::GET, basePath(), [this](const HttpRequest& req) { return listReports(req); });
    router.addRoute(HttpMethod::GET, basePath() + "/:id", [this](const HttpRequest& req) { return getReport(req); });
    router.addRoute(HttpMethod::POST, basePath(), [this](const HttpRequest& req) { return generateReport(req); });
    router.addRoute(HttpMethod::DELETE, basePath() + "/:id", [this](const HttpRequest& req) { return deleteReport(req); });
}

HttpResponse ReportController::listReports(const HttpRequest& /*request*/) {
    json response = json::array();
    json report;
    report["id"] = "report-001";
    report["title"] = "Weekly Security Summary";
    report["type"] = "summary";
    report["generatedAt"] = "2024-01-15T10:00:00Z";
    response.push_back(report);
    return jsonResponse(200, response.dump());
}

HttpResponse ReportController::getReport(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing report ID");
    }
    json report;
    report["id"] = it->second;
    report["title"] = "Weekly Security Summary";
    report["type"] = "summary";
    report["generatedAt"] = "2024-01-15T10:00:00Z";
    report["content"] = "Security report content";
    return jsonResponse(200, report.dump());
}

HttpResponse ReportController::generateReport(const HttpRequest& request) {
    json body;
    if (!request.body.empty()) {
        try {
            body = json::parse(request.body);
        } catch (const std::exception&) {
            return errorResponse(400, "Invalid JSON body");
        }
    }
    json response;
    response["id"] = "report-new";
    response["title"] = body.value("title", "New Report");
    response["type"] = body.value("type", "summary");
    response["status"] = "generating";
    return createdResponse(response.dump());
}

HttpResponse ReportController::deleteReport(const HttpRequest& request) {
    auto it = request.pathParams.find("id");
    if (it == request.pathParams.end()) {
        return errorResponse(400, "Missing report ID");
    }
    return noContentResponse();
}

} // namespace ThreatOne::Api
