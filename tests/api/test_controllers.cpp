#include <doctest/doctest.h>
#include <api/Controllers.h>
#include <api/Router.h>
#include <nlohmann/json.hpp>

using namespace ThreatOne::Api;
using json = nlohmann::json;

TEST_CASE("ScanController - Register routes") {
    Router router;
    ScanController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 5);
}

TEST_CASE("ScanController - List scans") {
    ScanController controller;
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/scans";

    auto response = controller.listScans(req);
    CHECK(response.statusCode == 200);

    auto body = json::parse(response.body);
    CHECK(body.is_array());
    CHECK(body.size() >= 1);
    CHECK(body[0]["id"] == "scan-001");
}

TEST_CASE("ScanController - Get scan by ID") {
    ScanController controller;
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/scans/scan-123";
    req.pathParams["id"] = "scan-123";

    auto response = controller.getScan(req);
    CHECK(response.statusCode == 200);

    auto body = json::parse(response.body);
    CHECK(body["id"] == "scan-123");
}

TEST_CASE("ScanController - Create scan") {
    ScanController controller;
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.path = "/api/v1/scans";
    json bodyJson;
    bodyJson["type"] = "full";
    bodyJson["target"] = "/etc";
    req.body = bodyJson.dump();

    auto response = controller.createScan(req);
    CHECK(response.statusCode == 201);

    auto body = json::parse(response.body);
    CHECK(body["type"] == "full");
    CHECK(body["target"] == "/etc");
    CHECK(body["status"] == "pending");
}

TEST_CASE("ScanController - Delete scan returns 204") {
    ScanController controller;
    HttpRequest req;
    req.method = HttpMethod::DELETE;
    req.path = "/api/v1/scans/scan-del";
    req.pathParams["id"] = "scan-del";

    auto response = controller.deleteScan(req);
    CHECK(response.statusCode == 204);
}

TEST_CASE("AlertController - Register routes") {
    Router router;
    AlertController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 5);
}

TEST_CASE("AlertController - Acknowledge alert") {
    AlertController controller;
    HttpRequest req;
    req.pathParams["id"] = "alert-001";

    auto response = controller.acknowledgeAlert(req);
    CHECK(response.statusCode == 200);

    auto body = json::parse(response.body);
    CHECK(body["id"] == "alert-001");
    CHECK(body["status"] == "acknowledged");
}

TEST_CASE("AlertController - Resolve alert") {
    AlertController controller;
    HttpRequest req;
    req.pathParams["id"] = "alert-002";

    auto response = controller.resolveAlert(req);
    CHECK(response.statusCode == 200);

    auto body = json::parse(response.body);
    CHECK(body["status"] == "resolved");
}

TEST_CASE("AssetController - Register routes") {
    Router router;
    AssetController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 5);
}

TEST_CASE("AssetController - Create asset") {
    AssetController controller;
    HttpRequest req;
    json bodyJson;
    bodyJson["hostname"] = "server-01";
    bodyJson["type"] = "server";
    req.body = bodyJson.dump();

    auto response = controller.createAsset(req);
    CHECK(response.statusCode == 201);

    auto body = json::parse(response.body);
    CHECK(body["hostname"] == "server-01");
    CHECK(body["type"] == "server");
}

TEST_CASE("UserController - Register routes") {
    Router router;
    UserController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 5);
}

TEST_CASE("UserController - Create user") {
    UserController controller;
    HttpRequest req;
    json bodyJson;
    bodyJson["username"] = "testuser";
    bodyJson["email"] = "test@example.com";
    bodyJson["role"] = "analyst";
    req.body = bodyJson.dump();

    auto response = controller.createUser(req);
    CHECK(response.statusCode == 201);

    auto body = json::parse(response.body);
    CHECK(body["username"] == "testuser");
    CHECK(body["email"] == "test@example.com");
    CHECK(body["role"] == "analyst");
}

TEST_CASE("PolicyController - Register routes") {
    Router router;
    PolicyController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 5);
}

TEST_CASE("PolicyController - Create policy") {
    PolicyController controller;
    HttpRequest req;
    json bodyJson;
    bodyJson["name"] = "Strict Policy";
    bodyJson["type"] = "compliance";
    req.body = bodyJson.dump();

    auto response = controller.createPolicy(req);
    CHECK(response.statusCode == 201);

    auto body = json::parse(response.body);
    CHECK(body["name"] == "Strict Policy");
    CHECK(body["type"] == "compliance");
}

TEST_CASE("ReportController - Register routes") {
    Router router;
    ReportController controller;
    controller.registerRoutes(router);

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 4);
}

TEST_CASE("ReportController - Generate report") {
    ReportController controller;
    HttpRequest req;
    json bodyJson;
    bodyJson["title"] = "Monthly Report";
    bodyJson["type"] = "monthly";
    req.body = bodyJson.dump();

    auto response = controller.generateReport(req);
    CHECK(response.statusCode == 201);

    auto body = json::parse(response.body);
    CHECK(body["title"] == "Monthly Report");
    CHECK(body["status"] == "generating");
}

TEST_CASE("Controller - Full router integration") {
    Router router;
    ScanController scanCtrl;
    scanCtrl.registerRoutes(router);

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/scans/scan-42";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 200);

    auto body = json::parse(response.body);
    CHECK(body["id"] == "scan-42");
}

TEST_CASE("Controller - Invalid JSON body returns 400") {
    ScanController controller;
    HttpRequest req;
    req.body = "not valid json{{{";

    auto response = controller.createScan(req);
    CHECK(response.statusCode == 400);
}
