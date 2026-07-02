#include <doctest/doctest.h>
#include <api/Router.h>
#include <string>
#include <vector>

using namespace ThreatOne::Api;

TEST_CASE("Router - Add and match simple route") {
    Router router;
    bool handlerCalled = false;

    router.addRoute(HttpMethod::GET, "/api/v1/status", [&](const HttpRequest&) -> HttpResponse {
        handlerCalled = true;
        HttpResponse resp;
        resp.statusCode = 200;
        resp.body = R"({"status":"ok"})";
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/status";

    auto response = router.handleRequest(req);
    CHECK(handlerCalled);
    CHECK(response.statusCode == 200);
    CHECK(response.body == R"({"status":"ok"})");
}

TEST_CASE("Router - Path parameter extraction") {
    Router router;
    std::string capturedId;

    router.addRoute(HttpMethod::GET, "/api/v1/users/:id", [&](const HttpRequest& req) -> HttpResponse {
        auto it = req.pathParams.find("id");
        if (it != req.pathParams.end()) {
            capturedId = it->second;
        }
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/users/user-123";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 200);
    CHECK(capturedId == "user-123");
}

TEST_CASE("Router - Multiple path parameters") {
    Router router;
    std::string capturedUserId;
    std::string capturedRoleId;

    router.addRoute(HttpMethod::GET, "/api/v1/users/:userId/roles/:roleId",
                    [&](const HttpRequest& req) -> HttpResponse {
        capturedUserId = req.pathParams.at("userId");
        capturedRoleId = req.pathParams.at("roleId");
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/users/u42/roles/admin";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 200);
    CHECK(capturedUserId == "u42");
    CHECK(capturedRoleId == "admin");
}

TEST_CASE("Router - 404 on unknown route") {
    Router router;

    router.addRoute(HttpMethod::GET, "/api/v1/known", [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/unknown";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 404);
}

TEST_CASE("Router - Method mismatch returns 404") {
    Router router;

    router.addRoute(HttpMethod::GET, "/api/v1/data", [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::POST;
    req.path = "/api/v1/data";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 404);
}

TEST_CASE("Router - Global middleware execution") {
    Router router;
    std::vector<std::string> order;

    router.addMiddleware([&](const HttpRequest& req, Handler next) -> HttpResponse {
        order.push_back("middleware1_before");
        auto resp = next(req);
        order.push_back("middleware1_after");
        return resp;
    });

    router.addRoute(HttpMethod::GET, "/api/v1/test", [&](const HttpRequest&) -> HttpResponse {
        order.push_back("handler");
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/test";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 200);
    REQUIRE(order.size() == 3);
    CHECK(order[0] == "middleware1_before");
    CHECK(order[1] == "handler");
    CHECK(order[2] == "middleware1_after");
}

TEST_CASE("Router - Multiple middlewares execute in order") {
    Router router;
    std::vector<int> order;

    router.addMiddleware([&](const HttpRequest& req, Handler next) -> HttpResponse {
        order.push_back(1);
        return next(req);
    });

    router.addMiddleware([&](const HttpRequest& req, Handler next) -> HttpResponse {
        order.push_back(2);
        return next(req);
    });

    router.addRoute(HttpMethod::GET, "/test", [&](const HttpRequest&) -> HttpResponse {
        order.push_back(3);
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/test";

    router.handleRequest(req);
    REQUIRE(order.size() == 3);
    CHECK(order[0] == 1);
    CHECK(order[1] == 2);
    CHECK(order[2] == 3);
}

TEST_CASE("Router - Middleware can short-circuit") {
    Router router;
    bool handlerCalled = false;

    router.addMiddleware([](const HttpRequest& /*req*/, Handler /*next*/) -> HttpResponse {
        HttpResponse resp;
        resp.statusCode = 401;
        resp.body = R"({"error":"Unauthorized"})";
        return resp;
    });

    router.addRoute(HttpMethod::GET, "/api/v1/secret", [&](const HttpRequest&) -> HttpResponse {
        handlerCalled = true;
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    });

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/secret";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 401);
    CHECK_FALSE(handlerCalled);
}

TEST_CASE("Router - Route-specific middleware") {
    Router router;
    bool routeMiddlewareCalled = false;

    Middleware routeMiddleware = [&](const HttpRequest& req, Handler next) -> HttpResponse {
        routeMiddlewareCalled = true;
        return next(req);
    };

    router.addRouteWithMiddleware(HttpMethod::GET, "/api/v1/protected",
                                   [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.statusCode = 200;
        return resp;
    }, {routeMiddleware});

    HttpRequest req;
    req.method = HttpMethod::GET;
    req.path = "/api/v1/protected";

    auto response = router.handleRequest(req);
    CHECK(response.statusCode == 200);
    CHECK(routeMiddlewareCalled);
}

TEST_CASE("Router - Get registered routes") {
    Router router;

    router.addRoute(HttpMethod::GET, "/api/v1/a", [](const HttpRequest&) -> HttpResponse { return {}; });
    router.addRoute(HttpMethod::POST, "/api/v1/b", [](const HttpRequest&) -> HttpResponse { return {}; });
    router.addRoute(HttpMethod::DELETE, "/api/v1/c", [](const HttpRequest&) -> HttpResponse { return {}; });

    auto routes = router.getRegisteredRoutes();
    CHECK(routes.size() == 3);
    CHECK(routes[0].method == HttpMethod::GET);
    CHECK(routes[1].method == HttpMethod::POST);
    CHECK(routes[2].method == HttpMethod::DELETE);
}

TEST_CASE("Router - HttpMethod to string conversion") {
    CHECK(httpMethodToString(HttpMethod::GET) == "GET");
    CHECK(httpMethodToString(HttpMethod::POST) == "POST");
    CHECK(httpMethodToString(HttpMethod::PUT) == "PUT");
    CHECK(httpMethodToString(HttpMethod::DELETE) == "DELETE");
    CHECK(httpMethodToString(HttpMethod::PATCH) == "PATCH");
}

TEST_CASE("Router - String to HttpMethod conversion") {
    CHECK(stringToHttpMethod("GET") == HttpMethod::GET);
    CHECK(stringToHttpMethod("POST") == HttpMethod::POST);
    CHECK(stringToHttpMethod("PUT") == HttpMethod::PUT);
    CHECK(stringToHttpMethod("DELETE") == HttpMethod::DELETE);
    CHECK(stringToHttpMethod("PATCH") == HttpMethod::PATCH);
}
