#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <optional>

namespace ThreatOne::Api {

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH
};

struct HttpRequest {
    HttpMethod method = HttpMethod::GET;
    std::string path;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> queryParams;
    std::string body;
    std::map<std::string, std::string> pathParams;
    std::string clientIP;
};

struct HttpResponse {
    int statusCode = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType = "application/json";
};

using Handler = std::function<HttpResponse(const HttpRequest&)>;
using Middleware = std::function<HttpResponse(const HttpRequest&, Handler)>;

struct Route {
    HttpMethod method;
    std::string pathPattern;
    Handler handler;
    std::vector<Middleware> middlewares;
};

class IRouter {
public:
    virtual ~IRouter() = default;

    virtual void addRoute(HttpMethod method, const std::string& pathPattern, Handler handler) = 0;
    virtual void addRouteWithMiddleware(HttpMethod method, const std::string& pathPattern,
                                        Handler handler, std::vector<Middleware> middlewares) = 0;
    virtual void addMiddleware(Middleware middleware) = 0;
    virtual HttpResponse handleRequest(const HttpRequest& request) = 0;
    virtual std::vector<Route> getRegisteredRoutes() const = 0;
};

class Router : public IRouter {
public:
    Router();

    void addRoute(HttpMethod method, const std::string& pathPattern, Handler handler) override;
    void addRouteWithMiddleware(HttpMethod method, const std::string& pathPattern,
                                Handler handler, std::vector<Middleware> middlewares) override;
    void addMiddleware(Middleware middleware) override;
    HttpResponse handleRequest(const HttpRequest& request) override;
    std::vector<Route> getRegisteredRoutes() const override;

private:
    struct MatchResult {
        bool matched = false;
        std::map<std::string, std::string> params;
    };

    MatchResult matchPath(const std::string& pattern, const std::string& path) const;
    HttpResponse executeMiddlewareChain(const HttpRequest& request, const Route& route);

    std::vector<Route> routes_;
    std::vector<Middleware> globalMiddlewares_;
};

std::string httpMethodToString(HttpMethod method);
HttpMethod stringToHttpMethod(const std::string& method);

} // namespace ThreatOne::Api
