#include "api/Router.h"
#include <sstream>
#include <algorithm>

namespace ThreatOne::Api {

Router::Router() = default;

void Router::addRoute(HttpMethod method, const std::string& pathPattern, Handler handler) {
    routes_.push_back(Route{method, pathPattern, std::move(handler), {}});
}

void Router::addRouteWithMiddleware(HttpMethod method, const std::string& pathPattern,
                                     Handler handler, std::vector<Middleware> middlewares) {
    routes_.push_back(Route{method, pathPattern, std::move(handler), std::move(middlewares)});
}

void Router::addMiddleware(Middleware middleware) {
    globalMiddlewares_.push_back(std::move(middleware));
}

HttpResponse Router::handleRequest(const HttpRequest& request) {
    for (auto& route : routes_) {
        if (route.method != request.method) {
            continue;
        }

        auto matchResult = matchPath(route.pathPattern, request.path);
        if (matchResult.matched) {
            // Create a modified request with path params filled in
            HttpRequest modifiedRequest = request;
            modifiedRequest.pathParams = matchResult.params;

            return executeMiddlewareChain(modifiedRequest, route);
        }
    }

    // No route matched - return 404
    HttpResponse response;
    response.statusCode = 404;
    response.contentType = "application/json";
    response.body = R"({"error":"Not Found","message":"No route matches )" + request.path + R"("})";
    return response;
}

std::vector<Route> Router::getRegisteredRoutes() const {
    return routes_;
}

Router::MatchResult Router::matchPath(const std::string& pattern, const std::string& path) const {
    MatchResult result;

    // Split pattern and path into segments
    auto splitPath = [](const std::string& p) -> std::vector<std::string> {
        std::vector<std::string> segments;
        std::istringstream stream(p);
        std::string segment;
        while (std::getline(stream, segment, '/')) {
            if (!segment.empty()) {
                segments.push_back(segment);
            }
        }
        return segments;
    };

    auto patternSegments = splitPath(pattern);
    auto pathSegments = splitPath(path);

    if (patternSegments.size() != pathSegments.size()) {
        result.matched = false;
        return result;
    }

    std::map<std::string, std::string> params;

    for (size_t i = 0; i < patternSegments.size(); ++i) {
        const auto& ps = patternSegments[i];
        const auto& actual = pathSegments[i];

        if (!ps.empty() && ps[0] == ':') {
            // This is a path parameter
            std::string paramName = ps.substr(1);
            params[paramName] = actual;
        } else if (ps != actual) {
            result.matched = false;
            return result;
        }
    }

    result.matched = true;
    result.params = params;
    return result;
}

HttpResponse Router::executeMiddlewareChain(const HttpRequest& request, const Route& route) {
    // Build the handler chain: global middlewares -> route middlewares -> handler
    Handler finalHandler = route.handler;

    // Apply route-specific middlewares in reverse order
    for (auto it = route.middlewares.rbegin(); it != route.middlewares.rend(); ++it) {
        auto mw = *it;
        Handler next = finalHandler;
        finalHandler = [mw, next](const HttpRequest& req) -> HttpResponse {
            return mw(req, next);
        };
    }

    // Apply global middlewares in reverse order
    for (auto it = globalMiddlewares_.rbegin(); it != globalMiddlewares_.rend(); ++it) {
        auto mw = *it;
        Handler next = finalHandler;
        finalHandler = [mw, next](const HttpRequest& req) -> HttpResponse {
            return mw(req, next);
        };
    }

    return finalHandler(request);
}

std::string httpMethodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
    }
    return "UNKNOWN";
}

HttpMethod stringToHttpMethod(const std::string& method) {
    if (method == "GET") return HttpMethod::GET;
    if (method == "POST") return HttpMethod::POST;
    if (method == "PUT") return HttpMethod::PUT;
    if (method == "DELETE") return HttpMethod::DELETE;
    if (method == "PATCH") return HttpMethod::PATCH;
    return HttpMethod::GET;
}

} // namespace ThreatOne::Api
