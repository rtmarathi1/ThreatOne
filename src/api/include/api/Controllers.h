#pragma once

#include "api/Router.h"
#include <string>
#include <vector>
#include <memory>

namespace ThreatOne::Api {

class ApiController {
public:
    virtual ~ApiController() = default;

    virtual void registerRoutes(IRouter& router) = 0;
    [[nodiscard]] virtual std::string basePath() const = 0;

protected:
    HttpResponse jsonResponse(int statusCode, const std::string& body) const;
    HttpResponse errorResponse(int statusCode, const std::string& message) const;
    HttpResponse notFoundResponse(const std::string& resource) const;
    HttpResponse createdResponse(const std::string& body) const;
    HttpResponse noContentResponse() const;
};

class ScanController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/scans"; }

    HttpResponse listScans(const HttpRequest& request);
    HttpResponse getScan(const HttpRequest& request);
    HttpResponse createScan(const HttpRequest& request);
    HttpResponse updateScan(const HttpRequest& request);
    HttpResponse deleteScan(const HttpRequest& request);
};

class AlertController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/alerts"; }

    HttpResponse listAlerts(const HttpRequest& request);
    HttpResponse getAlert(const HttpRequest& request);
    HttpResponse acknowledgeAlert(const HttpRequest& request);
    HttpResponse resolveAlert(const HttpRequest& request);
    HttpResponse deleteAlert(const HttpRequest& request);
};

class AssetController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/assets"; }

    HttpResponse listAssets(const HttpRequest& request);
    HttpResponse getAsset(const HttpRequest& request);
    HttpResponse createAsset(const HttpRequest& request);
    HttpResponse updateAsset(const HttpRequest& request);
    HttpResponse deleteAsset(const HttpRequest& request);
};

class UserController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/users"; }

    HttpResponse listUsers(const HttpRequest& request);
    HttpResponse getUser(const HttpRequest& request);
    HttpResponse createUser(const HttpRequest& request);
    HttpResponse updateUser(const HttpRequest& request);
    HttpResponse deleteUser(const HttpRequest& request);
};

class PolicyController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/policies"; }

    HttpResponse listPolicies(const HttpRequest& request);
    HttpResponse getPolicy(const HttpRequest& request);
    HttpResponse createPolicy(const HttpRequest& request);
    HttpResponse updatePolicy(const HttpRequest& request);
    HttpResponse deletePolicy(const HttpRequest& request);
};

class ReportController : public ApiController {
public:
    void registerRoutes(IRouter& router) override;
    [[nodiscard]] std::string basePath() const override { return "/api/v1/reports"; }

    HttpResponse listReports(const HttpRequest& request);
    HttpResponse getReport(const HttpRequest& request);
    HttpResponse generateReport(const HttpRequest& request);
    HttpResponse deleteReport(const HttpRequest& request);
};

} // namespace ThreatOne::Api
