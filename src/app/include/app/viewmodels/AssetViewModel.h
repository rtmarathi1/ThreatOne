#pragma once

// ThreatOne App - AssetViewModel
// Provides asset inventory and health data to the QML UI layer.

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_QT_BUILD
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#endif

#include "core/Logger.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

class AssetViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(int totalAssets READ totalAssets NOTIFY dataUpdated)
    Q_PROPERTY(int healthyCount READ healthyCount NOTIFY dataUpdated)
    Q_PROPERTY(int atRiskCount READ atRiskCount NOTIFY dataUpdated)

public:
    explicit AssetViewModel(QObject* parent = nullptr);
    ~AssetViewModel() override;

    int totalAssets() const;
    int healthyCount() const;
    int atRiskCount() const;

    Q_INVOKABLE QVariantList getAssetDetail(const QString& id);
    Q_INVOKABLE QVariantList getSoftwareInventory(const QString& id);
    Q_INVOKABLE QVariantList getVulnerabilities(const QString& id);
    Q_INVOKABLE QVariantList getEvents(const QString& id);
    Q_INVOKABLE void scanAsset(const QString& id);

signals:
    void dataUpdated();
    void assetStatusChanged();
    void newVulnerability();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int totalAssets_ = 0;
    int healthyCount_ = 0;
    int atRiskCount_ = 0;
};

#else // !ENABLE_QT_BUILD

class AssetViewModel {
public:
    AssetViewModel();
    ~AssetViewModel();

    int totalAssets() const;
    int healthyCount() const;
    int atRiskCount() const;

    std::vector<std::string> getAssetDetail(const std::string& id);
    std::vector<std::string> getSoftwareInventory(const std::string& id);
    std::vector<std::string> getVulnerabilities(const std::string& id);
    std::vector<std::string> getEvents(const std::string& id);
    void scanAsset(const std::string& id);

private:
    ThreatOne::Core::ModuleLogger logger_;
    int totalAssets_ = 0;
    int healthyCount_ = 0;
    int atRiskCount_ = 0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
