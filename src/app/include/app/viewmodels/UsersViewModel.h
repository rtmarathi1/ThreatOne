#pragma once

// ThreatOne App - UsersViewModel
// Provides user management and audit data to the QML UI layer.

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_QT_BUILD
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#endif

#include "core/Logger.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

class UsersViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(int userCount READ userCount NOTIFY dataUpdated)
    Q_PROPERTY(int activeUsers READ activeUsers NOTIFY dataUpdated)

public:
    explicit UsersViewModel(QObject* parent = nullptr);
    ~UsersViewModel() override;

    int userCount() const;
    int activeUsers() const;

    Q_INVOKABLE void addUser(const QVariantMap& params);
    Q_INVOKABLE void removeUser(const QString& id);
    Q_INVOKABLE void updateRole(const QString& userId, const QString& roleId);
    Q_INVOKABLE QVariantList getAuditLog(const QVariantMap& filters);
    Q_INVOKABLE void resetPassword(const QString& id);
    Q_INVOKABLE void toggleMFA(const QString& id);

signals:
    void dataUpdated();
    void userAdded();
    void roleChanged();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int userCount_ = 0;
    int activeUsers_ = 0;
};

#else // !ENABLE_QT_BUILD

class UsersViewModel {
public:
    UsersViewModel();
    ~UsersViewModel();

    int userCount() const;
    int activeUsers() const;

    void addUser(const std::string& params);
    void removeUser(const std::string& id);
    void updateRole(const std::string& userId, const std::string& roleId);
    std::vector<std::string> getAuditLog(const std::string& filters);
    void resetPassword(const std::string& id);
    void toggleMFA(const std::string& id);

private:
    ThreatOne::Core::ModuleLogger logger_;
    int userCount_ = 0;
    int activeUsers_ = 0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
