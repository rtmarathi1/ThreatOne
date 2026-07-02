// ThreatOne App - UsersViewModel Implementation

#include "app/viewmodels/UsersViewModel.h"
#include <string>
#include <vector>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

UsersViewModel::UsersViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("UsersViewModel")) {
}

UsersViewModel::~UsersViewModel() = default;

int UsersViewModel::userCount() const { return userCount_; }
int UsersViewModel::activeUsers() const { return activeUsers_; }

void UsersViewModel::addUser(const QVariantMap& /*params*/) {
    ++userCount_;
    emit userAdded();
    emit dataUpdated();
}

void UsersViewModel::removeUser(const QString& /*id*/) {
    if (userCount_ > 0) --userCount_;
    emit dataUpdated();
}

void UsersViewModel::updateRole(const QString& /*userId*/, const QString& /*roleId*/) {
    emit roleChanged();
    emit dataUpdated();
}

QVariantList UsersViewModel::getAuditLog(const QVariantMap& /*filters*/) {
    return {};
}

void UsersViewModel::resetPassword(const QString& /*id*/) {
    emit dataUpdated();
}

void UsersViewModel::toggleMFA(const QString& /*id*/) {
    emit dataUpdated();
}

#else // !ENABLE_QT_BUILD

UsersViewModel::UsersViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("UsersViewModel")) {
}

UsersViewModel::~UsersViewModel() = default;

int UsersViewModel::userCount() const { return userCount_; }
int UsersViewModel::activeUsers() const { return activeUsers_; }

void UsersViewModel::addUser(const std::string& /*params*/) {
    ++userCount_;
}

void UsersViewModel::removeUser(const std::string& /*id*/) {
    if (userCount_ > 0) --userCount_;
}

void UsersViewModel::updateRole(const std::string& /*userId*/, const std::string& /*roleId*/) {}

std::vector<std::string> UsersViewModel::getAuditLog(const std::string& /*filters*/) {
    return {};
}

void UsersViewModel::resetPassword(const std::string& /*id*/) {}

void UsersViewModel::toggleMFA(const std::string& /*id*/) {}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
