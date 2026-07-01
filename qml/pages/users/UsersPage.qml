import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: usersPage
    objectName: "users"
    color: ThemeManager.backgroundColor

    property var usersViewModel: QtObject {
        property int totalUsers: 45
        property int activeUsers: 38
        property int adminUsers: 5
        property int mfaEnabled: 42
    }

    property int currentTab: 0

    ScrollView {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingXL
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: ThemeManager.spacingXL

            // Header
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: ThemeManager.spacingXS
                    Text { text: "User Management"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Manage users, roles, access control, and audit logs"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: addUserLabel.implicitWidth + ThemeManager.spacingXL; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor
                    Text { id: addUserLabel; anchors.centerIn: parent; text: "+ Add User"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                }
            }

            // Stats
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Users"; value: usersViewModel.totalUsers.toString(); icon: "\u263A"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Active"; value: usersViewModel.activeUsers.toString(); icon: "\u2022"; iconColor: ThemeManager.successColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Administrators"; value: usersViewModel.adminUsers.toString(); icon: "\u2605"; iconColor: ThemeManager.warningColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "MFA Enabled"; value: usersViewModel.mfaEnabled.toString() + "/" + usersViewModel.totalUsers.toString(); icon: "\u2616"; iconColor: ThemeManager.successColor }
            }

            // Tabs
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Users", "Roles", "Access Control", "Audit Log"]
                    Rectangle {
                        Layout.preferredHeight: 36; Layout.preferredWidth: usrTabLabel.implicitWidth + ThemeManager.spacingXL; radius: ThemeManager.radiusMedium
                        color: usersPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: usersPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                        Text { id: usrTabLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: usersPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: usersPage.currentTab = index }
                    }
                }
            }

            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: usersPage.currentTab === 0 ? usersTab :
                                 usersPage.currentTab === 1 ? rolesTab :
                                 usersPage.currentTab === 2 ? accessTab : auditTab
            }
        }
    }

    // Users tab
    Component {
        id: usersTab
        DataTable {
            title: "User Accounts"
            columns: [
                { key: "username", label: "Username", width: 130 },
                { key: "email", label: "Email", width: 200 },
                { key: "role", label: "Role", width: 120 },
                { key: "status", label: "Status", width: 80 },
                { key: "lastLogin", label: "Last Login", width: 150 },
                { key: "mfa", label: "MFA", width: 70 }
            ]
            rows: [
                { username: "jsmith", email: "j.smith@corp.com", role: "Security Admin", status: "Active", lastLogin: "2024-12-15 14:30", mfa: "TOTP" },
                { username: "achen", email: "a.chen@corp.com", role: "SOC Analyst", status: "Active", lastLogin: "2024-12-15 14:25", mfa: "FIDO2" },
                { username: "mgarcia", email: "m.garcia@corp.com", role: "SOC Analyst", status: "Active", lastLogin: "2024-12-15 13:00", mfa: "TOTP" },
                { username: "kpatel", email: "k.patel@corp.com", role: "Incident Resp", status: "Active", lastLogin: "2024-12-15 12:45", mfa: "TOTP" },
                { username: "twilson", email: "t.wilson@corp.com", role: "SOC Analyst", status: "Active", lastLogin: "2024-12-15 11:30", mfa: "SMS" },
                { username: "admin", email: "admin@corp.com", role: "Super Admin", status: "Active", lastLogin: "2024-12-15 09:00", mfa: "FIDO2" },
                { username: "rjones", email: "r.jones@corp.com", role: "Viewer", status: "Active", lastLogin: "2024-12-14 16:00", mfa: "None" },
                { username: "lbrown", email: "l.brown@corp.com", role: "Network Admin", status: "Inactive", lastLogin: "2024-12-10 10:00", mfa: "TOTP" },
                { username: "svc-scanner", email: "scanner@internal", role: "Service Account", status: "Active", lastLogin: "2024-12-15 14:32", mfa: "Cert" },
                { username: "svc-backup", email: "backup@internal", role: "Service Account", status: "Active", lastLogin: "2024-12-15 02:00", mfa: "Cert" }
            ]
        }
    }

    // Roles tab
    Component {
        id: rolesTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Role Management"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            // Roles with permission matrix
            Repeater {
                model: ListModel {
                    ListElement { roleName: "Super Admin"; userCount: 2; permissions: "Full system access, user management, configuration" }
                    ListElement { roleName: "Security Admin"; userCount: 3; permissions: "Security config, scan management, rule editing, report generation" }
                    ListElement { roleName: "SOC Analyst"; userCount: 12; permissions: "View alerts, investigate incidents, run scans, view reports" }
                    ListElement { roleName: "Incident Responder"; userCount: 5; permissions: "Full incident access, containment actions, forensic tools" }
                    ListElement { roleName: "Network Admin"; userCount: 4; permissions: "Firewall rules, network monitoring, DNS configuration" }
                    ListElement { roleName: "Viewer"; userCount: 8; permissions: "Read-only access to dashboards and reports" }
                    ListElement { roleName: "Service Account"; userCount: 6; permissions: "API access, automated scan execution, data collection" }
                }
                Rectangle {
                    Layout.fillWidth: true; height: 72; radius: ThemeManager.radiusMedium; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                    RowLayout {
                        anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingMedium
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 2
                            Text { text: model.roleName; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.permissions; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; elide: Text.ElideRight; Layout.fillWidth: true }
                        }
                        Rectangle {
                            width: usrCntLabel.implicitWidth + 16; height: 24; radius: 12; color: ThemeManager.hoverColor
                            Text { id: usrCntLabel; anchors.centerIn: parent; text: model.userCount + " users"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        }
                        Text { text: "Edit"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                    }
                }
            }
        }
    }

    // Access Control tab
    Component {
        id: accessTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Access Control Policies"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            // IP Whitelist
            Rectangle {
                Layout.fillWidth: true; height: 140; radius: ThemeManager.radiusLarge; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge; spacing: ThemeManager.spacingSmall
                    RowLayout { Layout.fillWidth: true; Text { text: "IP Whitelist"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }; Item { Layout.fillWidth: true }; Text { text: "+ Add IP"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } } }
                    Repeater {
                        model: ["10.0.0.0/8 (Internal Network)", "192.168.1.0/24 (VPN Pool)", "203.0.113.10 (Admin Home)"]
                        RowLayout { spacing: ThemeManager.spacingSmall; Text { text: "\u2022"; color: ThemeManager.successColor }; Text { text: modelData; font.pixelSize: ThemeManager.fontSizeSmall; font.family: ThemeManager.fontFamilyMono; color: ThemeManager.textSecondary } }
                    }
                }
            }

            // Session and Password policies
            Rectangle {
                Layout.fillWidth: true; height: 160; radius: ThemeManager.radiusLarge; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge; spacing: ThemeManager.spacingSmall
                    Text { text: "Session & Password Policy"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    GridLayout {
                        columns: 2; rowSpacing: ThemeManager.spacingSmall; columnSpacing: ThemeManager.spacingXXL; Layout.fillWidth: true
                        Text { text: "Session Timeout:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "30 minutes"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Max Sessions:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "3 concurrent"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Password Min Length:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "14 characters"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Password Rotation:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "90 days"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Account Lockout:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "5 failed attempts (15 min lockout)"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    }
                }
            }
        }
    }

    // Audit Log tab
    Component {
        id: auditTab
        DataTable {
            title: "Audit Log"
            columns: [
                { key: "timestamp", label: "Timestamp", width: 160 },
                { key: "user", label: "User", width: 110 },
                { key: "action", label: "Action", width: 180 },
                { key: "resource", label: "Resource", width: 160 },
                { key: "ip", label: "IP Address", width: 130 },
                { key: "result", label: "Result", width: 80 }
            ]
            rows: [
                { timestamp: "2024-12-15 14:32:01", user: "jsmith", action: "Incident Updated", resource: "INC-001", ip: "10.0.1.12", result: "Success" },
                { timestamp: "2024-12-15 14:30:45", user: "achen", action: "Scan Started", resource: "Full Scan #847", ip: "10.0.1.45", result: "Success" },
                { timestamp: "2024-12-15 14:28:12", user: "system", action: "Alert Generated", resource: "ALT-4521", ip: "127.0.0.1", result: "Success" },
                { timestamp: "2024-12-15 14:25:00", user: "admin", action: "Rule Modified", resource: "FW-Rule-23", ip: "10.0.0.5", result: "Success" },
                { timestamp: "2024-12-15 14:20:33", user: "rjones", action: "Login Attempt", resource: "Web Console", ip: "203.0.113.10", result: "Failed" },
                { timestamp: "2024-12-15 14:18:00", user: "rjones", action: "Login Attempt", resource: "Web Console", ip: "203.0.113.10", result: "Failed" },
                { timestamp: "2024-12-15 14:15:22", user: "kpatel", action: "Report Generated", resource: "Incident Report", ip: "10.0.1.88", result: "Success" },
                { timestamp: "2024-12-15 14:10:00", user: "svc-scanner", action: "Signature Updated", resource: "DB v2024.12.15", ip: "127.0.0.1", result: "Success" },
                { timestamp: "2024-12-15 14:00:00", user: "admin", action: "User Created", resource: "twilson", ip: "10.0.0.5", result: "Success" },
                { timestamp: "2024-12-15 13:55:00", user: "mgarcia", action: "Asset Registered", resource: "IOT-CAM-05", ip: "10.0.1.100", result: "Success" }
            ]
        }
    }
}
