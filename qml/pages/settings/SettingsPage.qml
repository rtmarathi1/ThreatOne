import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: settingsPage
    objectName: "settings"
    color: ThemeManager.backgroundColor

    property var settingsViewModel: QtObject {
        property string language: "English"
        property bool autoStart: true
        property int lockTimeout: 5
        property string defaultScanType: "Quick Scan"
        property bool autoUpdate: true
        property string updateChannel: "Stable"
        property string licenseKey: "XXXX-XXXX-XXXX-XXXX"
        property string licenseExpiry: "2025-12-31"
        property string appVersion: "4.2.1"
        property string buildNumber: "20241215-001"
    }

    property int selectedCategory: 0

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Left category list
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 240
            color: ThemeManager.surfaceColor
            border.color: ThemeManager.borderColor
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: ThemeManager.spacingMedium
                spacing: ThemeManager.spacingXS

                Text {
                    text: "Settings"
                    font.pixelSize: ThemeManager.fontSizeLarge
                    font.weight: Font.Bold
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textPrimary
                    Layout.bottomMargin: ThemeManager.spacingMedium
                }

                Repeater {
                    model: ListModel {
                        ListElement { catName: "General"; catIcon: "\u2699"; catColor: "#3b82f6" }
                        ListElement { catName: "Scan Settings"; catIcon: "\u2616"; catColor: "#ef4444" }
                        ListElement { catName: "Firewall"; catIcon: "\u2194"; catColor: "#8b5cf6" }
                        ListElement { catName: "Notifications"; catIcon: "\u2022"; catColor: "#06b6d4" }
                        ListElement { catName: "Updates"; catIcon: "\u21BB"; catColor: "#10b981" }
                        ListElement { catName: "License"; catIcon: "\u2605"; catColor: "#f59e0b" }
                        ListElement { catName: "About"; catIcon: "\u2139"; catColor: "#8892b0" }
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        height: 44
                        radius: ThemeManager.radiusMedium
                        color: settingsPage.selectedCategory === index ? ThemeManager.hoverColor : "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: ThemeManager.spacingSmall
                            spacing: ThemeManager.spacingSmall

                            Rectangle {
                                width: 28; height: 28; radius: ThemeManager.radiusSmall
                                color: model.catColor
                                opacity: 0.15
                                Text { anchors.centerIn: parent; text: model.catIcon; font.pixelSize: 14; color: model.catColor }
                            }
                            Text {
                                text: model.catName
                                font.pixelSize: ThemeManager.fontSizeBody
                                font.weight: settingsPage.selectedCategory === index ? Font.DemiBold : Font.Normal
                                font.family: ThemeManager.fontFamily
                                color: settingsPage.selectedCategory === index ? ThemeManager.textPrimary : ThemeManager.textSecondary
                                Layout.fillWidth: true
                            }
                        }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsPage.selectedCategory = index }
                    }
                }
                Item { Layout.fillHeight: true }
            }
        }

        // Right content area
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth

            Loader {
                width: parent.width
                sourceComponent: settingsPage.selectedCategory === 0 ? generalSettings :
                                 settingsPage.selectedCategory === 1 ? scanSettings :
                                 settingsPage.selectedCategory === 2 ? firewallSettings :
                                 settingsPage.selectedCategory === 3 ? notificationSettings :
                                 settingsPage.selectedCategory === 4 ? updateSettings :
                                 settingsPage.selectedCategory === 5 ? licenseSettings : aboutSettings
            }
        }
    }

    // General Settings
    Component {
        id: generalSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            anchors.margins: ThemeManager.spacingXL

            Text { text: "General Settings"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }

            Repeater {
                model: ListModel {
                    ListElement { settingName: "Language"; settingType: "dropdown"; settingValue: "English"; settingDesc: "Application display language" }
                    ListElement { settingName: "Start on Boot"; settingType: "toggle"; settingValue: "true"; settingDesc: "Launch ThreatOne when system starts" }
                    ListElement { settingName: "Auto-Lock Timeout"; settingType: "slider"; settingValue: "5 minutes"; settingDesc: "Lock application after inactivity" }
                    ListElement { settingName: "Dark Mode"; settingType: "toggle"; settingValue: "true"; settingDesc: "Enable dark theme" }
                    ListElement { settingName: "Minimize to Tray"; settingType: "toggle"; settingValue: "true"; settingDesc: "Minimize to system tray instead of closing" }
                    ListElement { settingName: "Data Directory"; settingType: "path"; settingValue: "/var/lib/threatone"; settingDesc: "Location for scan data and quarantine" }
                }
                Rectangle {
                    Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL
                    height: 56; radius: ThemeManager.radiusSmall; color: "transparent"
                    RowLayout {
                        anchors.fill: parent; spacing: ThemeManager.spacingNormal
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 2
                            Text { text: model.settingName; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.settingDesc; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }
                        // Control
                        Loader {
                            sourceComponent: model.settingType === "toggle" ? toggleControl :
                                             model.settingType === "dropdown" ? dropdownControl : valueControl
                        }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: ThemeManager.dividerColor }
                }
            }
        }
    }

    Component { id: toggleControl; Rectangle { width: 42; height: 22; radius: 11; color: ThemeManager.successColor; Rectangle { x: 22; y: 2; width: 18; height: 18; radius: 9; color: "#ffffff" } ; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } } }
    Component { id: dropdownControl; Rectangle { width: 120; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: "English \u25BE"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } ; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } } }
    Component { id: valueControl; Rectangle { width: 160; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.left: parent.left; anchors.leftMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: "5 minutes"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } } }

    // Scan Settings
    Component {
        id: scanSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Scan Settings"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Repeater {
                model: ListModel {
                    ListElement { settingName: "Default Scan Type"; settingValue: "Quick Scan" }
                    ListElement { settingName: "Scan Archives (ZIP/RAR)"; settingValue: "Enabled" }
                    ListElement { settingName: "Maximum Archive Depth"; settingValue: "5 levels" }
                    ListElement { settingName: "Scan Network Drives"; settingValue: "Disabled" }
                    ListElement { settingName: "Heuristic Level"; settingValue: "Medium" }
                    ListElement { settingName: "PUP Detection"; settingValue: "Enabled" }
                    ListElement { settingName: "Scheduled Scan"; settingValue: "Daily at 02:00" }
                    ListElement { settingName: "CPU Priority"; settingValue: "Normal" }
                }
                Rectangle {
                    Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 48; color: "transparent"
                    RowLayout {
                        anchors.fill: parent
                        Text { text: model.settingName; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                        Rectangle { width: 140; height: 30; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: model.settingValue; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: ThemeManager.dividerColor }
                }
            }
            // Exclusions
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; Layout.preferredHeight: 120; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingSmall
                    RowLayout { Layout.fillWidth: true; Text { text: "Scan Exclusions"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }; Item { Layout.fillWidth: true }; Text { text: "+ Add"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } } }
                    Text { text: "/var/lib/docker/**\n/tmp/build-*\n*.iso"; font.pixelSize: ThemeManager.fontSizeSmall; font.family: ThemeManager.fontFamilyMono; color: ThemeManager.textSecondary; lineHeight: 1.4 }
                }
            }
        }
    }

    // Firewall Settings
    Component {
        id: firewallSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Firewall Settings"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Repeater {
                model: ListModel {
                    ListElement { settingName: "Default Policy"; settingValue: "Block Inbound / Allow Outbound" }
                    ListElement { settingName: "Logging Verbosity"; settingValue: "Medium" }
                    ListElement { settingName: "Connection Timeout"; settingValue: "60 seconds" }
                    ListElement { settingName: "Rate Limiting"; settingValue: "1000 req/min" }
                    ListElement { settingName: "GeoIP Database"; settingValue: "Auto-update weekly" }
                    ListElement { settingName: "DNS Filtering"; settingValue: "Enabled" }
                    ListElement { settingName: "Stealth Mode"; settingValue: "Enabled" }
                }
                Rectangle {
                    Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 48; color: "transparent"
                    RowLayout {
                        anchors.fill: parent
                        Text { text: model.settingName; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                        Rectangle { width: 200; height: 30; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: model.settingValue; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: ThemeManager.dividerColor }
                }
            }
        }
    }

    // Notification Settings
    Component {
        id: notificationSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Notification Settings"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Repeater {
                model: ListModel {
                    ListElement { settingName: "Desktop Notifications"; enabled: true }
                    ListElement { settingName: "Email Alerts"; enabled: true }
                    ListElement { settingName: "SMS Alerts (Critical only)"; enabled: false }
                    ListElement { settingName: "Slack Integration"; enabled: true }
                    ListElement { settingName: "Sound Alerts"; enabled: true }
                }
                Rectangle {
                    Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 48; color: "transparent"
                    RowLayout {
                        anchors.fill: parent
                        Text { text: model.settingName; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                        Rectangle { width: 42; height: 22; radius: 11; color: model.enabled ? ThemeManager.successColor : ThemeManager.borderColor; Rectangle { x: model.enabled ? 22 : 2; y: 2; width: 18; height: 18; radius: 9; color: "#ffffff" } ; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: ThemeManager.dividerColor }
                }
            }
            // Severity threshold
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 60; color: "transparent"
                ColumnLayout {
                    anchors.fill: parent; spacing: ThemeManager.spacingSmall
                    Text { text: "Minimum Severity for Alerts"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    RowLayout {
                        spacing: ThemeManager.spacingSmall
                        Repeater {
                            model: ["Info", "Low", "Medium", "High", "Critical"]
                            Rectangle {
                                width: sevOptLabel.implicitWidth + 16; height: 28; radius: 14
                                color: index === 2 ? ThemeManager.primaryColor : ThemeManager.cardColor
                                border.color: index === 2 ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                                Text { id: sevOptLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeXS; color: index === 2 ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                            }
                        }
                    }
                }
            }
        }
    }

    // Update Settings
    Component {
        id: updateSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Update Settings"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Repeater {
                model: ListModel {
                    ListElement { settingName: "Auto-Update"; settingValue: "Enabled"; isToggle: true }
                    ListElement { settingName: "Update Channel"; settingValue: "Stable"; isToggle: false }
                    ListElement { settingName: "Signature Updates"; settingValue: "Every 4 hours"; isToggle: false }
                    ListElement { settingName: "Engine Updates"; settingValue: "Weekly"; isToggle: false }
                    ListElement { settingName: "Proxy Server"; settingValue: "None"; isToggle: false }
                    ListElement { settingName: "Bandwidth Limit"; settingValue: "Unlimited"; isToggle: false }
                }
                Rectangle {
                    Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 48; color: "transparent"
                    RowLayout {
                        anchors.fill: parent
                        Text { text: model.settingName; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                        Loader { sourceComponent: model.isToggle ? toggleControl : dropdownControl }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: ThemeManager.dividerColor }
                }
            }
            // Last update info
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 80; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                RowLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium
                    ColumnLayout { spacing: 2; Layout.fillWidth: true
                        Text { text: "Last Updated: December 15, 2024 at 14:30"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Signature version: 2024.12.15.002 | Engine: 4.2.1"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                    }
                    Rectangle { width: 120; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor; Text { anchors.centerIn: parent; text: "Check Now"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                }
            }
        }
    }

    // License Settings
    Component {
        id: licenseSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "License Information"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 160; radius: ThemeManager.radiusLarge; color: ThemeManager.surfaceColor; border.color: ThemeManager.successColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge; spacing: ThemeManager.spacingSmall
                    RowLayout { Text { text: "ThreatOne Enterprise"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }; Item { Layout.fillWidth: true }; Rectangle { width: actLabel.implicitWidth + 16; height: 24; radius: 12; color: Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.15); Text { id: actLabel; anchors.centerIn: parent; text: "Active"; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: ThemeManager.successColor; font.family: ThemeManager.fontFamily } } }
                    GridLayout { columns: 2; rowSpacing: ThemeManager.spacingSmall; columnSpacing: ThemeManager.spacingXXL
                        Text { text: "License Key:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: settingsViewModel.licenseKey; font.pixelSize: ThemeManager.fontSizeBody; font.family: ThemeManager.fontFamilyMono; color: ThemeManager.textPrimary }
                        Text { text: "Expires:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: settingsViewModel.licenseExpiry; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Text { text: "Seats:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "342 / 500 used"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    }
                }
            }
            // Features
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 180; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingSmall
                    Text { text: "Licensed Features"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    Repeater {
                        model: ["Real-time Protection", "EDR Module", "Firewall Management", "Threat Intelligence", "AI/ML Engine", "Vulnerability Scanner", "Compliance Reporting", "24/7 Support"]
                        RowLayout { spacing: ThemeManager.spacingSmall; Text { text: "\u2713"; color: ThemeManager.successColor; font.pixelSize: 12 }; Text { text: modelData; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily } }
                    }
                }
            }
        }
    }

    // About
    Component {
        id: aboutSettings
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "About ThreatOne"; font.pixelSize: ThemeManager.fontSizeTitle; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.topMargin: ThemeManager.spacingXL; Layout.leftMargin: ThemeManager.spacingXL }
            Rectangle {
                Layout.fillWidth: true; Layout.leftMargin: ThemeManager.spacingXL; Layout.rightMargin: ThemeManager.spacingXL; height: 200; radius: ThemeManager.radiusLarge; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge; spacing: ThemeManager.spacingMedium
                    Text { text: "ThreatOne Enterprise"; font.pixelSize: ThemeManager.fontSizeXL; font.weight: Font.Bold; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily }
                    Text { text: "Advanced Cybersecurity Platform"; font.pixelSize: ThemeManager.fontSizeNormal; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                    GridLayout { columns: 2; rowSpacing: ThemeManager.spacingSmall; columnSpacing: ThemeManager.spacingXXL
                        Text { text: "Version:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: settingsViewModel.appVersion; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                        Text { text: "Build:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: settingsViewModel.buildNumber; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                        Text { text: "Qt Version:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "6.7.0"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                        Text { text: "Platform:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "Linux x86_64"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    }
                    Text { text: "Copyright 2024 ThreatOne Inc. All rights reserved."; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                }
            }
        }
    }
}
