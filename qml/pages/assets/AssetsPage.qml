import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: assetsPage
    objectName: "assets"
    color: ThemeManager.backgroundColor

    property var assetViewModel: QtObject {
        property int totalDevices: 342
        property int onlineDevices: 318
        property int offlineDevices: 24
        property int highRiskDevices: 13
        property real averageHealthScore: 87.5
    }

    property bool showDetail: false
    property int currentDetailTab: 0

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
                    Text { text: "Asset Inventory"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Monitor and manage all endpoints and devices"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: addAssetLabel.implicitWidth + ThemeManager.spacingXL; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor
                    Text { id: addAssetLabel; anchors.centerIn: parent; text: "+ Register Asset"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                }
            }

            // Stats
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Devices"; value: assetViewModel.totalDevices.toString(); icon: "\u2318"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Online"; value: assetViewModel.onlineDevices.toString(); icon: "\u2022"; iconColor: ThemeManager.successColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Offline"; value: assetViewModel.offlineDevices.toString(); icon: "\u2022"; iconColor: ThemeManager.textMuted }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "High Risk"; value: assetViewModel.highRiskDevices.toString(); trend: 18.0; icon: "\u26A0"; iconColor: ThemeManager.errorColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Avg Health"; value: assetViewModel.averageHealthScore.toFixed(0) + "%"; trend: -2.1; icon: "\u2665"; iconColor: ThemeManager.successColor }
            }

            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 500
                sourceComponent: assetsPage.showDetail ? assetDetailView : assetListView
            }
        }
    }

    Component {
        id: assetListView
        DataTable {
            title: "Devices & Endpoints"
            columns: [
                { key: "hostname", label: "Hostname", width: 160 },
                { key: "ip", label: "IP Address", width: 130 },
                { key: "os", label: "OS", width: 140 },
                { key: "status", label: "Status", width: 80 },
                { key: "lastSeen", label: "Last Seen", width: 130 },
                { key: "riskScore", label: "Risk", width: 70 },
                { key: "agentVersion", label: "Agent", width: 90 }
            ]
            rows: [
                { hostname: "FIN-WS-003", ip: "10.0.1.45", os: "Windows 11 Pro", status: "Online", lastSeen: "Just now", riskScore: "Critical", agentVersion: "v4.2.1" },
                { hostname: "DEV-SRV-001", ip: "10.0.2.10", os: "Ubuntu 22.04 LTS", status: "Online", lastSeen: "Just now", riskScore: "Low", agentVersion: "v4.2.1" },
                { hostname: "ADMIN-PC", ip: "10.0.1.12", os: "Windows 11 Ent", status: "Online", lastSeen: "2m ago", riskScore: "High", agentVersion: "v4.2.0" },
                { hostname: "DB-PROD-01", ip: "10.0.3.5", os: "RHEL 9.2", status: "Online", lastSeen: "Just now", riskScore: "Medium", agentVersion: "v4.2.1" },
                { hostname: "WEB-FRONT-01", ip: "10.0.4.20", os: "Debian 12", status: "Online", lastSeen: "1m ago", riskScore: "Low", agentVersion: "v4.2.1" },
                { hostname: "MAIL-SRV", ip: "10.0.2.50", os: "Windows Server 2022", status: "Online", lastSeen: "Just now", riskScore: "Medium", agentVersion: "v4.1.9" },
                { hostname: "HR-WS-012", ip: "10.0.1.88", os: "macOS 14.2", status: "Online", lastSeen: "5m ago", riskScore: "Low", agentVersion: "v4.2.1" },
                { hostname: "IOT-CAM-04", ip: "10.0.5.104", os: "Linux (embedded)", status: "Offline", lastSeen: "2h ago", riskScore: "High", agentVersion: "v3.9.0" },
                { hostname: "BUILD-SRV-02", ip: "10.0.2.30", os: "Ubuntu 24.04 LTS", status: "Online", lastSeen: "Just now", riskScore: "Low", agentVersion: "v4.2.1" },
                { hostname: "VPN-GW-01", ip: "10.0.0.1", os: "pfSense 2.7", status: "Online", lastSeen: "Just now", riskScore: "Low", agentVersion: "v4.2.1" }
            ]
            onRowClicked: function(idx) { assetsPage.showDetail = true }
        }
    }

    Component {
        id: assetDetailView
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            RowLayout {
                Layout.fillWidth: true
                Rectangle {
                    width: assetBackLabel.implicitWidth + 16; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                    Text { id: assetBackLabel; anchors.centerIn: parent; text: "\u2190 Back to Assets"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: assetsPage.showDetail = false }
                }
                Item { Layout.fillWidth: true }
                Text { text: "FIN-WS-003"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            }

            // Tab bar for detail view
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Overview", "Software", "Vulnerabilities", "Events"]
                    Rectangle {
                        Layout.preferredHeight: 32; Layout.preferredWidth: adtLabel.implicitWidth + ThemeManager.spacingXL; radius: ThemeManager.radiusMedium
                        color: assetsPage.currentDetailTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: assetsPage.currentDetailTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                        Text { id: adtLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: assetsPage.currentDetailTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: assetsPage.currentDetailTab = index }
                    }
                }
            }

            // Detail content
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 400
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor; border.width: 1

                Loader {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    sourceComponent: assetsPage.currentDetailTab === 0 ? overviewSection :
                                     assetsPage.currentDetailTab === 1 ? softwareSection :
                                     assetsPage.currentDetailTab === 2 ? vulnSection : eventsSection
                }
            }
        }
    }

    Component {
        id: overviewSection
        GridLayout {
            columns: 2
            rowSpacing: ThemeManager.spacingMedium
            columnSpacing: ThemeManager.spacingXXL

            Text { text: "Hostname:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "FIN-WS-003"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "IP Address:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "10.0.1.45"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
            Text { text: "Operating System:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "Windows 11 Pro 23H2 (Build 22631.2715)"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "Agent Version:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "v4.2.1 (latest)"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.successColor; font.family: ThemeManager.fontFamily }
            Text { text: "Last Boot:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "2024-12-14 08:30:00"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "User:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "CORP\\jdoe (Finance)"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "CPU:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "Intel Core i7-13700K (16 cores)"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "RAM:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "32 GB DDR5"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "Risk Score:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "Critical (92/100)"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Bold; color: ThemeManager.errorColor; font.family: ThemeManager.fontFamily }
            Text { text: "Health Status:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            Text { text: "Compromised - Requires immediate attention"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.errorColor; font.family: ThemeManager.fontFamily }
        }
    }

    Component {
        id: softwareSection
        ListView {
            clip: true
            spacing: 1
            model: ListModel {
                ListElement { pkg: "Microsoft Office 365"; version: "16.0.17126"; publisher: "Microsoft"; installed: "2024-10-15" }
                ListElement { pkg: "Chrome"; version: "120.0.6099.130"; publisher: "Google"; installed: "2024-12-10" }
                ListElement { pkg: "Visual Studio Code"; version: "1.85.1"; publisher: "Microsoft"; installed: "2024-12-01" }
                ListElement { pkg: "Adobe Acrobat Reader"; version: "23.008.20533"; publisher: "Adobe"; installed: "2024-11-20" }
                ListElement { pkg: "7-Zip"; version: "23.01"; publisher: "Igor Pavlov"; installed: "2024-09-15" }
                ListElement { pkg: "Python 3.12"; version: "3.12.1"; publisher: "PSF"; installed: "2024-11-10" }
                ListElement { pkg: "Git for Windows"; version: "2.43.0"; publisher: "Git"; installed: "2024-12-05" }
                ListElement { pkg: "ThreatOne Agent"; version: "4.2.1"; publisher: "ThreatOne Inc."; installed: "2024-12-12" }
            }
            delegate: Rectangle {
                width: ListView.view.width; height: 36; color: index % 2 === 0 ? "transparent" : ThemeManager.cardColor; radius: ThemeManager.radiusXS
                RowLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingSmall
                    Text { text: model.pkg; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                    Text { text: model.version; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamilyMono; Layout.preferredWidth: 140 }
                    Text { text: model.publisher; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily; Layout.preferredWidth: 120 }
                    Text { text: model.installed; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily; Layout.preferredWidth: 100 }
                }
            }
        }
    }

    Component {
        id: vulnSection
        ListView {
            clip: true
            spacing: ThemeManager.spacingSmall
            model: ListModel {
                ListElement { cve: "CVE-2024-49138"; severity: "Critical"; cvss: "7.8"; product: "Windows CLFS Driver"; status: "Unpatched" }
                ListElement { cve: "CVE-2024-49112"; severity: "Critical"; cvss: "9.8"; product: "Windows LDAP"; status: "Unpatched" }
                ListElement { cve: "CVE-2024-49093"; severity: "High"; cvss: "8.8"; product: "Windows Resilient FS"; status: "Patch Available" }
                ListElement { cve: "CVE-2024-43451"; severity: "Medium"; cvss: "6.5"; product: "NTLM Hash Disclosure"; status: "Patched" }
            }
            delegate: Rectangle {
                width: ListView.view.width; height: 52; radius: ThemeManager.radiusSmall; color: ThemeManager.cardColor
                border.color: model.severity === "Critical" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.3) : ThemeManager.borderColor; border.width: 1
                RowLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingMedium
                    ColumnLayout {
                        spacing: 2
                        Text { text: model.cve; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                        Text { text: model.product; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                    }
                    Item { Layout.fillWidth: true }
                    Text { text: "CVSS " + model.cvss; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    Rectangle { width: sevLabelA.implicitWidth + 10; height: 20; radius: ThemeManager.radiusSmall; color: model.severity === "Critical" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15) : Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15); Text { id: sevLabelA; anchors.centerIn: parent; text: model.severity; font.pixelSize: ThemeManager.fontSizeXS; color: model.severity === "Critical" ? ThemeManager.errorColor : ThemeManager.warningColor; font.family: ThemeManager.fontFamily } }
                    Text { text: model.status; font.pixelSize: ThemeManager.fontSizeSmall; color: model.status === "Patched" ? ThemeManager.successColor : ThemeManager.errorColor; font.family: ThemeManager.fontFamily }
                }
            }
        }
    }

    Component {
        id: eventsSection
        TimelineView {
            title: "Recent Security Events"
            events: [
                { time: "14:32", title: "Ransomware payload executed", description: "LockBit 3.0 variant detected and active", severity: "critical" },
                { time: "14:30", title: "Suspicious file created", description: "/temp/payload.bin - known malware hash", severity: "critical" },
                { time: "14:18", title: "Macro execution", description: "Office macro triggered from invoice_Q4.docm", severity: "high" },
                { time: "14:15", title: "Email attachment opened", description: "User opened invoice_Q4.docm from external sender", severity: "medium" },
                { time: "09:00", title: "User logged in", description: "jdoe authenticated via Windows Hello", severity: "info" }
            ]
        }
    }
}
