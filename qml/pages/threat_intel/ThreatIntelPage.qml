import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: threatIntelPage
    objectName: "threat_intel"
    color: ThemeManager.backgroundColor

    property var threatIntelViewModel: QtObject {
        property int totalIOCs: 245892
        property int activeFeeds: 12
        property int mitreTechniques: 201
        property int cveTracked: 3456
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
                    Text { text: "Threat Intelligence"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "IOC management, threat feeds, MITRE ATT&CK mapping, and CVE tracking"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
            }

            // Stats
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total IOCs"; value: threatIntelViewModel.totalIOCs.toLocaleString(); trend: 4.5; icon: "\uD83D\uDD0D"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Active Feeds"; value: threatIntelViewModel.activeFeeds.toString(); icon: "\u21BB"; iconColor: ThemeManager.successColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "MITRE Techniques"; value: threatIntelViewModel.mitreTechniques.toString(); icon: "\u2616"; iconColor: ThemeManager.secondaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "CVEs Tracked"; value: threatIntelViewModel.cveTracked.toLocaleString(); trend: 2.1; icon: "\u26A0"; iconColor: ThemeManager.warningColor }
            }

            // Tab bar
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["IOC Search", "Threat Feeds", "MITRE ATT&CK", "CVE Browser", "Correlations"]
                    Rectangle {
                        Layout.preferredHeight: 36; Layout.preferredWidth: tiTabLabel.implicitWidth + ThemeManager.spacingXL; radius: ThemeManager.radiusMedium
                        color: threatIntelPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: threatIntelPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                        Text { id: tiTabLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: threatIntelPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: threatIntelPage.currentTab = index }
                    }
                }
            }

            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: threatIntelPage.currentTab === 0 ? iocTab :
                                 threatIntelPage.currentTab === 1 ? feedsTab :
                                 threatIntelPage.currentTab === 2 ? mitreTab :
                                 threatIntelPage.currentTab === 3 ? cveTab : correlationsTab
            }
        }
    }

    // IOC Search tab
    Component {
        id: iocTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            // Search bar with type selector
            Rectangle {
                Layout.fillWidth: true; height: 50; radius: ThemeManager.radiusMedium; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                RowLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingSmall
                    Rectangle {
                        width: iocTypeLabel.implicitWidth + 20; height: 30; radius: ThemeManager.radiusSmall; color: ThemeManager.hoverColor
                        Text { id: iocTypeLabel; anchors.centerIn: parent; text: "IP Address \u25BE"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                    }
                    Rectangle { width: 1; height: 24; color: ThemeManager.borderColor }
                    TextInput { Layout.fillWidth: true; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary; clip: true
                        Text { anchors.fill: parent; text: "Search IOCs (IP, domain, hash, URL)..."; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textMuted; visible: !parent.text && !parent.activeFocus; verticalAlignment: Text.AlignVCenter }
                    }
                    Rectangle { width: 70; height: 30; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor; Text { anchors.centerIn: parent; text: "Search"; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily } ; MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                }
            }

            DataTable {
                Layout.fillWidth: true
                Layout.preferredHeight: 380
                title: "IOC Results"
                columns: [
                    { key: "type", label: "Type", width: 80 },
                    { key: "indicator", label: "Indicator", width: 240 },
                    { key: "threat", label: "Associated Threat", width: 180 },
                    { key: "confidence", label: "Confidence", width: 90 },
                    { key: "firstSeen", label: "First Seen", width: 110 },
                    { key: "lastSeen", label: "Last Seen", width: 110 },
                    { key: "source", label: "Source", width: 100 }
                ]
                rows: [
                    { type: "IP", indicator: "203.0.113.42", threat: "APT29 C2 Infrastructure", confidence: "95%", firstSeen: "2024-11-01", lastSeen: "2024-12-15", source: "OSINT" },
                    { type: "Domain", indicator: "evil-update.com", threat: "SolarWinds variant", confidence: "88%", firstSeen: "2024-10-15", lastSeen: "2024-12-14", source: "Partner" },
                    { type: "Hash", indicator: "a1b2c3d4e5f6...789012345678", threat: "LockBit 3.0", confidence: "99%", firstSeen: "2024-12-10", lastSeen: "2024-12-15", source: "Internal" },
                    { type: "URL", indicator: "http://cdn.malware.cc/payload", threat: "Emotet Dropper", confidence: "92%", firstSeen: "2024-11-20", lastSeen: "2024-12-13", source: "VirusTotal" },
                    { type: "IP", indicator: "198.51.100.17", threat: "Cobalt Strike Beacon", confidence: "85%", firstSeen: "2024-12-01", lastSeen: "2024-12-15", source: "ThreatFox" },
                    { type: "Domain", indicator: "xk9f2m.malware.cc", threat: "DGA - Mirai variant", confidence: "78%", firstSeen: "2024-12-14", lastSeen: "2024-12-15", source: "DNS Intel" }
                ]
            }
        }
    }

    // Threat Feeds tab
    Component {
        id: feedsTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "Threat Feed Sources"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            ListView {
                Layout.fillWidth: true
                Layout.preferredHeight: 420
                clip: true
                spacing: ThemeManager.spacingSmall
                model: ListModel {
                    ListElement { feedName: "AlienVault OTX"; feedStatus: "Active"; lastUpdated: "2 min ago"; iocCount: "45,892"; feedType: "OSINT" }
                    ListElement { feedName: "Abuse.ch URLhaus"; feedStatus: "Active"; lastUpdated: "5 min ago"; iocCount: "12,456"; feedType: "URL" }
                    ListElement { feedName: "ThreatFox"; feedStatus: "Active"; lastUpdated: "10 min ago"; iocCount: "8,901"; feedType: "Mixed" }
                    ListElement { feedName: "MISP Community"; feedStatus: "Active"; lastUpdated: "15 min ago"; iocCount: "89,234"; feedType: "MISP" }
                    ListElement { feedName: "VirusTotal LiveHunt"; feedStatus: "Active"; lastUpdated: "1 min ago"; iocCount: "3,456"; feedType: "Hash" }
                    ListElement { feedName: "Shodan Monitor"; feedStatus: "Active"; lastUpdated: "30 min ago"; iocCount: "1,200"; feedType: "IP" }
                    ListElement { feedName: "CrowdStrike Falcon"; feedStatus: "Active"; lastUpdated: "8 min ago"; iocCount: "67,890"; feedType: "Premium" }
                    ListElement { feedName: "Mandiant Advantage"; feedStatus: "Error"; lastUpdated: "2h ago"; iocCount: "0"; feedType: "Premium" }
                    ListElement { feedName: "Custom YARA Feed"; feedStatus: "Active"; lastUpdated: "1h ago"; iocCount: "234"; feedType: "Internal" }
                    ListElement { feedName: "DNS Blocklist"; feedStatus: "Stale"; lastUpdated: "12h ago"; iocCount: "15,678"; feedType: "Domain" }
                }
                delegate: Rectangle {
                    width: ListView.view.width; height: 56; radius: ThemeManager.radiusMedium; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                    RowLayout {
                        anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingMedium
                        Rectangle { width: 8; height: 8; radius: 4; color: model.feedStatus === "Active" ? ThemeManager.successColor : model.feedStatus === "Error" ? ThemeManager.errorColor : ThemeManager.warningColor }
                        ColumnLayout {
                            spacing: 2; Layout.fillWidth: true
                            Text { text: model.feedName; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.feedType + " feed"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }
                        Text { text: model.iocCount + " IOCs"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: model.lastUpdated; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Rectangle {
                            width: feedStatusLabel.implicitWidth + 12; height: 22; radius: ThemeManager.radiusSmall
                            color: model.feedStatus === "Active" ? Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.15) : model.feedStatus === "Error" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15) : Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15)
                            Text { id: feedStatusLabel; anchors.centerIn: parent; text: model.feedStatus; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Medium; color: model.feedStatus === "Active" ? ThemeManager.successColor : model.feedStatus === "Error" ? ThemeManager.errorColor : ThemeManager.warningColor; font.family: ThemeManager.fontFamily }
                        }
                    }
                }
            }
        }
    }

    // MITRE ATT&CK tab
    Component {
        id: mitreTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "MITRE ATT&CK Navigator"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "Detection coverage mapped to ATT&CK framework tactics and techniques"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }

            // Tactics header row
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 400
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor; border.width: 1

                GridLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingMedium
                    columns: 7
                    rowSpacing: 4
                    columnSpacing: 4

                    // Row 1: Tactic headers
                    Repeater {
                        model: ["Initial Access", "Execution", "Persistence", "Priv Escalation", "Defense Evasion", "Credential Access", "Lateral Movement"]
                        Rectangle {
                            Layout.fillWidth: true; height: 32; radius: ThemeManager.radiusSmall; color: ThemeManager.hoverColor
                            Text { anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; elide: Text.ElideRight; width: parent.width - 8; horizontalAlignment: Text.AlignHCenter }
                        }
                    }

                    // Technique cells (5 rows x 7 columns)
                    Repeater {
                        model: [
                            "T1566 Phishing", "T1059 CmdLine", "T1547 Boot/Logon", "T1548 Abuse Elev", "T1070 Indicator Rm", "T1003 OS Creds", "T1021 Remote Svc",
                            "T1190 Exploit App", "T1204 User Exec", "T1053 Sched Task", "T1055 Process Inj", "T1036 Masquerade", "T1110 Brute Force", "T1570 Lateral Tool",
                            "T1133 External Svc", "T1047 WMI", "T1543 System Svc", "T1068 Exploit Priv", "T1027 Obfuscation", "T1558 Kerberoast", "T1563 RDP Hijack",
                            "T1195 Supply Chain", "T1569 Sys Services", "T1136 Create Acct", "T1134 Token Manip", "T1562 Impair Def", "T1552 Unsecured Cr", "T1080 Taint Share",
                            "T1078 Valid Accts", "T1106 Native API", "T1546 Event Trigger", "T1574 Hijack Flow", "T1553 Subvert Trust", "T1557 MITM", "T1550 Alt Auth"
                        ]
                        Rectangle {
                            Layout.fillWidth: true; height: 60; radius: ThemeManager.radiusSmall
                            property int coverage: Math.floor(Math.random() * 3)
                            color: coverage === 2 ? Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.2) :
                                   coverage === 1 ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.2) :
                                   Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.1)
                            border.color: coverage === 2 ? ThemeManager.successColor : coverage === 1 ? ThemeManager.warningColor : ThemeManager.borderColor
                            border.width: 1
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 4; spacing: 2
                                Text { Layout.fillWidth: true; text: modelData.substring(0, 5); font.pixelSize: 8; font.family: ThemeManager.fontFamilyMono; color: ThemeManager.textMuted; horizontalAlignment: Text.AlignHCenter }
                                Text { Layout.fillWidth: true; text: modelData.substring(6); font.pixelSize: 9; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap; maximumLineCount: 2 }
                            }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; hoverEnabled: true; onEntered: parent.opacity = 0.8; onExited: parent.opacity = 1.0 }
                        }
                    }
                }
            }
        }
    }

    // CVE Browser tab
    Component {
        id: cveTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            // CVE search
            Rectangle {
                Layout.fillWidth: true; height: 44; radius: ThemeManager.radiusMedium; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                RowLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingSmall; spacing: ThemeManager.spacingSmall
                    Text { text: "\uD83D\uDD0D"; font.pixelSize: 14; color: ThemeManager.textMuted }
                    TextInput { Layout.fillWidth: true; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary; clip: true
                        Text { anchors.fill: parent; text: "Search CVEs by ID, product, or keyword..."; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textMuted; visible: !parent.text && !parent.activeFocus; verticalAlignment: Text.AlignVCenter }
                    }
                }
            }

            DataTable {
                Layout.fillWidth: true
                Layout.preferredHeight: 380
                title: "CVE Database"
                columns: [
                    { key: "cveId", label: "CVE ID", width: 150 },
                    { key: "severity", label: "Severity", width: 80 },
                    { key: "cvss", label: "CVSS", width: 60 },
                    { key: "product", label: "Affected Product", width: 180 },
                    { key: "description", label: "Description", width: 280 },
                    { key: "published", label: "Published", width: 100 }
                ]
                rows: [
                    { cveId: "CVE-2024-49138", severity: "Critical", cvss: "7.8", product: "Windows CLFS", description: "Heap-based buffer overflow in CLFS driver", published: "2024-12-10" },
                    { cveId: "CVE-2024-49112", severity: "Critical", cvss: "9.8", product: "Windows LDAP", description: "Remote code execution via LDAP request", published: "2024-12-10" },
                    { cveId: "CVE-2024-44308", severity: "Critical", cvss: "8.8", product: "Apple WebKit", description: "Type confusion in JavaScriptCore", published: "2024-11-19" },
                    { cveId: "CVE-2024-43451", severity: "High", cvss: "6.5", product: "Windows NTLM", description: "NTLM hash disclosure via crafted file", published: "2024-11-12" },
                    { cveId: "CVE-2024-38813", severity: "High", cvss: "7.5", product: "VMware vCenter", description: "Privilege escalation in vCenter Server", published: "2024-10-21" },
                    { cveId: "CVE-2024-9680", severity: "Critical", cvss: "9.8", product: "Firefox", description: "Use-after-free in Animation timeline", published: "2024-10-09" }
                ]
            }
        }
    }

    // Correlations tab
    Component {
        id: correlationsTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "Threat Correlation Graph"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "Visual relationship mapping between IOCs, threat actors, and campaigns"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 300
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor; border.width: 1

                ColumnLayout {
                    anchors.centerIn: parent
                    spacing: ThemeManager.spacingMedium
                    Text { Layout.alignment: Qt.AlignHCenter; text: "\u2B21"; font.pixelSize: 64; color: ThemeManager.textMuted }
                    Text { Layout.alignment: Qt.AlignHCenter; text: "Graph Visualization"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                    Text { Layout.alignment: Qt.AlignHCenter; text: "Interactive node-link diagram showing IOC relationships,\nthreat actor attribution, and campaign connections"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily; horizontalAlignment: Text.AlignHCenter }
                }
            }

            // Related threats summary
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                Repeater {
                    model: ListModel {
                        ListElement { actor: "APT29 (Cozy Bear)"; campaigns: "3 active"; iocs: "1,234"; confidence: "High" }
                        ListElement { actor: "FIN7"; campaigns: "1 active"; iocs: "567"; confidence: "Medium" }
                        ListElement { actor: "LockBit Gang"; campaigns: "2 active"; iocs: "890"; confidence: "High" }
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: 80; radius: ThemeManager.radiusMedium; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingXS
                            Text { text: model.actor; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.campaigns + " | " + model.iocs + " IOCs"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Text { text: "Confidence: " + model.confidence; font.pixelSize: ThemeManager.fontSizeXS; color: model.confidence === "High" ? ThemeManager.successColor : ThemeManager.warningColor; font.family: ThemeManager.fontFamily }
                        }
                    }
                }
            }
        }
    }
}
