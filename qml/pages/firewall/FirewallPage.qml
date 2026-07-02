import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: firewallPage
    objectName: "firewall"
    color: ThemeManager.backgroundColor

    property var firewallViewModel: QtObject {
        property int activeConnections: 142
        property int blockedToday: 1847
        property int rulesActive: 23
        property real bandwidth: 45.2
        property int totalRules: 28

        Behavior on activeConnections { NumberAnimation { duration: 600 } }
        Behavior on blockedToday { NumberAnimation { duration: 600 } }
        Behavior on bandwidth { NumberAnimation { duration: 600 } }
    }

    // Real-time data update timer
    Timer {
        interval: 2500
        running: true
        repeat: true
        onTriggered: {
            firewallViewModel.activeConnections = firewallViewModel.activeConnections + Math.floor(Math.random() * 5) - 2
            if (firewallViewModel.activeConnections < 120) firewallViewModel.activeConnections = 120
            if (firewallViewModel.activeConnections > 180) firewallViewModel.activeConnections = 180
            firewallViewModel.blockedToday = firewallViewModel.blockedToday + Math.floor(Math.random() * 3) + 1
            firewallViewModel.bandwidth = firewallViewModel.bandwidth + (Math.random() * 4 - 2)
            if (firewallViewModel.bandwidth < 20) firewallViewModel.bandwidth = 20
            if (firewallViewModel.bandwidth > 80) firewallViewModel.bandwidth = 80
        }
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
                    Text { text: "Firewall Manager"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Network rules, connection monitoring, and traffic analysis"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: addRuleLabel.implicitWidth + ThemeManager.spacingXL
                    height: ThemeManager.buttonHeight
                    radius: ThemeManager.radiusMedium
                    color: ThemeManager.primaryColor
                    Text { id: addRuleLabel; anchors.centerIn: parent; text: "+ Add Rule"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                }
            }

            // Stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Active Connections"; value: firewallViewModel.activeConnections.toString(); icon: "\u2194"; iconColor: ThemeManager.primaryColor; sparklineData: [120,125,135,128,140,138,142] }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Blocked Today"; value: firewallViewModel.blockedToday.toLocaleString(); trend: 8.2; icon: "\u2716"; iconColor: ThemeManager.errorColor; sparklineData: [1500,1600,1700,1650,1780,1820,1847] }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Rules Active"; value: firewallViewModel.rulesActive.toString(); icon: "\u2611"; iconColor: ThemeManager.successColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Bandwidth"; value: firewallViewModel.bandwidth.toFixed(1) + " MB/s"; icon: "\u21C5"; iconColor: ThemeManager.chart6; sparklineData: [38,42,40,44,43,46,45] }
            }

            // Tab bar
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Rules", "Connections", "Blocked IPs", "DNS Filter", "Geo-blocking", "Bandwidth"]
                    Rectangle {
                        Layout.preferredHeight: 36
                        Layout.preferredWidth: ftLabel.implicitWidth + ThemeManager.spacingXL
                        radius: ThemeManager.radiusMedium
                        color: firewallPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: firewallPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor
                        border.width: 1
                        Text { id: ftLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: firewallPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: firewallPage.currentTab = index }
                    }
                }
            }

            // Tab content
            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: firewallPage.currentTab === 0 ? rulesTab :
                                 firewallPage.currentTab === 1 ? connectionsTab :
                                 firewallPage.currentTab === 2 ? blockedTab :
                                 firewallPage.currentTab === 3 ? dnsTab :
                                 firewallPage.currentTab === 4 ? geoTab : bwTab
            }
        }
    }

    Component {
        id: rulesTab
        DataTable {
            title: "Firewall Rules"
            columns: [
                { key: "enabled", label: "Status", width: 70 },
                { key: "name", label: "Rule Name", width: 200 },
                { key: "direction", label: "Direction", width: 100 },
                { key: "protocol", label: "Protocol", width: 80 },
                { key: "source", label: "Source", width: 140 },
                { key: "destination", label: "Destination", width: 140 },
                { key: "action", label: "Action", width: 80 },
                { key: "hits", label: "Hits", width: 80 }
            ]
            rows: [
                { enabled: "Active", name: "Block External SSH", direction: "Inbound", protocol: "TCP", source: "0.0.0.0/0", destination: ":22", action: "Block", hits: "12,847" },
                { enabled: "Active", name: "Allow HTTPS Outbound", direction: "Outbound", protocol: "TCP", source: "Any", destination: ":443", action: "Allow", hits: "892,103" },
                { enabled: "Active", name: "Block Telnet", direction: "Inbound", protocol: "TCP", source: "0.0.0.0/0", destination: ":23", action: "Block", hits: "4,521" },
                { enabled: "Active", name: "Allow DNS", direction: "Outbound", protocol: "UDP", source: "Any", destination: ":53", action: "Allow", hits: "1,204,881" },
                { enabled: "Disabled", name: "Block ICMP Flood", direction: "Inbound", protocol: "ICMP", source: "0.0.0.0/0", destination: "Any", action: "Block", hits: "0" },
                { enabled: "Active", name: "Allow Internal HTTP", direction: "Both", protocol: "TCP", source: "10.0.0.0/8", destination: ":80,:443", action: "Allow", hits: "456,200" },
                { enabled: "Active", name: "Block Known C2", direction: "Outbound", protocol: "TCP", source: "Any", destination: "Threat Feed", action: "Block", hits: "89" },
                { enabled: "Active", name: "Rate Limit API", direction: "Inbound", protocol: "TCP", source: "0.0.0.0/0", destination: ":8080", action: "Limit", hits: "23,456" }
            ]
        }
    }

    Component {
        id: connectionsTab
        DataTable {
            title: "Live Connections"
            columns: [
                { key: "srcIP", label: "Source IP", width: 140 },
                { key: "destIP", label: "Destination IP", width: 140 },
                { key: "port", label: "Port", width: 70 },
                { key: "protocol", label: "Protocol", width: 80 },
                { key: "status", label: "Status", width: 100 },
                { key: "duration", label: "Duration", width: 90 },
                { key: "bytes", label: "Bytes", width: 100 }
            ]
            rows: [
                { srcIP: "10.0.1.45", destIP: "52.85.132.99", port: "443", protocol: "TCP", status: "Established", duration: "00:12:45", bytes: "2.4 MB" },
                { srcIP: "10.0.1.12", destIP: "142.250.80.46", port: "443", protocol: "TCP", status: "Established", duration: "00:05:32", bytes: "890 KB" },
                { srcIP: "10.0.2.88", destIP: "10.0.1.5", port: "445", protocol: "TCP", status: "Established", duration: "01:23:10", bytes: "45 MB" },
                { srcIP: "203.0.113.42", destIP: "10.0.1.1", port: "22", protocol: "TCP", status: "Blocked", duration: "00:00:01", bytes: "0 B" },
                { srcIP: "10.0.1.100", destIP: "8.8.8.8", port: "53", protocol: "UDP", status: "Active", duration: "00:00:02", bytes: "256 B" },
                { srcIP: "10.0.3.15", destIP: "185.199.108.133", port: "443", protocol: "TCP", status: "Established", duration: "00:02:18", bytes: "1.2 MB" },
                { srcIP: "10.0.1.200", destIP: "10.0.2.50", port: "3306", protocol: "TCP", status: "Established", duration: "04:15:00", bytes: "120 MB" },
                { srcIP: "192.168.1.105", destIP: "10.0.1.1", port: "80", protocol: "TCP", status: "SYN_SENT", duration: "00:00:05", bytes: "128 B" }
            ]
        }
    }

    Component {
        id: blockedTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            RowLayout {
                Layout.fillWidth: true
                Text { text: "Blocked IP Addresses"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                Item { Layout.fillWidth: true }
                Rectangle { width: impLabel.implicitWidth + 24; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1; Text { id: impLabel; anchors.centerIn: parent; text: "Import List"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                Rectangle { width: expLabel.implicitWidth + 24; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1; Text { id: expLabel; anchors.centerIn: parent; text: "Export"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
            }

            DataTable {
                Layout.fillWidth: true
                Layout.preferredHeight: 380
                title: ""
                columns: [
                    { key: "ip", label: "IP Address", width: 160 },
                    { key: "reason", label: "Reason", width: 200 },
                    { key: "blockedAt", label: "Blocked At", width: 160 },
                    { key: "attempts", label: "Attempts", width: 80 },
                    { key: "country", label: "Country", width: 100 },
                    { key: "source", label: "Source", width: 120 }
                ]
                rows: [
                    { ip: "203.0.113.42", reason: "Brute force SSH", blockedAt: "2024-12-15 14:28", attempts: "53", country: "CN", source: "Auto-block" },
                    { ip: "198.51.100.17", reason: "Port scanning", blockedAt: "2024-12-15 12:05", attempts: "1024", country: "RU", source: "IDS" },
                    { ip: "192.0.2.88", reason: "Known C2 server", blockedAt: "2024-12-15 10:30", attempts: "7", country: "KP", source: "Threat Feed" },
                    { ip: "45.33.32.156", reason: "DDoS source", blockedAt: "2024-12-14 22:15", attempts: "50000", country: "US", source: "Rate Limiter" },
                    { ip: "103.224.182.250", reason: "Malware distribution", blockedAt: "2024-12-14 18:40", attempts: "12", country: "VN", source: "Threat Feed" }
                ]
            }
        }
    }

    Component {
        id: dnsTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "DNS Filter Configuration"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            // Category toggles
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 350
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingSmall

                    Repeater {
                        model: ListModel {
                            ListElement { category: "Malware Domains"; enabled: true; count: "145,892" }
                            ListElement { category: "Phishing Sites"; enabled: true; count: "89,234" }
                            ListElement { category: "Cryptomining"; enabled: true; count: "12,456" }
                            ListElement { category: "Adult Content"; enabled: false; count: "2,100,000" }
                            ListElement { category: "Gambling"; enabled: false; count: "45,678" }
                            ListElement { category: "Social Media"; enabled: false; count: "234" }
                            ListElement { category: "Ads & Trackers"; enabled: true; count: "567,890" }
                            ListElement { category: "Newly Registered Domains"; enabled: true; count: "34,567" }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            height: 40
                            radius: ThemeManager.radiusSmall
                            color: "transparent"

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: ThemeManager.spacingSmall
                                Rectangle { width: 36; height: 20; radius: 10; color: model.enabled ? ThemeManager.successColor : ThemeManager.borderColor; Rectangle { x: model.enabled ? 18 : 2; y: 2; width: 16; height: 16; radius: 8; color: "#ffffff" } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                                Text { text: model.category; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                                Text { text: model.count + " domains"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            }
                        }
                    }
                }
            }
        }
    }

    Component {
        id: geoTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "Geographic Blocking"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 150
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1
                Text { anchors.centerIn: parent; text: "[World Map Visualization Placeholder]"; font.pixelSize: ThemeManager.fontSizeNormal; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
            }

            DataTable {
                Layout.fillWidth: true
                Layout.preferredHeight: 300
                title: "Country Block List"
                columns: [
                    { key: "country", label: "Country", width: 160 },
                    { key: "code", label: "Code", width: 60 },
                    { key: "blocked", label: "Status", width: 100 },
                    { key: "blockedCount", label: "Blocked Requests", width: 140 },
                    { key: "lastActivity", label: "Last Activity", width: 160 }
                ]
                rows: [
                    { country: "China", code: "CN", blocked: "Blocked", blockedCount: "45,892", lastActivity: "2 min ago" },
                    { country: "Russia", code: "RU", blocked: "Blocked", blockedCount: "23,456", lastActivity: "5 min ago" },
                    { country: "North Korea", code: "KP", blocked: "Blocked", blockedCount: "1,234", lastActivity: "1 hour ago" },
                    { country: "Iran", code: "IR", blocked: "Blocked", blockedCount: "8,901", lastActivity: "15 min ago" },
                    { country: "Vietnam", code: "VN", blocked: "Monitored", blockedCount: "567", lastActivity: "30 min ago" }
                ]
            }
        }
    }

    Component {
        id: bwTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Upload"; value: "12.8 MB/s"; trend: 5.2; icon: "\u2191"; iconColor: ThemeManager.successColor; sparklineData: [10,11,12,11,13,12,13] }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Download"; value: "32.4 MB/s"; trend: -2.1; icon: "\u2193"; iconColor: ThemeManager.primaryColor; sparklineData: [35,34,33,34,32,33,32] }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Today"; value: "1.2 TB"; trend: 0; icon: "\u21C5"; iconColor: ThemeManager.chart6 }
            }

            ThreatChart {
                Layout.fillWidth: true
                Layout.preferredHeight: 300
                title: "Bandwidth Usage (24h)"
                chartType: "bar"
                chartData: [
                    { label: "00:00", value: 15 }, { label: "02:00", value: 8 },
                    { label: "04:00", value: 5 }, { label: "06:00", value: 12 },
                    { label: "08:00", value: 35 }, { label: "10:00", value: 52 },
                    { label: "12:00", value: 48 }, { label: "14:00", value: 55 },
                    { label: "16:00", value: 42 }, { label: "18:00", value: 38 },
                    { label: "20:00", value: 28 }, { label: "22:00", value: 20 }
                ]
            }
        }
    }
}
