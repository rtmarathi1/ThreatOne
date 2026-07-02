import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: dashboardPage
    objectName: "dashboard"
    color: ThemeManager.backgroundColor

    // ViewModel binding placeholders
    property var dashboardViewModel: QtObject {
        property real securityScore: 87
        property int threatsBlocked: 1247
        property int activeScans: 3
        property int openIncidents: 7
        property int criticalAlerts: 4
        property int totalAssets: 342
        property int healthyEndpoints: 298
        property int warningEndpoints: 31
        property int criticalEndpoints: 13
        property real complianceScore: 92.5
        property real cpuUsage: 42.0
        property real memUsage: 67.0
        property real diskUsage: 54.0
        property bool networkUp: true

        Behavior on securityScore { NumberAnimation { duration: 800; easing.type: Easing.OutCubic } }
        Behavior on threatsBlocked { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
        Behavior on activeScans { NumberAnimation { duration: 400; easing.type: Easing.OutCubic } }
        Behavior on openIncidents { NumberAnimation { duration: 400; easing.type: Easing.OutCubic } }
        Behavior on cpuUsage { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
        Behavior on memUsage { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
        Behavior on diskUsage { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
    }

    // Real-time data simulation timer (2s interval)
    Timer {
        id: dataSimTimer
        interval: 2000
        running: true
        repeat: true
        onTriggered: {
            dashboardViewModel.securityScore = 82 + Math.random() * 13
            dashboardViewModel.threatsBlocked += Math.floor(1 + Math.random() * 5)
            dashboardViewModel.activeScans = Math.floor(1 + Math.random() * 5)
            dashboardViewModel.openIncidents = Math.floor(3 + Math.random() * 10)
            dashboardViewModel.cpuUsage = 30 + Math.random() * 50
            dashboardViewModel.memUsage = 55 + Math.random() * 30
            dashboardViewModel.diskUsage = 40 + Math.random() * 30
        }
    }

    // Last updated timestamp refresh (1s interval)
    property string lastUpdatedTime: Qt.formatDateTime(new Date(), "hh:mm:ss AP")
    Timer {
        id: timestampTimer
        interval: 1000
        running: true
        repeat: true
        onTriggered: dashboardPage.lastUpdatedTime = Qt.formatDateTime(new Date(), "hh:mm:ss AP")
    }

    // Live chart data
    property var liveChartData: [
        { label: "Mon", value: 45 },
        { label: "Tue", value: 62 },
        { label: "Wed", value: 38 },
        { label: "Thu", value: 71 },
        { label: "Fri", value: 55 },
        { label: "Sat", value: 29 },
        { label: "Sun", value: 33 }
    ]

    // Chart data update timer (3s interval)
    Timer {
        id: chartUpdateTimer
        interval: 3000
        running: true
        repeat: true
        onTriggered: {
            var newData = []
            for (var i = 1; i < dashboardPage.liveChartData.length; i++) {
                newData.push(dashboardPage.liveChartData[i])
            }
            var labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            newData.push({ label: labels[Math.floor(Math.random() * 7)], value: Math.floor(20 + Math.random() * 60) })
            dashboardPage.liveChartData = newData
        }
    }

    // Network status dot pulsing
    property real networkDotOpacity: 1.0
    SequentialAnimation on networkDotOpacity {
        loops: Animation.Infinite
        NumberAnimation { from: 1.0; to: 0.4; duration: 1000; easing.type: Easing.InOutSine }
        NumberAnimation { from: 0.4; to: 1.0; duration: 1000; easing.type: Easing.InOutSine }
    }

    // Critical alerts badge pulsing
    property real alertBadgePulse: 1.0
    SequentialAnimation on alertBadgePulse {
        loops: Animation.Infinite
        NumberAnimation { from: 1.0; to: 0.6; duration: 800; easing.type: Easing.InOutSine }
        NumberAnimation { from: 0.6; to: 1.0; duration: 800; easing.type: Easing.InOutSine }
    }

    ScrollView {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingXL
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: ThemeManager.spacingXL

            // Page header
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: ThemeManager.spacingXS
                    Text {
                        text: "Executive Dashboard"
                        font.pixelSize: ThemeManager.fontSizeHeading
                        font.weight: Font.Bold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }
                    Text {
                        text: "Real-time security posture overview"
                        font.pixelSize: ThemeManager.fontSizeNormal
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                    }
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: "Last updated: " + dashboardPage.lastUpdatedTime
                    font.pixelSize: ThemeManager.fontSizeSmall
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textMuted
                }
            }

            // Top stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Threats Blocked"
                    value: dashboardViewModel.threatsBlocked.toLocaleString()
                    trend: 12.3
                    icon: "\u26A0"
                    iconColor: ThemeManager.warningColor
                    sparklineData: [980, 1020, 1100, 1050, 1150, 1200, 1247]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Active Scans"
                    value: dashboardViewModel.activeScans.toString()
                    trend: 0
                    icon: "\u21BB"
                    iconColor: ThemeManager.primaryColor
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Open Incidents"
                    value: dashboardViewModel.openIncidents.toString()
                    trend: -22.0
                    icon: "\u2139"
                    iconColor: ThemeManager.errorColor
                    sparklineData: [12, 11, 10, 9, 8, 9, 7]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Total Assets"
                    value: dashboardViewModel.totalAssets.toString()
                    trend: 3.2
                    icon: "\u2318"
                    iconColor: ThemeManager.successColor
                    sparklineData: [320, 325, 330, 332, 338, 340, 342]
                }
            }

            // Main content row: score gauge + threat chart + compliance
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                SecurityScoreGauge {
                    Layout.preferredWidth: 280
                    Layout.preferredHeight: 300
                    score: dashboardViewModel.securityScore
                    label: "Overall Security Score"
                }

                ThreatChart {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                    title: "Threat Activity (Live)"
                    chartType: "line"
                    chartData: dashboardPage.liveChartData
                }

                // Compliance Score Card
                Rectangle {
                    Layout.preferredWidth: 220
                    Layout.preferredHeight: 300
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.glassBackground
                    border.color: Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.3)
                    border.width: 1

                    // Gradient overlay
                    Rectangle {
                        anchors.fill: parent
                        radius: parent.radius
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(ThemeManager.surfaceColor.r, ThemeManager.surfaceColor.g, ThemeManager.surfaceColor.b, 0.7) }
                            GradientStop { position: 1.0; color: Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.7) }
                        }
                    }

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingMedium

                        Text {
                            text: "Compliance"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: dashboardViewModel.complianceScore.toFixed(1) + "%"
                            font.pixelSize: ThemeManager.fontSizeDisplay
                            font.weight: Font.Bold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.successColor
                        }

                        Item { Layout.fillHeight: true }

                        // Framework scores
                        Repeater {
                            model: [
                                { name: "NIST CSF", score: 94 },
                                { name: "ISO 27001", score: 89 },
                                { name: "SOC 2", score: 91 },
                                { name: "PCI DSS", score: 96 }
                            ]
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: modelData.name; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                                    Item { Layout.fillWidth: true }
                                    Text { text: modelData.score + "%"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; font.weight: Font.Medium }
                                }
                                Rectangle {
                                    Layout.fillWidth: true
                                    height: 3
                                    radius: 2
                                    color: ThemeManager.borderColor
                                    Rectangle {
                                        width: parent.width * modelData.score / 100
                                        height: parent.height
                                        radius: 2
                                        color: modelData.score >= 90 ? ThemeManager.successColor : ThemeManager.warningColor
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Middle row: Risk heatmap + Endpoint health + System performance
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                // Risk Heatmap
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 260
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingMedium

                        Text {
                            text: "Risk Heatmap"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        GridLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            columns: 6
                            rowSpacing: 4
                            columnSpacing: 4

                            Repeater {
                                model: [
                                    3,1,2,0,1,2, 1,0,3,2,1,0,
                                    2,1,0,1,2,3, 0,2,1,0,1,1,
                                    1,3,2,1,0,2
                                ]
                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    radius: ThemeManager.radiusSmall
                                    color: modelData === 3 ? ThemeManager.severityCritical :
                                           modelData === 2 ? ThemeManager.severityHigh :
                                           modelData === 1 ? ThemeManager.severityMedium :
                                           ThemeManager.cardColor
                                    opacity: modelData === 0 ? 0.3 : 0.7 + modelData * 0.1
                                }
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: ThemeManager.spacingMedium
                            Text { text: "Low"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            Rectangle { width: 12; height: 12; radius: 2; color: ThemeManager.severityMedium; opacity: 0.7 }
                            Rectangle { width: 12; height: 12; radius: 2; color: ThemeManager.severityHigh; opacity: 0.8 }
                            Rectangle { width: 12; height: 12; radius: 2; color: ThemeManager.severityCritical; opacity: 0.9 }
                            Text { text: "Critical"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }
                    }
                }

                // Endpoint Health
                Rectangle {
                    Layout.preferredWidth: 260
                    Layout.preferredHeight: 260
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.glassBackground
                    border.color: Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.3)
                    border.width: 1

                    // Gradient overlay
                    Rectangle {
                        anchors.fill: parent
                        radius: parent.radius
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(ThemeManager.surfaceColor.r, ThemeManager.surfaceColor.g, ThemeManager.surfaceColor.b, 0.7) }
                            GradientStop { position: 1.0; color: Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.7) }
                        }
                    }

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingMedium

                        Text {
                            text: "Endpoint Health"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Repeater {
                            model: [
                                { label: "Healthy", count: dashboardViewModel.healthyEndpoints, color: ThemeManager.successColor },
                                { label: "Warning", count: dashboardViewModel.warningEndpoints, color: ThemeManager.warningColor },
                                { label: "Critical", count: dashboardViewModel.criticalEndpoints, color: ThemeManager.errorColor }
                            ]
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: ThemeManager.spacingSmall
                                Rectangle { width: 12; height: 12; radius: 6; color: modelData.color }
                                Text { text: modelData.label; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                                Text { text: modelData.count.toString(); font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        // Stacked bar
                        Rectangle {
                            Layout.fillWidth: true
                            height: 8
                            radius: 4
                            color: ThemeManager.borderColor
                            Row {
                                anchors.fill: parent
                                Rectangle {
                                    width: parent.width * (dashboardViewModel.healthyEndpoints / dashboardViewModel.totalAssets)
                                    height: parent.height
                                    radius: 4
                                    color: ThemeManager.successColor
                                }
                                Rectangle {
                                    width: parent.width * (dashboardViewModel.warningEndpoints / dashboardViewModel.totalAssets)
                                    height: parent.height
                                    color: ThemeManager.warningColor
                                }
                                Rectangle {
                                    width: parent.width * (dashboardViewModel.criticalEndpoints / dashboardViewModel.totalAssets)
                                    height: parent.height
                                    radius: 4
                                    color: ThemeManager.errorColor
                                }
                            }
                        }
                    }
                }

                // System Performance
                Rectangle {
                    Layout.preferredWidth: 260
                    Layout.preferredHeight: 260
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.glassBackground
                    border.color: Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.3)
                    border.width: 1

                    // Gradient overlay
                    Rectangle {
                        anchors.fill: parent
                        radius: parent.radius
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(ThemeManager.surfaceColor.r, ThemeManager.surfaceColor.g, ThemeManager.surfaceColor.b, 0.7) }
                            GradientStop { position: 1.0; color: Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.7) }
                        }
                    }

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingMedium

                        Text {
                            text: "System Performance"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Repeater {
                            model: [
                                { label: "CPU", usage: dashboardViewModel.cpuUsage, color: ThemeManager.primaryColor },
                                { label: "Memory", usage: dashboardViewModel.memUsage, color: ThemeManager.secondaryColor },
                                { label: "Disk I/O", usage: dashboardViewModel.diskUsage, color: ThemeManager.chart2 }
                            ]
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 4
                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: modelData.label; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                                    Item { Layout.fillWidth: true }
                                    Text { text: modelData.usage.toFixed(0) + "%"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                                }
                                Rectangle {
                                    Layout.fillWidth: true
                                    height: 6
                                    radius: 3
                                    color: ThemeManager.borderColor
                                    Rectangle {
                                        width: parent.width * (modelData.usage / 100)
                                        height: parent.height
                                        radius: 3
                                        color: modelData.color
                                    }
                                }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        // Network status indicator
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: ThemeManager.spacingSmall
                            Rectangle { width: 8; height: 8; radius: 4; color: dashboardViewModel.networkUp ? ThemeManager.successColor : ThemeManager.errorColor; opacity: dashboardPage.networkDotOpacity }
                            Text { text: "Network: " + (dashboardViewModel.networkUp ? "Online" : "Offline"); font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Item { Layout.fillWidth: true }
                            Text { text: "45.2 MB/s"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }
                    }
                }
            }

            // Bottom row: Attack timeline + Critical alerts + AI Insights
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                TimelineView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 350
                    title: "Live Attack Timeline"
                    events: [
                        { time: "14:32", title: "Ransomware attempt blocked", description: "LockBit variant detected and quarantined on WS-2847", severity: "critical" },
                        { time: "14:28", title: "Lateral movement detected", description: "PsExec execution from compromised host 10.0.1.15", severity: "high" },
                        { time: "14:15", title: "Brute force attempt", description: "50+ failed SSH logins from 203.0.113.42", severity: "high" },
                        { time: "14:02", title: "Suspicious DNS query", description: "DGA domain resolution: xk9f2m.malware.cc", severity: "medium" },
                        { time: "13:45", title: "Policy violation", description: "Unauthorized USB device connected on ADMIN-PC", severity: "medium" },
                        { time: "13:30", title: "Certificate expiring", description: "TLS cert for api.internal expires in 7 days", severity: "low" },
                        { time: "13:15", title: "Scan completed", description: "Full system scan finished - 0 threats found", severity: "info" }
                    ]
                }

                // Critical Alerts + AI Insights column
                ColumnLayout {
                    Layout.preferredWidth: 380
                    spacing: ThemeManager.spacingNormal

                    // Critical alerts section
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 200
                        radius: ThemeManager.radiusLarge
                        color: ThemeManager.surfaceColor
                        border.color: ThemeManager.borderColor
                        border.width: 1

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: ThemeManager.spacingLarge
                            spacing: ThemeManager.spacingSmall

                            RowLayout {
                                Layout.fillWidth: true
                                Text { text: "Critical Alerts"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                                Item { Layout.fillWidth: true }
                                Rectangle {
                                    width: 24; height: 20; radius: ThemeManager.radiusSmall
                                    color: Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15)
                                    opacity: dashboardPage.alertBadgePulse
                                    Text { anchors.centerIn: parent; text: dashboardViewModel.criticalAlerts.toString(); font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Bold; color: ThemeManager.errorColor; font.family: ThemeManager.fontFamily }
                                }
                            }

                            ListView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                spacing: ThemeManager.spacingSmall
                                model: ListModel {
                                    ListElement { alertTitle: "Ransomware detected"; alertSource: "EDR"; alertTime: "2m ago" }
                                    ListElement { alertTitle: "Data exfiltration attempt"; alertSource: "DLP"; alertTime: "5m ago" }
                                    ListElement { alertTitle: "C2 beacon active"; alertSource: "NDR"; alertTime: "8m ago" }
                                    ListElement { alertTitle: "Privilege escalation"; alertSource: "SIEM"; alertTime: "12m ago" }
                                }
                                delegate: Rectangle {
                                    width: ListView.view.width
                                    height: 32
                                    radius: ThemeManager.radiusSmall
                                    color: ThemeManager.cardColor

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: ThemeManager.spacingSmall
                                        Rectangle { width: 4; height: 16; radius: 2; color: ThemeManager.errorColor }
                                        Text { text: model.alertTitle; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true; elide: Text.ElideRight }
                                        Text { text: model.alertSource; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily }
                                        Text { text: model.alertTime; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                                    }
                                }
                            }
                        }
                    }

                    // AI Insights
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 140
                        radius: ThemeManager.radiusLarge
                        color: ThemeManager.surfaceColor
                        border.color: ThemeManager.secondaryColor
                        border.width: 1

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: ThemeManager.spacingLarge
                            spacing: ThemeManager.spacingSmall

                            RowLayout {
                                Layout.fillWidth: true
                                Text { text: "\u2728"; font.pixelSize: ThemeManager.fontSizeMedium }
                                Text { text: "AI Insights"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            }

                            Text {
                                Layout.fillWidth: true
                                text: "\u2022 Unusual login pattern detected for user jsmith - recommend MFA review\n\u2022 Network segment 10.0.3.x shows 40% increase in lateral traffic\n\u2022 3 endpoints missing critical patches from last Tuesday"
                                font.pixelSize: ThemeManager.fontSizeSmall
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textSecondary
                                wrapMode: Text.WordWrap
                                lineHeight: 1.4
                            }
                        }
                    }
                }
            }

            // MITRE ATT&CK Matrix section
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 200
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingMedium

                    Text {
                        text: "MITRE ATT&CK Coverage"
                        font.pixelSize: ThemeManager.fontSizeMedium
                        font.weight: Font.DemiBold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }

                    // Tactics row
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: ThemeManager.spacingXS

                        Repeater {
                            model: [
                                { tactic: "Recon", coverage: 85 },
                                { tactic: "Resource Dev", coverage: 72 },
                                { tactic: "Initial Access", coverage: 91 },
                                { tactic: "Execution", coverage: 88 },
                                { tactic: "Persistence", coverage: 79 },
                                { tactic: "Priv Esc", coverage: 83 },
                                { tactic: "Defense Evasion", coverage: 67 },
                                { tactic: "Credential Access", coverage: 90 },
                                { tactic: "Discovery", coverage: 75 },
                                { tactic: "Lateral Mov", coverage: 81 },
                                { tactic: "Collection", coverage: 70 },
                                { tactic: "C2", coverage: 86 },
                                { tactic: "Exfiltration", coverage: 78 },
                                { tactic: "Impact", coverage: 92 }
                            ]
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                radius: ThemeManager.radiusSmall
                                color: modelData.coverage >= 85 ? Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.2) :
                                       modelData.coverage >= 70 ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.2) :
                                       Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.2)
                                border.color: modelData.coverage >= 85 ? ThemeManager.successColor :
                                              modelData.coverage >= 70 ? ThemeManager.warningColor :
                                              ThemeManager.errorColor
                                border.width: 1

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 4
                                    spacing: 2
                                    Text { Layout.fillWidth: true; text: modelData.tactic; font.pixelSize: 8; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary; horizontalAlignment: Text.AlignHCenter; elide: Text.ElideRight }
                                    Text { Layout.fillWidth: true; text: modelData.coverage + "%"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary; horizontalAlignment: Text.AlignHCenter }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
