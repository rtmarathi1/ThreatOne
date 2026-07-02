import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: siemPage
    objectName: "siem"
    color: ThemeManager.backgroundColor

    // ViewModel binding placeholders
    property var siemViewModel: QtObject {
        property int eventsPerSec: 2450
        property int alertsGenerated: 127
        property int correlationRules: 84
        property int logSources: 36
        property int totalEventsToday: 4820000

        Behavior on eventsPerSec { NumberAnimation { duration: 800; easing.type: Easing.OutCubic } }
        Behavior on alertsGenerated { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
    }

    // Real-time events/sec timer (1.5s)
    Timer {
        id: eventsTimer
        interval: 1500
        running: true
        repeat: true
        onTriggered: {
            siemViewModel.eventsPerSec = Math.floor(1200 + Math.random() * 2300)
            siemViewModel.alertsGenerated += Math.floor(Math.random() * 3)
            siemViewModel.totalEventsToday += siemViewModel.eventsPerSec
        }
    }

    // Live event log model
    property var logSeverities: ["Critical", "High", "Medium", "Low", "Info"]
    property var logSources: ["Firewall", "Endpoint", "DNS", "Auth", "IDS", "Proxy", "Mail"]
    property var logMessages: [
        "Connection blocked from suspicious IP",
        "Failed authentication attempt detected",
        "DNS query to known malicious domain",
        "Unusual outbound traffic pattern",
        "Port scan detected on subnet",
        "Privilege escalation attempt",
        "Malware signature match",
        "Certificate validation failure",
        "Brute force login attempt",
        "Data exfiltration pattern detected",
        "Unauthorized registry modification",
        "Suspicious PowerShell execution",
        "Lateral movement via SMB",
        "C2 beacon communication detected",
        "Anomalous user behavior score elevated"
    ]

    ListModel {
        id: eventLogModel
    }

    // Live event log timer (1s)
    Timer {
        id: logTimer
        interval: 1000
        running: true
        repeat: true
        onTriggered: {
            var severity = siemPage.logSeverities[Math.floor(Math.random() * siemPage.logSeverities.length)]
            var source = siemPage.logSources[Math.floor(Math.random() * siemPage.logSources.length)]
            var message = siemPage.logMessages[Math.floor(Math.random() * siemPage.logMessages.length)]
            var ip = Math.floor(Math.random() * 223 + 1) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255)
            var now = new Date()
            var timeStr = Qt.formatDateTime(now, "hh:mm:ss")

            eventLogModel.insert(0, {
                eventTime: timeStr,
                eventSeverity: severity,
                eventSource: source,
                eventMessage: message + " (" + ip + ")",
                eventIp: ip
            })

            // Keep max 50 entries
            if (eventLogModel.count > 50) {
                eventLogModel.remove(50, eventLogModel.count - 50)
            }
        }
    }

    // Events per minute chart data (rolling)
    property var eventsChartData: [
        { label: "1m", value: 2100 },
        { label: "2m", value: 2350 },
        { label: "3m", value: 1980 },
        { label: "4m", value: 2600 },
        { label: "5m", value: 2450 },
        { label: "6m", value: 2200 },
        { label: "7m", value: 2800 }
    ]

    Timer {
        id: chartTimer
        interval: 2000
        running: true
        repeat: true
        onTriggered: {
            var newData = []
            for (var i = 1; i < siemPage.eventsChartData.length; i++) {
                newData.push(siemPage.eventsChartData[i])
            }
            newData.push({ label: Math.floor(siemPage.eventsChartData.length + 1) + "m", value: Math.floor(1200 + Math.random() * 2300) })
            siemPage.eventsChartData = newData
        }
    }

    // Correlation rules data
    property var correlationRulesData: [
        { name: "Brute Force Detection", status: "Active", hits: 47, severity: "High" },
        { name: "Lateral Movement Chain", status: "Active", hits: 12, severity: "Critical" },
        { name: "Data Exfiltration Pattern", status: "Active", hits: 8, severity: "Critical" },
        { name: "Privilege Escalation Sequence", status: "Active", hits: 23, severity: "High" },
        { name: "Anomalous Login Geolocation", status: "Active", hits: 31, severity: "Medium" },
        { name: "C2 Beacon Interval Detection", status: "Tuning", hits: 5, severity: "Critical" },
        { name: "Insider Threat Scoring", status: "Active", hits: 15, severity: "Medium" },
        { name: "Supply Chain Compromise", status: "Active", hits: 2, severity: "Critical" }
    ]

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
                        text: "SIEM Analytics"
                        font.pixelSize: ThemeManager.fontSizeHeading
                        font.weight: Font.Bold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }
                    Text {
                        text: "Security Information and Event Management - Real-time log analysis and correlation"
                        font.pixelSize: ThemeManager.fontSizeNormal
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                    }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: statusRow.implicitWidth + 16
                    height: 28
                    radius: ThemeManager.radiusSmall
                    color: Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.15)
                    RowLayout {
                        id: statusRow
                        anchors.centerIn: parent
                        spacing: ThemeManager.spacingXS
                        Rectangle { width: 8; height: 8; radius: 4; color: ThemeManager.successColor }
                        Text {
                            text: "Collecting"
                            font.pixelSize: ThemeManager.fontSizeSmall
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.successColor
                            font.weight: Font.Medium
                        }
                    }
                }
            }

            // Stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Events/sec"
                    value: siemViewModel.eventsPerSec.toLocaleString()
                    trend: 15.2
                    icon: "\u26A1"
                    iconColor: ThemeManager.primaryColor
                    sparklineData: [2100, 2300, 1900, 2600, 2400, 2200, 2800]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Alerts Generated"
                    value: siemViewModel.alertsGenerated.toString()
                    trend: -8.4
                    icon: "\u26A0"
                    iconColor: ThemeManager.warningColor
                    sparklineData: [140, 135, 132, 130, 128, 127, 127]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Correlation Rules"
                    value: siemViewModel.correlationRules.toString()
                    trend: 4.2
                    icon: "\u2699"
                    iconColor: ThemeManager.secondaryColor
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Log Sources"
                    value: siemViewModel.logSources.toString()
                    trend: 2.8
                    icon: "\u2261"
                    iconColor: ThemeManager.successColor
                }
            }

            // Main content: Event log + Chart
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                // Live Event Log
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 400
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingMedium

                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "Live Event Stream"
                                font.pixelSize: ThemeManager.fontSizeMedium
                                font.weight: Font.DemiBold
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textPrimary
                            }
                            Item { Layout.fillWidth: true }
                            Text {
                                text: siemViewModel.totalEventsToday.toLocaleString() + " events today"
                                font.pixelSize: ThemeManager.fontSizeSmall
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textMuted
                            }
                        }

                        // Column headers
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: ThemeManager.spacingSmall
                            Text { Layout.preferredWidth: 60; text: "TIME"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            Text { Layout.preferredWidth: 60; text: "SEVERITY"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            Text { Layout.preferredWidth: 70; text: "SOURCE"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            Text { Layout.fillWidth: true; text: "MESSAGE"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 1
                            color: ThemeManager.borderColor
                        }

                        ListView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 2
                            model: eventLogModel

                            delegate: Rectangle {
                                width: ListView.view.width
                                height: 28
                                radius: ThemeManager.radiusSmall
                                color: index % 2 === 0 ? "transparent" : Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.5)

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: ThemeManager.spacingXS
                                    anchors.rightMargin: ThemeManager.spacingXS
                                    spacing: ThemeManager.spacingSmall

                                    Text {
                                        Layout.preferredWidth: 60
                                        text: model.eventTime
                                        font.pixelSize: ThemeManager.fontSizeSmall
                                        font.family: ThemeManager.fontFamily
                                        color: ThemeManager.textMuted
                                    }
                                    Rectangle {
                                        Layout.preferredWidth: 60
                                        height: 18
                                        radius: ThemeManager.radiusSmall
                                        color: model.eventSeverity === "Critical" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.2) :
                                               model.eventSeverity === "High" ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.2) :
                                               model.eventSeverity === "Medium" ? Qt.rgba(ThemeManager.secondaryColor.r, ThemeManager.secondaryColor.g, ThemeManager.secondaryColor.b, 0.2) :
                                               Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.2)
                                        Text {
                                            anchors.centerIn: parent
                                            text: model.eventSeverity
                                            font.pixelSize: 9
                                            font.weight: Font.Medium
                                            font.family: ThemeManager.fontFamily
                                            color: model.eventSeverity === "Critical" ? ThemeManager.errorColor :
                                                   model.eventSeverity === "High" ? ThemeManager.warningColor :
                                                   model.eventSeverity === "Medium" ? ThemeManager.secondaryColor :
                                                   ThemeManager.successColor
                                        }
                                    }
                                    Text {
                                        Layout.preferredWidth: 70
                                        text: model.eventSource
                                        font.pixelSize: ThemeManager.fontSizeSmall
                                        font.family: ThemeManager.fontFamily
                                        color: ThemeManager.primaryColor
                                    }
                                    Text {
                                        Layout.fillWidth: true
                                        text: model.eventMessage
                                        font.pixelSize: ThemeManager.fontSizeSmall
                                        font.family: ThemeManager.fontFamily
                                        color: ThemeManager.textPrimary
                                        elide: Text.ElideRight
                                    }
                                }
                            }
                        }
                    }
                }

                // Events per minute chart
                ThreatChart {
                    Layout.preferredWidth: 380
                    Layout.preferredHeight: 400
                    title: "Events Per Minute (Live)"
                    chartType: "line"
                    chartData: siemPage.eventsChartData
                }
            }

            // Correlation Rules Section
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 320
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingMedium

                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "Correlation Rules"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }
                        Item { Layout.fillWidth: true }
                        Text {
                            text: siemViewModel.correlationRules + " rules active"
                            font.pixelSize: ThemeManager.fontSizeSmall
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                        }
                    }

                    // Headers
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: ThemeManager.spacingSmall
                        Text { Layout.fillWidth: true; text: "RULE NAME"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 70; text: "STATUS"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 50; text: "HITS"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily; horizontalAlignment: Text.AlignRight }
                        Text { Layout.preferredWidth: 70; text: "SEVERITY"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily; horizontalAlignment: Text.AlignRight }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: ThemeManager.borderColor
                    }

                    ListView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 4
                        model: siemPage.correlationRulesData.length

                        delegate: Rectangle {
                            width: ListView.view.width
                            height: 36
                            radius: ThemeManager.radiusSmall
                            color: index % 2 === 0 ? "transparent" : Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.5)

                            property var ruleData: siemPage.correlationRulesData[index]

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: ThemeManager.spacingSmall
                                anchors.rightMargin: ThemeManager.spacingSmall
                                spacing: ThemeManager.spacingSmall

                                Rectangle { width: 3; height: 20; radius: 2; color: ruleData.severity === "Critical" ? ThemeManager.errorColor : ruleData.severity === "High" ? ThemeManager.warningColor : ThemeManager.secondaryColor }
                                Text {
                                    Layout.fillWidth: true
                                    text: ruleData.name
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textPrimary
                                }
                                Rectangle {
                                    Layout.preferredWidth: 60
                                    height: 20
                                    radius: ThemeManager.radiusSmall
                                    color: ruleData.status === "Active" ? Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.15) : Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15)
                                    Text {
                                        anchors.centerIn: parent
                                        text: ruleData.status
                                        font.pixelSize: 9
                                        font.weight: Font.Medium
                                        font.family: ThemeManager.fontFamily
                                        color: ruleData.status === "Active" ? ThemeManager.successColor : ThemeManager.warningColor
                                    }
                                }
                                Text {
                                    Layout.preferredWidth: 50
                                    text: ruleData.hits.toString()
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.weight: Font.Medium
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textPrimary
                                    horizontalAlignment: Text.AlignRight
                                }
                                Rectangle {
                                    Layout.preferredWidth: 60
                                    height: 20
                                    radius: ThemeManager.radiusSmall
                                    color: ruleData.severity === "Critical" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15) :
                                           ruleData.severity === "High" ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15) :
                                           Qt.rgba(ThemeManager.secondaryColor.r, ThemeManager.secondaryColor.g, ThemeManager.secondaryColor.b, 0.15)
                                    Text {
                                        anchors.centerIn: parent
                                        text: ruleData.severity
                                        font.pixelSize: 9
                                        font.weight: Font.Medium
                                        font.family: ThemeManager.fontFamily
                                        color: ruleData.severity === "Critical" ? ThemeManager.errorColor :
                                               ruleData.severity === "High" ? ThemeManager.warningColor :
                                               ThemeManager.secondaryColor
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
