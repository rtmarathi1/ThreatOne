import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: monitorPage
    objectName: "monitor"
    color: ThemeManager.backgroundColor

    // ViewModel binding placeholders
    property var monitorViewModel: QtObject {
        property real cpuUsage: 45.0
        property real memoryUsage: 68.0
        property real diskUsage: 52.0
        property real networkIn: 124.5
        property real networkOut: 87.3
        property int uptime: 1247400
        property real throughput: 1.24

        Behavior on cpuUsage { NumberAnimation { duration: 1200; easing.type: Easing.OutCubic } }
        Behavior on memoryUsage { NumberAnimation { duration: 1200; easing.type: Easing.OutCubic } }
        Behavior on diskUsage { NumberAnimation { duration: 1200; easing.type: Easing.OutCubic } }
        Behavior on networkIn { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
        Behavior on networkOut { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
    }

    // Real-time resource update timer (1.5s)
    Timer {
        id: resourceTimer
        interval: 1500
        running: true
        repeat: true
        onTriggered: {
            monitorViewModel.cpuUsage = 25 + Math.random() * 55
            monitorViewModel.memoryUsage = 55 + Math.random() * 30
            monitorViewModel.diskUsage = 45 + Math.random() * 20
            monitorViewModel.networkIn = 80 + Math.random() * 120
            monitorViewModel.networkOut = 50 + Math.random() * 80
            monitorViewModel.uptime += 1
            monitorViewModel.throughput = 0.8 + Math.random() * 1.2
        }
    }

    // Network traffic chart data (rolling)
    property var networkChartData: [
        { label: "1", value: 95 },
        { label: "2", value: 120 },
        { label: "3", value: 88 },
        { label: "4", value: 145 },
        { label: "5", value: 110 },
        { label: "6", value: 132 },
        { label: "7", value: 98 }
    ]

    Timer {
        id: networkChartTimer
        interval: 2000
        running: true
        repeat: true
        onTriggered: {
            var newData = []
            for (var i = 1; i < monitorPage.networkChartData.length; i++) {
                newData.push(monitorPage.networkChartData[i])
            }
            newData.push({ label: String(monitorPage.networkChartData.length + 1), value: Math.floor(80 + Math.random() * 120) })
            monitorPage.networkChartData = newData
        }
    }

    // Service health model
    property var services: [
        { name: "Agent Service", status: "healthy", uptime: "14d 5h" },
        { name: "Scanner Engine", status: "healthy", uptime: "14d 5h" },
        { name: "Firewall Module", status: "healthy", uptime: "7d 12h" },
        { name: "SIEM Collector", status: "healthy", uptime: "14d 5h" },
        { name: "XDR Correlator", status: "warning", uptime: "2d 8h" },
        { name: "Update Service", status: "healthy", uptime: "14d 5h" },
        { name: "Log Forwarder", status: "healthy", uptime: "14d 5h" },
        { name: "Threat Intel Feed", status: "healthy", uptime: "14d 5h" },
        { name: "API Gateway", status: "healthy", uptime: "14d 5h" },
        { name: "Database", status: "healthy", uptime: "30d 2h" },
        { name: "Message Queue", status: "warning", uptime: "5d 11h" },
        { name: "Cache Server", status: "healthy", uptime: "14d 5h" }
    ]

    // Service health flicker timer
    Timer {
        id: serviceFlickerTimer
        interval: 4000
        running: true
        repeat: true
        onTriggered: {
            var newServices = []
            for (var i = 0; i < monitorPage.services.length; i++) {
                var s = monitorPage.services[i]
                var newStatus = s.status
                // 10% chance of status flicker
                if (Math.random() < 0.1) {
                    if (s.status === "healthy") {
                        newStatus = Math.random() < 0.7 ? "healthy" : "warning"
                    } else if (s.status === "warning") {
                        newStatus = Math.random() < 0.5 ? "healthy" : "warning"
                    }
                }
                newServices.push({ name: s.name, status: newStatus, uptime: s.uptime })
            }
            monitorPage.services = newServices
        }
    }

    // Format uptime
    function formatUptime(seconds) {
        var days = Math.floor(seconds / 86400)
        var hours = Math.floor((seconds % 86400) / 3600)
        var mins = Math.floor((seconds % 3600) / 60)
        return days + "d " + hours + "h " + mins + "m"
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
                        text: "System Monitor"
                        font.pixelSize: ThemeManager.fontSizeHeading
                        font.weight: Font.Bold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }
                    Text {
                        text: "Infrastructure health monitoring and resource utilization"
                        font.pixelSize: ThemeManager.fontSizeNormal
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                    }
                }
                Item { Layout.fillWidth: true }
                ColumnLayout {
                    spacing: 2
                    Text {
                        text: "Uptime: " + monitorPage.formatUptime(monitorViewModel.uptime)
                        font.pixelSize: ThemeManager.fontSizeSmall
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.successColor
                        font.weight: Font.Medium
                        Layout.alignment: Qt.AlignRight
                    }
                    Text {
                        text: "Throughput: " + monitorViewModel.throughput.toFixed(2) + " GB/s"
                        font.pixelSize: ThemeManager.fontSizeSmall
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textMuted
                        Layout.alignment: Qt.AlignRight
                    }
                }
            }

            // Resource gauges row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                // CPU Gauge
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 160
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        Text {
                            text: "CPU"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: monitorViewModel.cpuUsage.toFixed(1) + "%"
                            font.pixelSize: ThemeManager.fontSizeDisplay
                            font.weight: Font.Bold
                            font.family: ThemeManager.fontFamily
                            color: monitorViewModel.cpuUsage > 80 ? ThemeManager.errorColor : monitorViewModel.cpuUsage > 60 ? ThemeManager.warningColor : ThemeManager.primaryColor
                        }

                        Item { Layout.fillHeight: true }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 8
                            radius: 4
                            color: ThemeManager.borderColor
                            Rectangle {
                                width: parent.width * (monitorViewModel.cpuUsage / 100)
                                height: parent.height
                                radius: 4
                                color: monitorViewModel.cpuUsage > 80 ? ThemeManager.errorColor : monitorViewModel.cpuUsage > 60 ? ThemeManager.warningColor : ThemeManager.primaryColor
                                Behavior on width { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
                            }
                        }

                        Text {
                            text: "8 cores / 16 threads"
                            font.pixelSize: ThemeManager.fontSizeXS
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                        }
                    }
                }

                // Memory Gauge
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 160
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        Text {
                            text: "Memory"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: monitorViewModel.memoryUsage.toFixed(1) + "%"
                            font.pixelSize: ThemeManager.fontSizeDisplay
                            font.weight: Font.Bold
                            font.family: ThemeManager.fontFamily
                            color: monitorViewModel.memoryUsage > 85 ? ThemeManager.errorColor : monitorViewModel.memoryUsage > 70 ? ThemeManager.warningColor : ThemeManager.successColor
                        }

                        Item { Layout.fillHeight: true }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 8
                            radius: 4
                            color: ThemeManager.borderColor
                            Rectangle {
                                width: parent.width * (monitorViewModel.memoryUsage / 100)
                                height: parent.height
                                radius: 4
                                color: monitorViewModel.memoryUsage > 85 ? ThemeManager.errorColor : monitorViewModel.memoryUsage > 70 ? ThemeManager.warningColor : ThemeManager.successColor
                                Behavior on width { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
                            }
                        }

                        Text {
                            text: "21.8 / 32 GB used"
                            font.pixelSize: ThemeManager.fontSizeXS
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                        }
                    }
                }

                // Disk Gauge
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 160
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        Text {
                            text: "Disk"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: monitorViewModel.diskUsage.toFixed(1) + "%"
                            font.pixelSize: ThemeManager.fontSizeDisplay
                            font.weight: Font.Bold
                            font.family: ThemeManager.fontFamily
                            color: monitorViewModel.diskUsage > 85 ? ThemeManager.errorColor : monitorViewModel.diskUsage > 70 ? ThemeManager.warningColor : ThemeManager.secondaryColor
                        }

                        Item { Layout.fillHeight: true }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 8
                            radius: 4
                            color: ThemeManager.borderColor
                            Rectangle {
                                width: parent.width * (monitorViewModel.diskUsage / 100)
                                height: parent.height
                                radius: 4
                                color: monitorViewModel.diskUsage > 85 ? ThemeManager.errorColor : monitorViewModel.diskUsage > 70 ? ThemeManager.warningColor : ThemeManager.secondaryColor
                                Behavior on width { NumberAnimation { duration: 1000; easing.type: Easing.OutCubic } }
                            }
                        }

                        Text {
                            text: "520 / 1000 GB used"
                            font.pixelSize: ThemeManager.fontSizeXS
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                        }
                    }
                }

                // Network I/O Gauge
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 160
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        Text {
                            text: "Network I/O"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }

                        Item { Layout.fillHeight: true }

                        RowLayout {
                            Layout.alignment: Qt.AlignHCenter
                            spacing: ThemeManager.spacingMedium
                            ColumnLayout {
                                spacing: 2
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "\u2193 " + monitorViewModel.networkIn.toFixed(1)
                                    font.pixelSize: ThemeManager.fontSizeLarge
                                    font.weight: Font.Bold
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.successColor
                                }
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "MB/s in"
                                    font.pixelSize: ThemeManager.fontSizeXS
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textMuted
                                }
                            }
                            ColumnLayout {
                                spacing: 2
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "\u2191 " + monitorViewModel.networkOut.toFixed(1)
                                    font.pixelSize: ThemeManager.fontSizeLarge
                                    font.weight: Font.Bold
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.primaryColor
                                }
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "MB/s out"
                                    font.pixelSize: ThemeManager.fontSizeXS
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textMuted
                                }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            text: "10 Gbps link capacity"
                            font.pixelSize: ThemeManager.fontSizeXS
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                        }
                    }
                }
            }

            // Network traffic chart
            ThreatChart {
                Layout.fillWidth: true
                Layout.preferredHeight: 280
                title: "Network Traffic (Live MB/s)"
                chartType: "line"
                chartData: monitorPage.networkChartData
            }

            // Service Health Grid
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
                            text: "Service Health"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }
                        Item { Layout.fillWidth: true }
                        RowLayout {
                            spacing: ThemeManager.spacingMedium
                            RowLayout {
                                spacing: 4
                                Rectangle { width: 8; height: 8; radius: 4; color: ThemeManager.successColor }
                                Text { text: "Healthy"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            }
                            RowLayout {
                                spacing: 4
                                Rectangle { width: 8; height: 8; radius: 4; color: ThemeManager.warningColor }
                                Text { text: "Warning"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            }
                            RowLayout {
                                spacing: 4
                                Rectangle { width: 8; height: 8; radius: 4; color: ThemeManager.errorColor }
                                Text { text: "Critical"; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            }
                        }
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        columns: 3
                        rowSpacing: ThemeManager.spacingSmall
                        columnSpacing: ThemeManager.spacingSmall

                        Repeater {
                            model: monitorPage.services.length

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 70
                                radius: ThemeManager.radiusMedium
                                color: ThemeManager.cardColor
                                border.color: monitorPage.services[index].status === "healthy" ? Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.3) :
                                              monitorPage.services[index].status === "warning" ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.3) :
                                              Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.3)
                                border.width: 1

                                property var serviceData: monitorPage.services[index]

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: ThemeManager.spacingSmall
                                    spacing: ThemeManager.spacingSmall

                                    Rectangle {
                                        width: 10
                                        height: 10
                                        radius: 5
                                        color: serviceData.status === "healthy" ? ThemeManager.successColor :
                                               serviceData.status === "warning" ? ThemeManager.warningColor :
                                               ThemeManager.errorColor
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2
                                        Text {
                                            text: serviceData.name
                                            font.pixelSize: ThemeManager.fontSizeSmall
                                            font.weight: Font.Medium
                                            font.family: ThemeManager.fontFamily
                                            color: ThemeManager.textPrimary
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        Text {
                                            text: "Up: " + serviceData.uptime
                                            font.pixelSize: ThemeManager.fontSizeXS
                                            font.family: ThemeManager.fontFamily
                                            color: ThemeManager.textMuted
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
}
