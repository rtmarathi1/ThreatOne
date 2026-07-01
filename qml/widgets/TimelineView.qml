import QtQuick
import QtQuick.Layouts
import "../themes"

// Vertical event timeline with timestamps, colored dots, connecting line
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
    border.width: 1

    property string title: "Timeline"
    property var events: [
        { time: "14:32", title: "Malware detected", description: "Trojan.Win32.Agent found in temp directory", severity: "critical" },
        { time: "14:28", title: "Suspicious process", description: "svchost_x86.exe spawned from cmd.exe", severity: "high" },
        { time: "14:15", title: "Network scan detected", description: "Port scan from 192.168.1.105", severity: "medium" },
        { time: "14:02", title: "Login success", description: "Admin user authenticated from VPN", severity: "low" },
        { time: "13:45", title: "Policy updated", description: "Firewall rule set updated by admin", severity: "info" }
    ]

    function severityColor(sev) {
        switch(sev) {
            case "critical": return ThemeManager.severityCritical
            case "high": return ThemeManager.severityHigh
            case "medium": return ThemeManager.severityMedium
            case "low": return ThemeManager.severityLow
            default: return ThemeManager.severityInfo
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        spacing: ThemeManager.spacingMedium

        // Header
        RowLayout {
            Layout.fillWidth: true

            Text {
                text: root.title
                font.pixelSize: ThemeManager.fontSizeMedium
                font.weight: Font.DemiBold
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textPrimary
            }

            Item { Layout.fillWidth: true }

            Text {
                text: root.events.length + " events"
                font.pixelSize: ThemeManager.fontSizeSmall
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
            }
        }

        // Timeline list
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.events
            spacing: 0

            delegate: Item {
                width: ListView.view.width
                height: eventContent.implicitHeight + ThemeManager.spacingMedium

                // Vertical connector line
                Rectangle {
                    x: 40
                    y: 0
                    width: 2
                    height: parent.height
                    color: ThemeManager.borderColor
                    visible: index < root.events.length - 1
                }

                // Timeline dot
                Rectangle {
                    id: dot
                    x: 34
                    y: ThemeManager.spacingSmall
                    width: 14
                    height: 14
                    radius: 7
                    color: root.severityColor(modelData.severity)
                    border.color: Qt.rgba(root.severityColor(modelData.severity).r,
                                          root.severityColor(modelData.severity).g,
                                          root.severityColor(modelData.severity).b, 0.3)
                    border.width: 3
                }

                // Timestamp on the left
                Text {
                    x: 0
                    y: ThemeManager.spacingSmall + 1
                    width: 28
                    text: modelData.time
                    font.pixelSize: ThemeManager.fontSizeXS
                    font.family: ThemeManager.fontFamilyMono
                    color: ThemeManager.textMuted
                    horizontalAlignment: Text.AlignRight
                }

                // Event content
                ColumnLayout {
                    id: eventContent
                    x: 60
                    y: ThemeManager.spacingSmall - 2
                    width: parent.width - 68
                    spacing: 2

                    Text {
                        text: modelData.title
                        font.pixelSize: ThemeManager.fontSizeBody
                        font.weight: Font.Medium
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                        Layout.fillWidth: true
                    }

                    Text {
                        text: modelData.description
                        font.pixelSize: ThemeManager.fontSizeSmall
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }
        }
    }
}
