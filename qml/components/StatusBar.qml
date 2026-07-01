import QtQuick
import QtQuick.Layouts
import "../themes"

// Bottom status bar with connection status, last scan time, protection status,
// CPU/memory indicators, update badge
Rectangle {
    id: statusBar
    color: ThemeManager.darkMode ? "#0a0a1a" : "#f1f5f9"
    height: ThemeManager.statusBarHeight
    border.color: ThemeManager.borderColor
    border.width: 0

    property bool connected: true
    property string lastScanTime: "14:32"
    property bool protectionActive: true
    property real cpuUsage: 0.23
    property real memoryUsage: 0.45
    property bool updateAvailable: true

    // Top border
    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        height: 1
        color: ThemeManager.borderColor
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: ThemeManager.spacingNormal
        anchors.rightMargin: ThemeManager.spacingNormal
        spacing: ThemeManager.spacingLarge

        // Connection status
        Row {
            spacing: 6
            Layout.alignment: Qt.AlignVCenter

            Rectangle {
                width: 6; height: 6; radius: 3
                color: statusBar.connected ? ThemeManager.successColor : ThemeManager.errorColor
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                text: statusBar.connected ? "Connected" : "Disconnected"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textSecondary
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        // Separator
        Rectangle { width: 1; height: 16; color: ThemeManager.borderColor; Layout.alignment: Qt.AlignVCenter }

        // Last scan
        Text {
            text: "Last Scan: " + statusBar.lastScanTime
            font.pixelSize: ThemeManager.fontSizeXS
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textSecondary
        }

        // Separator
        Rectangle { width: 1; height: 16; color: ThemeManager.borderColor; Layout.alignment: Qt.AlignVCenter }

        // Protection status
        Row {
            spacing: 4
            Layout.alignment: Qt.AlignVCenter

            Text {
                text: statusBar.protectionActive ? "\u2713" : "\u2717"
                font.pixelSize: 11
                color: statusBar.protectionActive ? ThemeManager.successColor : ThemeManager.errorColor
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                text: statusBar.protectionActive ? "Protection Active" : "Protection Off"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamily
                color: statusBar.protectionActive ? ThemeManager.successColor : ThemeManager.errorColor
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        Item { Layout.fillWidth: true }

        // CPU usage
        Row {
            spacing: 4
            Layout.alignment: Qt.AlignVCenter

            Text {
                text: "CPU"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
                anchors.verticalCenter: parent.verticalCenter
            }

            Rectangle {
                width: 40; height: 4; radius: 2
                color: ThemeManager.borderColor
                anchors.verticalCenter: parent.verticalCenter

                Rectangle {
                    width: parent.width * statusBar.cpuUsage
                    height: parent.height; radius: 2
                    color: statusBar.cpuUsage > 0.8 ? ThemeManager.errorColor :
                           statusBar.cpuUsage > 0.6 ? ThemeManager.warningColor :
                           ThemeManager.successColor
                }
            }

            Text {
                text: Math.round(statusBar.cpuUsage * 100) + "%"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamilyMono
                color: ThemeManager.textSecondary
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        // Memory usage
        Row {
            spacing: 4
            Layout.alignment: Qt.AlignVCenter

            Text {
                text: "MEM"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
                anchors.verticalCenter: parent.verticalCenter
            }

            Rectangle {
                width: 40; height: 4; radius: 2
                color: ThemeManager.borderColor
                anchors.verticalCenter: parent.verticalCenter

                Rectangle {
                    width: parent.width * statusBar.memoryUsage
                    height: parent.height; radius: 2
                    color: statusBar.memoryUsage > 0.8 ? ThemeManager.errorColor :
                           statusBar.memoryUsage > 0.6 ? ThemeManager.warningColor :
                           ThemeManager.successColor
                }
            }

            Text {
                text: Math.round(statusBar.memoryUsage * 100) + "%"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamilyMono
                color: ThemeManager.textSecondary
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        // Separator
        Rectangle { width: 1; height: 16; color: ThemeManager.borderColor; Layout.alignment: Qt.AlignVCenter }

        // Update available badge
        Rectangle {
            visible: statusBar.updateAvailable
            width: updateText.implicitWidth + 12
            height: 18
            radius: ThemeManager.radiusSmall
            color: ThemeManager.primaryColor
            opacity: 0.15
            Layout.alignment: Qt.AlignVCenter

            Text {
                id: updateText
                anchors.centerIn: parent
                text: "\u2191 Update Available"
                font.pixelSize: ThemeManager.fontSizeXS
                font.weight: Font.Medium
                font.family: ThemeManager.fontFamily
                color: ThemeManager.primaryColor
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
            }
        }
    }
}
