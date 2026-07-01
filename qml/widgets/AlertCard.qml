import QtQuick
import QtQuick.Layouts
import "../themes"

// Severity-colored alert card with icon, title, description, timestamp, source badge
Rectangle {
    id: root
    radius: ThemeManager.radiusMedium
    color: ThemeManager.cardColor
    border.color: severityBorderColor
    border.width: 1
    height: contentColumn.implicitHeight + ThemeManager.spacingLarge * 2

    // Public properties
    property string severity: "medium" // critical, high, medium, low, info
    property string title: "Alert Title"
    property string description: "Alert description goes here"
    property string source: "EDR"
    property string timestamp: "2 min ago"
    property bool showActions: true

    // Derived colors
    property color severityColor: severity === "critical" ? ThemeManager.severityCritical :
                                  severity === "high" ? ThemeManager.severityHigh :
                                  severity === "medium" ? ThemeManager.severityMedium :
                                  severity === "low" ? ThemeManager.severityLow :
                                  ThemeManager.severityInfo

    property color severityBorderColor: Qt.rgba(severityColor.r, severityColor.g, severityColor.b, 0.3)

    property string severityIcon: severity === "critical" ? "\u2620" :
                                  severity === "high" ? "\u26A0" :
                                  severity === "medium" ? "\u26A1" :
                                  severity === "low" ? "\u2139" : "\u2022"

    signal dismissed()
    signal clicked()

    // Left severity accent bar
    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 4
        radius: 2
        color: root.severityColor
    }

    ColumnLayout {
        id: contentColumn
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        anchors.leftMargin: ThemeManager.spacingLarge + 8
        spacing: ThemeManager.spacingSmall

        // Header row: severity icon, title, timestamp
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingSmall

            // Severity dot
            Rectangle {
                width: 28
                height: 28
                radius: 14
                color: Qt.rgba(root.severityColor.r, root.severityColor.g, root.severityColor.b, 0.15)

                Text {
                    anchors.centerIn: parent
                    text: root.severityIcon
                    font.pixelSize: 14
                    color: root.severityColor
                }
            }

            // Title
            Text {
                Layout.fillWidth: true
                text: root.title
                font.pixelSize: ThemeManager.fontSizeNormal
                font.weight: Font.DemiBold
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textPrimary
                elide: Text.ElideRight
                maximumLineCount: 1
            }

            // Timestamp
            Text {
                text: root.timestamp
                font.pixelSize: ThemeManager.fontSizeSmall
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
            }
        }

        // Description
        Text {
            Layout.fillWidth: true
            text: root.description
            font.pixelSize: ThemeManager.fontSizeBody
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textSecondary
            wrapMode: Text.WordWrap
            maximumLineCount: 2
            elide: Text.ElideRight
        }

        // Footer: source badge + severity label + actions
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingSmall

            // Source badge
            Rectangle {
                width: sourceLbl.implicitWidth + 12
                height: 20
                radius: ThemeManager.radiusSmall
                color: ThemeManager.primaryColor
                opacity: 0.15

                Text {
                    id: sourceLbl
                    anchors.centerIn: parent
                    text: root.source
                    font.pixelSize: ThemeManager.fontSizeXS
                    font.weight: Font.Medium
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.primaryColor
                }
            }

            // Severity label
            Rectangle {
                width: sevLbl.implicitWidth + 12
                height: 20
                radius: ThemeManager.radiusSmall
                color: Qt.rgba(root.severityColor.r, root.severityColor.g, root.severityColor.b, 0.15)

                Text {
                    id: sevLbl
                    anchors.centerIn: parent
                    text: root.severity.charAt(0).toUpperCase() + root.severity.slice(1)
                    font.pixelSize: ThemeManager.fontSizeXS
                    font.weight: Font.Medium
                    font.family: ThemeManager.fontFamily
                    color: root.severityColor
                }
            }

            Item { Layout.fillWidth: true }

            // Dismiss action
            Text {
                visible: root.showActions
                text: "Dismiss"
                font.pixelSize: ThemeManager.fontSizeSmall
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.dismissed()
                }
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        z: -1
        cursorShape: Qt.PointingHandCursor
        hoverEnabled: true
        onClicked: root.clicked()
        onEntered: root.color = ThemeManager.hoverColor
        onExited: root.color = ThemeManager.cardColor
    }
}
