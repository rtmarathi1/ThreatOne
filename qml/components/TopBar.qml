import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../themes"

// Enhanced top toolbar with breadcrumb, search, notifications, user menu, theme toggle
Rectangle {
    id: topBar
    color: ThemeManager.topbarColor
    height: ThemeManager.topbarHeight
    border.color: ThemeManager.borderColor
    border.width: 0

    property string currentPageTitle: "Dashboard"
    property string breadcrumb: "Home"
    property int notificationCount: 3
    property bool notificationPanelOpen: false
    property bool userMenuOpen: false

    signal themeToggled()
    signal searchTriggered(string query)

    // Bottom border
    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: 1
        color: ThemeManager.borderColor
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: ThemeManager.spacingXL
        anchors.rightMargin: ThemeManager.spacingXL
        spacing: ThemeManager.spacingNormal

        // Breadcrumb path
        RowLayout {
            spacing: ThemeManager.spacingXS

            Text {
                text: topBar.breadcrumb
                font.pixelSize: ThemeManager.fontSizeBody
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
            }

            Text {
                text: "\u203A"
                font.pixelSize: ThemeManager.fontSizeBody
                color: ThemeManager.textMuted
            }

            Text {
                text: topBar.currentPageTitle
                font.pixelSize: ThemeManager.fontSizeBody
                font.weight: Font.Medium
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textPrimary
            }
        }

        Item { Layout.fillWidth: true }

        // Global search bar
        Rectangle {
            Layout.preferredWidth: 320
            Layout.preferredHeight: 36
            radius: ThemeManager.radiusFull
            color: ThemeManager.inputColor
            border.color: globalSearch.activeFocus ? ThemeManager.primaryColor : ThemeManager.borderColor
            border.width: 1

            // Subtle gradient overlay on focus
            Rectangle {
                anchors.fill: parent
                radius: parent.radius
                opacity: globalSearch.activeFocus ? 1.0 : 0.0
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.05) }
                    GradientStop { position: 1.0; color: "transparent" }
                }
                Behavior on opacity { NumberAnimation { duration: 200 } }
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 14
                anchors.rightMargin: 14
                spacing: 8

                Text {
                    text: "\uD83D\uDD0D"
                    font.pixelSize: 13
                    color: ThemeManager.textMuted
                }

                TextInput {
                    id: globalSearch
                    Layout.fillWidth: true
                    font.pixelSize: ThemeManager.fontSizeBody
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textPrimary
                    clip: true
                    selectByMouse: true

                    Keys.onReturnPressed: topBar.searchTriggered(text)

                    Text {
                        anchors.fill: parent
                        text: "Search..."
                        font.pixelSize: ThemeManager.fontSizeBody
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textMuted
                        visible: !globalSearch.text && !globalSearch.activeFocus
                        verticalAlignment: Text.AlignVCenter
                    }
                }

                // Shortcut hint
                Rectangle {
                    visible: !globalSearch.activeFocus
                    width: kbdText.implicitWidth + 8
                    height: 18
                    radius: 3
                    color: ThemeManager.hoverColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    Text {
                        id: kbdText
                        anchors.centerIn: parent
                        text: "Ctrl+K"
                        font.pixelSize: 9
                        font.family: ThemeManager.fontFamilyMono
                        color: ThemeManager.textMuted
                    }
                }
            }
        }

        Item { Layout.preferredWidth: ThemeManager.spacingSmall }

        // System status indicators
        Row {
            spacing: ThemeManager.spacingSmall

            // Connection status dot
            Rectangle {
                width: 8; height: 8; radius: 4
                color: ThemeManager.successColor
                anchors.verticalCenter: parent.verticalCenter

                SequentialAnimation on opacity {
                    loops: Animation.Infinite
                    NumberAnimation { to: 0.4; duration: 1500 }
                    NumberAnimation { to: 1.0; duration: 1500 }
                }
            }

            Text {
                text: "Live"
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamily
                color: ThemeManager.successColor
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        // Theme toggle button
        Rectangle {
            width: 36; height: 36; radius: 18
            color: themeToggleArea.containsMouse ? ThemeManager.hoverColor : "transparent"

            Text {
                anchors.centerIn: parent
                text: ThemeManager.darkMode ? "\u263D" : "\u2600"
                font.pixelSize: 18
                color: ThemeManager.textSecondary
            }

            MouseArea {
                id: themeToggleArea
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: {
                    ThemeManager.toggleTheme()
                    topBar.themeToggled()
                }
            }
        }

        // Notification bell
        Rectangle {
            width: 36; height: 36; radius: 18
            color: notifArea.containsMouse ? ThemeManager.hoverColor : "transparent"

            Text {
                anchors.centerIn: parent
                text: "\uD83D\uDD14"
                font.pixelSize: 17
                color: ThemeManager.textSecondary
            }

            // Badge
            Rectangle {
                anchors.top: parent.top
                anchors.right: parent.right
                anchors.topMargin: 2
                anchors.rightMargin: 2
                width: 16; height: 16; radius: 8
                color: ThemeManager.errorColor
                visible: topBar.notificationCount > 0

                Text {
                    anchors.centerIn: parent
                    text: topBar.notificationCount.toString()
                    font.pixelSize: 9
                    font.weight: Font.Bold
                    font.family: ThemeManager.fontFamily
                    color: "#ffffff"
                }
            }

            MouseArea {
                id: notifArea
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: topBar.notificationPanelOpen = !topBar.notificationPanelOpen
            }
        }

        // User avatar with dropdown
        Rectangle {
            width: 36; height: 36; radius: 18
            color: ThemeManager.primaryColor

            Text {
                anchors.centerIn: parent
                text: "AD"
                font.pixelSize: 13
                font.weight: Font.Bold
                font.family: ThemeManager.fontFamily
                color: ThemeManager.darkMode ? "#0a0a1a" : "#ffffff"
            }

            MouseArea {
                id: userArea
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: topBar.userMenuOpen = !topBar.userMenuOpen
            }
        }
    }

    // Notification dropdown panel
    Rectangle {
        id: notificationPanel
        visible: opacity > 0
        opacity: topBar.notificationPanelOpen ? 1.0 : 0.0
        anchors.right: parent.right
        anchors.top: parent.bottom
        anchors.rightMargin: 80
        anchors.topMargin: topBar.notificationPanelOpen ? 4 : -10
        width: 320
        height: notifContent.implicitHeight + ThemeManager.spacingLarge * 2
        radius: ThemeManager.radiusLarge
        color: ThemeManager.surfaceColor
        border.color: ThemeManager.borderColor
        border.width: 1
        z: 1000

        Behavior on opacity { NumberAnimation { duration: 200; easing.type: Easing.OutCubic } }
        Behavior on anchors.topMargin { NumberAnimation { duration: 200; easing.type: Easing.OutCubic } }

        ColumnLayout {
            id: notifContent
            anchors.fill: parent
            anchors.margins: ThemeManager.spacingLarge
            spacing: ThemeManager.spacingMedium
            enabled: topBar.notificationPanelOpen

            RowLayout {
                Layout.fillWidth: true

                Text {
                    text: "Notifications"
                    font.pixelSize: ThemeManager.fontSizeMedium
                    font.weight: Font.DemiBold
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textPrimary
                }

                Item { Layout.fillWidth: true }

                Text {
                    text: "Mark all read"
                    font.pixelSize: ThemeManager.fontSizeSmall
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.primaryColor

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: topBar.notificationCount = 0
                    }
                }
            }

            // Sample notifications
            Repeater {
                model: [
                    { title: "Critical alert: Malware detected", time: "2m ago", severity: "critical" },
                    { title: "Scan completed: 3 threats found", time: "15m ago", severity: "high" },
                    { title: "Firewall rule updated", time: "1h ago", severity: "info" }
                ]

                Rectangle {
                    Layout.fillWidth: true
                    height: 52
                    radius: ThemeManager.radiusMedium
                    color: ThemeManager.cardColor

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingSmall
                        spacing: ThemeManager.spacingSmall

                        Rectangle {
                            width: 8; height: 8; radius: 4
                            color: modelData.severity === "critical" ? ThemeManager.errorColor :
                                   modelData.severity === "high" ? ThemeManager.warningColor :
                                   ThemeManager.severityInfo
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Text {
                                text: modelData.title
                                font.pixelSize: ThemeManager.fontSizeSmall
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textPrimary
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }

                            Text {
                                text: modelData.time
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

    // User menu dropdown
    Rectangle {
        id: userMenuPanel
        visible: opacity > 0
        opacity: topBar.userMenuOpen ? 1.0 : 0.0
        anchors.right: parent.right
        anchors.top: parent.bottom
        anchors.rightMargin: 20
        anchors.topMargin: topBar.userMenuOpen ? 4 : -10
        width: 180
        height: userMenuCol.implicitHeight + ThemeManager.spacingMedium * 2
        radius: ThemeManager.radiusLarge
        color: ThemeManager.surfaceColor
        border.color: ThemeManager.borderColor
        border.width: 1
        z: 1000

        Behavior on opacity { NumberAnimation { duration: 200; easing.type: Easing.OutCubic } }
        Behavior on anchors.topMargin { NumberAnimation { duration: 200; easing.type: Easing.OutCubic } }

        Column {
            id: userMenuCol
            anchors.fill: parent
            anchors.margins: ThemeManager.spacingMedium
            spacing: 2
            enabled: topBar.userMenuOpen

            Repeater {
                model: [
                    { label: "Profile", icon: "\u263A" },
                    { label: "Preferences", icon: "\u2699" },
                    { label: "Help", icon: "\u2753" },
                    { label: "Logout", icon: "\u2192" }
                ]

                Rectangle {
                    width: parent.width
                    height: 32
                    radius: ThemeManager.radiusSmall
                    color: "transparent"

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: ThemeManager.spacingSmall
                        spacing: ThemeManager.spacingSmall

                        Text {
                            text: modelData.icon
                            font.pixelSize: 14
                            color: ThemeManager.textSecondary
                        }

                        Text {
                            text: modelData.label
                            font.pixelSize: ThemeManager.fontSizeBody
                            font.family: ThemeManager.fontFamily
                            color: modelData.label === "Logout" ? ThemeManager.errorColor : ThemeManager.textPrimary
                            Layout.fillWidth: true
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        hoverEnabled: true
                        onEntered: parent.color = ThemeManager.hoverColor
                        onExited: parent.color = "transparent"
                        onClicked: topBar.userMenuOpen = false
                    }
                }
            }
        }
    }

    // Global shortcut for search focus
    Shortcut {
        sequence: "Ctrl+K"
        onActivated: globalSearch.forceActiveFocus()
    }
}
