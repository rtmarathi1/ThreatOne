import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Global search bar with filter dropdown, recent searches, keyboard shortcut hint
Rectangle {
    id: root
    radius: ThemeManager.radiusFull
    color: ThemeManager.inputColor
    border.color: searchInput.activeFocus ? ThemeManager.primaryColor : ThemeManager.borderColor
    border.width: 1
    height: ThemeManager.inputHeight
    clip: true

    property string placeholder: "Search threats, assets, events..."
    property string text: searchInput.text
    property var filters: ["All", "Threats", "Assets", "Events", "Rules", "Users"]
    property int selectedFilter: 0
    property var recentSearches: ["CVE-2024-1234", "192.168.1.45", "svchost.exe"]
    property bool showRecent: false
    property string shortcutHint: "Ctrl+K"

    signal searchSubmitted(string query, string filter)
    signal cleared()

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 16
        anchors.rightMargin: 12
        spacing: 8

        // Search icon
        Text {
            text: "\uD83D\uDD0D"
            font.pixelSize: 14
            color: ThemeManager.textMuted
        }

        // Filter dropdown button
        Rectangle {
            width: filterLabel.implicitWidth + 20
            height: 24
            radius: ThemeManager.radiusSmall
            color: ThemeManager.hoverColor

            Text {
                id: filterLabel
                anchors.centerIn: parent
                text: root.filters[root.selectedFilter] + " \u25BE"
                font.pixelSize: ThemeManager.fontSizeXS
                font.weight: Font.Medium
                font.family: ThemeManager.fontFamily
                color: ThemeManager.primaryColor
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    root.selectedFilter = (root.selectedFilter + 1) % root.filters.length
                }
            }
        }

        // Text input
        TextInput {
            id: searchInput
            Layout.fillWidth: true
            font.pixelSize: ThemeManager.fontSizeNormal
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textPrimary
            clip: true
            selectByMouse: true

            Keys.onReturnPressed: root.searchSubmitted(text, root.filters[root.selectedFilter])
            Keys.onEscapePressed: {
                text = ""
                focus = false
            }

            onActiveFocusChanged: {
                root.showRecent = activeFocus && text === ""
            }
            onTextChanged: {
                root.showRecent = activeFocus && text === ""
            }

            // Placeholder text
            Text {
                anchors.fill: parent
                anchors.verticalCenter: parent.verticalCenter
                text: root.placeholder
                font.pixelSize: ThemeManager.fontSizeNormal
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
                visible: !searchInput.text && !searchInput.activeFocus
                verticalAlignment: Text.AlignVCenter
            }
        }

        // Keyboard shortcut hint
        Rectangle {
            visible: !searchInput.activeFocus && searchInput.text === ""
            width: hintText.implicitWidth + 10
            height: 20
            radius: ThemeManager.radiusSmall
            color: ThemeManager.hoverColor
            border.color: ThemeManager.borderColor
            border.width: 1

            Text {
                id: hintText
                anchors.centerIn: parent
                text: root.shortcutHint
                font.pixelSize: ThemeManager.fontSizeXS
                font.family: ThemeManager.fontFamilyMono
                color: ThemeManager.textMuted
            }
        }

        // Clear button
        Rectangle {
            visible: searchInput.text !== ""
            width: 20; height: 20; radius: 10
            color: ThemeManager.hoverColor

            Text {
                anchors.centerIn: parent
                text: "\u2715"
                font.pixelSize: 10
                color: ThemeManager.textSecondary
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    searchInput.text = ""
                    root.cleared()
                }
            }
        }
    }

    // Recent searches dropdown
    Rectangle {
        visible: root.showRecent && root.recentSearches.length > 0
        anchors.top: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 4
        height: recentColumn.implicitHeight + ThemeManager.spacingMedium * 2
        radius: ThemeManager.radiusMedium
        color: ThemeManager.surfaceColor
        border.color: ThemeManager.borderColor
        border.width: 1
        z: 100

        Column {
            id: recentColumn
            anchors.fill: parent
            anchors.margins: ThemeManager.spacingMedium
            spacing: 2

            Text {
                text: "Recent Searches"
                font.pixelSize: ThemeManager.fontSizeXS
                font.weight: Font.Medium
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
                bottomPadding: 4
            }

            Repeater {
                model: root.recentSearches
                Rectangle {
                    width: parent.width
                    height: 28
                    radius: ThemeManager.radiusSmall
                    color: "transparent"

                    Text {
                        anchors.left: parent.left
                        anchors.leftMargin: 8
                        anchors.verticalCenter: parent.verticalCenter
                        text: "\u23F1 " + modelData
                        font.pixelSize: ThemeManager.fontSizeBody
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        hoverEnabled: true
                        onEntered: parent.color = ThemeManager.hoverColor
                        onExited: parent.color = "transparent"
                        onClicked: {
                            searchInput.text = modelData
                            root.showRecent = false
                            root.searchSubmitted(modelData, root.filters[root.selectedFilter])
                        }
                    }
                }
            }
        }
    }
}
