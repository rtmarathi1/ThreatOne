import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Top toolbar with search, notifications, and user profile
Rectangle {
    id: topBar
    color: "#0f3460"
    height: 64

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 24
        anchors.rightMargin: 24
        spacing: 16

        // Search bar
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 40
            Layout.maximumWidth: 500
            radius: 20
            color: "#1a1a2e"
            border.color: "#2a2a4a"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                spacing: 8

                Text {
                    text: "\uD83D\uDD0D"
                    font.pixelSize: 14
                    color: "#8892b0"
                }

                TextInput {
                    id: searchInput
                    Layout.fillWidth: true
                    font.pixelSize: 14
                    color: "#ffffff"
                    clip: true

                    Text {
                        anchors.fill: parent
                        text: "Search threats, assets, events..."
                        font.pixelSize: 14
                        color: "#8892b0"
                        visible: !searchInput.text && !searchInput.activeFocus
                    }
                }
            }
        }

        Item { Layout.fillWidth: true }

        // Notifications bell
        Rectangle {
            width: 40
            height: 40
            radius: 20
            color: "#1a1a2e"

            Text {
                anchors.centerIn: parent
                text: "\uD83D\uDD14"
                font.pixelSize: 18
            }

            // Notification badge
            Rectangle {
                anchors.top: parent.top
                anchors.right: parent.right
                anchors.topMargin: -2
                anchors.rightMargin: -2
                width: 18
                height: 18
                radius: 9
                color: "#ef4444"
                visible: notificationCount > 0

                property int notificationCount: 3

                Text {
                    anchors.centerIn: parent
                    text: parent.notificationCount.toString()
                    font.pixelSize: 10
                    font.bold: true
                    color: "#ffffff"
                }
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    // Open notifications panel
                }
            }
        }

        // User avatar
        Rectangle {
            width: 40
            height: 40
            radius: 20
            color: "#00d4ff"

            Text {
                anchors.centerIn: parent
                text: "AD"
                font.pixelSize: 14
                font.bold: true
                color: "#1a1a2e"
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    // Open user menu
                }
            }
        }
    }
}
