import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: settingsPage
    color: "#0a0a1a"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 24

        Text {
            text: "Settings"
            font.pixelSize: 28
            font.bold: true
            color: "#ffffff"
        }

        // Settings categories
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: settingsModel
            spacing: 8
            clip: true

            delegate: Rectangle {
                width: parent.width
                height: 72
                radius: 12
                color: "#1a1a2e"
                border.color: "#2a2a4a"
                border.width: 1

                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 16

                    Rectangle {
                        width: 40; height: 40
                        radius: 8
                        color: model.color

                        Text {
                            anchors.centerIn: parent
                            text: model.icon
                            font.pixelSize: 18
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: model.title
                            font.pixelSize: 15
                            font.bold: true
                            color: "#ffffff"
                        }
                        Text {
                            text: model.description
                            font.pixelSize: 12
                            color: "#8892b0"
                        }
                    }

                    Text {
                        text: ">"
                        font.pixelSize: 18
                        color: "#8892b0"
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                }
            }
        }
    }

    ListModel {
        id: settingsModel
        ListElement {
            title: "General"
            description: "Application preferences"
            icon: "\u2699"
            color: "#3b82f6"
        }
        ListElement {
            title: "Security"
            description: "Protection and scan settings"
            icon: "\u2616"
            color: "#ef4444"
        }
        ListElement {
            title: "Network"
            description: "Proxy, firewall, connections"
            icon: "\u2604"
            color: "#8b5cf6"
        }
        ListElement {
            title: "Updates"
            description: "Auto-update and channels"
            icon: "\u21BB"
            color: "#10b981"
        }
        ListElement {
            title: "License"
            description: "Activation and features"
            icon: "\u2605"
            color: "#f59e0b"
        }
        ListElement {
            title: "Notifications"
            description: "Alert preferences"
            icon: "\uD83D\uDD14"
            color: "#06b6d4"
        }
    }
}
