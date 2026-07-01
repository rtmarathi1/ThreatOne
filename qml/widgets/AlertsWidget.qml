import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Recent alerts list widget
Rectangle {
    id: widget
    radius: 12
    color: "#1a1a2e"
    border.color: "#2a2a4a"
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 12

        RowLayout {
            Layout.fillWidth: true

            Text {
                text: "Recent Alerts"
                font.pixelSize: 16
                font.bold: true
                color: "#ffffff"
            }

            Item { Layout.fillWidth: true }

            Text {
                text: "View All"
                font.pixelSize: 12
                color: "#00d4ff"

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                }
            }
        }

        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: alertsModel
            clip: true
            spacing: 8

            delegate: Rectangle {
                width: parent.width
                height: 56
                radius: 8
                color: "#0f1629"

                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 12

                    Rectangle {
                        width: 32; height: 32; radius: 16
                        color: model.severity === "critical" ? "#ef4444" :
                               model.severity === "high" ? "#f59e0b" :
                               model.severity === "medium" ? "#3b82f6" : "#4ade80"
                        opacity: 0.2

                        Text {
                            anchors.centerIn: parent
                            text: "!"
                            font.pixelSize: 14
                            font.bold: true
                            color: model.severity === "critical" ? "#ef4444" :
                                   model.severity === "high" ? "#f59e0b" :
                                   model.severity === "medium" ? "#3b82f6" : "#4ade80"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2

                        Text {
                            text: model.title
                            font.pixelSize: 13
                            color: "#ffffff"
                            elide: Text.ElideRight
                        }

                        Text {
                            text: model.source + " - " + model.time
                            font.pixelSize: 11
                            color: "#8892b0"
                        }
                    }

                    Text {
                        text: model.severity
                        font.pixelSize: 11
                        font.bold: true
                        color: model.severity === "critical" ? "#ef4444" :
                               model.severity === "high" ? "#f59e0b" :
                               model.severity === "medium" ? "#3b82f6" : "#4ade80"
                    }
                }
            }
        }
    }

    ListModel {
        id: alertsModel
        ListElement {
            title: "Suspicious process detected: svchost_x86.exe"
            severity: "critical"
            source: "EDR"
            time: "2 min ago"
        }
        ListElement {
            title: "Multiple failed login attempts from 192.168.1.45"
            severity: "high"
            source: "SIEM"
            time: "5 min ago"
        }
        ListElement {
            title: "Outbound connection to known C2 server blocked"
            severity: "critical"
            source: "Firewall"
            time: "8 min ago"
        }
        ListElement {
            title: "File integrity change: /etc/passwd"
            severity: "high"
            source: "HIDS"
            time: "12 min ago"
        }
        ListElement {
            title: "New vulnerability discovered: CVE-2024-1234"
            severity: "medium"
            source: "Scanner"
            time: "15 min ago"
        }
    }
}
