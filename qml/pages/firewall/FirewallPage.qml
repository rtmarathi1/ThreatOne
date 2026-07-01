import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Firewall page with rules table and connection monitor
Rectangle {
    id: firewallPage
    color: "#0a0a1a"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 24

        // Page header
        RowLayout {
            Layout.fillWidth: true

            ColumnLayout {
                Text {
                    text: "Firewall Manager"
                    font.pixelSize: 28
                    font.bold: true
                    color: "#ffffff"
                }

                Text {
                    text: "Manage network rules and monitor connections"
                    font.pixelSize: 14
                    color: "#8892b0"
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                text: "+ Add Rule"
                onClicked: {}
            }
        }

        // Rules table
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 12
            color: "#1a1a2e"
            border.color: "#2a2a4a"
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 12

                // Table header
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 0

                    Text { Layout.preferredWidth: 80; text: "Status"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.fillWidth: true; text: "Rule Name"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.preferredWidth: 100; text: "Direction"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.preferredWidth: 80; text: "Protocol"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.preferredWidth: 120; text: "Source"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.preferredWidth: 120; text: "Destination"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                    Text { Layout.preferredWidth: 80; text: "Action"; font.pixelSize: 12; font.bold: true; color: "#8892b0" }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: "#2a2a4a"
                }

                // Placeholder rules list
                ListView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    model: rulesModel
                    clip: true

                    delegate: RowLayout {
                        width: parent.width
                        height: 40
                        spacing: 0

                        Rectangle {
                            Layout.preferredWidth: 80
                            height: parent.height
                            color: "transparent"
                            Rectangle {
                                anchors.centerIn: parent
                                width: 8; height: 8; radius: 4
                                color: model.enabled ? "#4ade80" : "#ef4444"
                            }
                        }
                        Text { Layout.fillWidth: true; text: model.name; font.pixelSize: 13; color: "#ffffff" }
                        Text { Layout.preferredWidth: 100; text: model.direction; font.pixelSize: 13; color: "#8892b0" }
                        Text { Layout.preferredWidth: 80; text: model.protocol; font.pixelSize: 13; color: "#8892b0" }
                        Text { Layout.preferredWidth: 120; text: model.source; font.pixelSize: 13; color: "#8892b0" }
                        Text { Layout.preferredWidth: 120; text: model.destination; font.pixelSize: 13; color: "#8892b0" }
                        Text { Layout.preferredWidth: 80; text: model.action; font.pixelSize: 13; color: model.action === "Block" ? "#ef4444" : "#4ade80" }
                    }
                }
            }
        }

        // Connection monitor summary
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 100
            radius: 12
            color: "#1a1a2e"
            border.color: "#2a2a4a"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 32

                ColumnLayout {
                    Text { text: "Active Connections"; font.pixelSize: 12; color: "#8892b0" }
                    Text { text: "142"; font.pixelSize: 24; font.bold: true; color: "#ffffff" }
                }
                ColumnLayout {
                    Text { text: "Blocked Today"; font.pixelSize: 12; color: "#8892b0" }
                    Text { text: "1,847"; font.pixelSize: 24; font.bold: true; color: "#ef4444" }
                }
                ColumnLayout {
                    Text { text: "Rules Active"; font.pixelSize: 12; color: "#8892b0" }
                    Text { text: "23"; font.pixelSize: 24; font.bold: true; color: "#4ade80" }
                }
                ColumnLayout {
                    Text { text: "Bandwidth"; font.pixelSize: 12; color: "#8892b0" }
                    Text { text: "45 MB/s"; font.pixelSize: 24; font.bold: true; color: "#00d4ff" }
                }
            }
        }
    }

    ListModel {
        id: rulesModel
        ListElement { name: "Block External SSH"; direction: "Inbound"; protocol: "TCP"; source: "0.0.0.0/0"; destination: ":22"; action: "Block"; enabled: true }
        ListElement { name: "Allow HTTPS Out"; direction: "Outbound"; protocol: "TCP"; source: "Any"; destination: ":443"; action: "Allow"; enabled: true }
        ListElement { name: "Block Telnet"; direction: "Inbound"; protocol: "TCP"; source: "0.0.0.0/0"; destination: ":23"; action: "Block"; enabled: true }
        ListElement { name: "Allow DNS"; direction: "Outbound"; protocol: "UDP"; source: "Any"; destination: ":53"; action: "Allow"; enabled: true }
        ListElement { name: "Block ICMP Flood"; direction: "Inbound"; protocol: "ICMP"; source: "0.0.0.0/0"; destination: "Any"; action: "Block"; enabled: false }
    }
}
