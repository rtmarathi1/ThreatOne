import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Scanner page with scan type selection and progress
Rectangle {
    id: scannerPage
    color: "#0a0a1a"

    property bool scanning: false
    property double scanProgress: 0.0

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 24

        // Page header
        Text {
            text: "Threat Scanner"
            font.pixelSize: 28
            font.bold: true
            color: "#ffffff"
        }

        Text {
            text: "Select a scan type and target to begin"
            font.pixelSize: 14
            color: "#8892b0"
        }

        // Scan type selection
        GridLayout {
            Layout.fillWidth: true
            columns: 4
            rowSpacing: 16
            columnSpacing: 16

            Repeater {
                model: [
                    { name: "Quick Scan", desc: "Scan critical areas", duration: "~5 min" },
                    { name: "Full Scan", desc: "Complete system scan", duration: "~45 min" },
                    { name: "Memory Scan", desc: "Scan running processes", duration: "~10 min" },
                    { name: "Rootkit Scan", desc: "Deep rootkit detection", duration: "~20 min" },
                    { name: "Custom Scan", desc: "Choose specific targets", duration: "Varies" },
                    { name: "Network Scan", desc: "Scan network devices", duration: "~15 min" },
                    { name: "Container Scan", desc: "Scan Docker containers", duration: "~10 min" },
                    { name: "YARA Scan", desc: "Custom YARA rules", duration: "Varies" }
                ]

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    radius: 12
                    color: "#1a1a2e"
                    border.color: "#2a2a4a"
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 4

                        Text {
                            text: modelData.name
                            font.pixelSize: 16
                            font.bold: true
                            color: "#ffffff"
                        }

                        Text {
                            text: modelData.desc
                            font.pixelSize: 12
                            color: "#8892b0"
                        }

                        Item { Layout.fillHeight: true }

                        Text {
                            text: modelData.duration
                            font.pixelSize: 11
                            color: "#00d4ff"
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: scannerPage.scanning = true
                    }
                }
            }
        }

        // Scan progress area
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 200
            radius: 12
            color: "#1a1a2e"
            border.color: "#2a2a4a"
            border.width: 1
            visible: scannerPage.scanning

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 24
                spacing: 16

                Text {
                    text: "Scanning in progress..."
                    font.pixelSize: 18
                    font.bold: true
                    color: "#ffffff"
                }

                ProgressBar {
                    Layout.fillWidth: true
                    value: scannerPage.scanProgress
                    from: 0
                    to: 100
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 32

                    Text { text: "Files scanned: 12,847"; font.pixelSize: 12; color: "#8892b0" }
                    Text { text: "Threats found: 0"; font.pixelSize: 12; color: "#4ade80" }
                    Text { text: "Elapsed: 00:03:27"; font.pixelSize: 12; color: "#8892b0" }
                }

                RowLayout {
                    spacing: 12
                    Button {
                        text: "Pause"
                        onClicked: {}
                    }
                    Button {
                        text: "Stop"
                        onClicked: scannerPage.scanning = false
                    }
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
