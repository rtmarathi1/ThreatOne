import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// World map placeholder showing threat origins
Rectangle {
    id: widget
    radius: 12
    color: "#1a1a2e"
    border.color: "#2a2a4a"
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16

        RowLayout {
            Layout.fillWidth: true

            Text {
                text: "Threat Map"
                font.pixelSize: 16
                font.bold: true
                color: "#ffffff"
            }

            Item { Layout.fillWidth: true }

            Text {
                text: "Live"
                font.pixelSize: 12
                color: "#4ade80"
            }

            Rectangle {
                width: 8; height: 8; radius: 4
                color: "#4ade80"
            }
        }

        // Map placeholder
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: "#0f1629"

            Text {
                anchors.centerIn: parent
                text: "World Threat Map\n(Visualization loads with Qt)"
                font.pixelSize: 14
                color: "#8892b0"
                horizontalAlignment: Text.AlignHCenter
            }

            // Simulated threat dots
            Repeater {
                model: 5
                Rectangle {
                    x: 50 + index * 60
                    y: 30 + (index % 3) * 40
                    width: 10; height: 10; radius: 5
                    color: "#ef4444"
                    opacity: 0.8

                    SequentialAnimation on opacity {
                        loops: Animation.Infinite
                        NumberAnimation { to: 0.3; duration: 1000 }
                        NumberAnimation { to: 0.8; duration: 1000 }
                    }
                }
            }
        }

        // Legend
        RowLayout {
            Layout.fillWidth: true
            spacing: 16

            Row {
                spacing: 4
                Rectangle { width: 8; height: 8; radius: 4; color: "#ef4444"; anchors.verticalCenter: parent.verticalCenter }
                Text { text: "Active Attacks"; font.pixelSize: 11; color: "#8892b0" }
            }
            Row {
                spacing: 4
                Rectangle { width: 8; height: 8; radius: 4; color: "#f59e0b"; anchors.verticalCenter: parent.verticalCenter }
                Text { text: "Suspicious"; font.pixelSize: 11; color: "#8892b0" }
            }
            Row {
                spacing: 4
                Rectangle { width: 8; height: 8; radius: 4; color: "#4ade80"; anchors.verticalCenter: parent.verticalCenter }
                Text { text: "Blocked"; font.pixelSize: 11; color: "#8892b0" }
            }
        }
    }
}
