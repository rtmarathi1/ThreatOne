import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Circular gauge showing overall security score
Rectangle {
    id: widget
    radius: 12
    color: "#1a1a2e"
    border.color: "#2a2a4a"
    border.width: 1

    property double score: 85.0
    property string grade: score >= 90 ? "A+" :
                           score >= 80 ? "A" :
                           score >= 70 ? "B" :
                           score >= 60 ? "C" : "D"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16

        Text {
            text: "Security Score"
            font.pixelSize: 16
            font.bold: true
            color: "#ffffff"
        }

        // Circular gauge placeholder
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Rectangle {
                anchors.centerIn: parent
                width: Math.min(parent.width, parent.height) * 0.7
                height: width
                radius: width / 2
                color: "transparent"
                border.color: "#2a2a4a"
                border.width: 12

                Rectangle {
                    anchors.centerIn: parent
                    width: parent.width - 24
                    height: width
                    radius: width / 2
                    color: "transparent"
                    border.color: widget.score >= 80 ? "#4ade80" :
                                  widget.score >= 60 ? "#f59e0b" : "#ef4444"
                    border.width: 12
                }

                ColumnLayout {
                    anchors.centerIn: parent
                    spacing: 4

                    Text {
                        Layout.alignment: Qt.AlignHCenter
                        text: Math.round(widget.score).toString()
                        font.pixelSize: 42
                        font.bold: true
                        color: "#ffffff"
                    }

                    Text {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Grade: " + widget.grade
                        font.pixelSize: 14
                        color: "#8892b0"
                    }
                }
            }
        }
    }
}
