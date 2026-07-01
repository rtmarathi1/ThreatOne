import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../widgets"

// Dashboard page with grid of security widgets
Rectangle {
    id: dashboardPage
    color: "#0a0a1a"

    ScrollView {
        anchors.fill: parent
        anchors.margins: 24
        clip: true

        ColumnLayout {
            width: parent.width
            spacing: 24

            // Page header
            Text {
                text: "Security Dashboard"
                font.pixelSize: 28
                font.bold: true
                color: "#ffffff"
            }

            Text {
                text: "Real-time overview of your security posture"
                font.pixelSize: 14
                color: "#8892b0"
            }

            // Top stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: 16

                StatCard { title: "Threats Blocked"; value: "1,247"; trend: "+12%"; trendPositive: true }
                StatCard { title: "Active Scans"; value: "3"; trend: ""; trendPositive: true }
                StatCard { title: "Open Incidents"; value: "7"; trend: "-2"; trendPositive: true }
                StatCard { title: "Security Score"; value: "85/100"; trend: "+5"; trendPositive: true }
            }

            // Widget grid
            GridLayout {
                Layout.fillWidth: true
                columns: 2
                rowSpacing: 16
                columnSpacing: 16

                SecurityScoreWidget {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                }

                ThreatMapWidget {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                }

                AlertsWidget {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                    Layout.columnSpan: 2
                }
            }
        }
    }

    // Stat card component
    component StatCard: Rectangle {
        property string title: ""
        property string value: ""
        property string trend: ""
        property bool trendPositive: true

        Layout.fillWidth: true
        Layout.preferredHeight: 100
        radius: 12
        color: "#1a1a2e"
        border.color: "#2a2a4a"
        border.width: 1

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 4

            Text {
                text: title
                font.pixelSize: 12
                color: "#8892b0"
            }

            Text {
                text: value
                font.pixelSize: 28
                font.bold: true
                color: "#ffffff"
            }

            Text {
                text: trend
                font.pixelSize: 12
                color: trendPositive ? "#4ade80" : "#ef4444"
                visible: trend.length > 0
            }
        }
    }
}
