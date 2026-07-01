import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Left sidebar with navigation icons for all major modules
Rectangle {
    id: sidebar
    color: "#1a1a2e"
    width: 260

    signal pageSelected(string page)

    property int currentIndex: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Logo/Brand area
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 64
            color: "#16213e"

            Text {
                anchors.centerIn: parent
                text: "ThreatOne"
                font.pixelSize: 20
                font.bold: true
                color: "#00d4ff"
            }
        }

        // Navigation items
        ListView {
            id: navList
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: navigationModel
            clip: true
            spacing: 2

            delegate: Rectangle {
                width: navList.width
                height: 44
                color: sidebar.currentIndex === index ? "#2a2a4a" : "transparent"
                radius: 4

                Row {
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    spacing: 12

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: model.icon
                        font.pixelSize: 18
                        color: sidebar.currentIndex === index ? "#00d4ff" : "#8892b0"
                    }

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: model.title
                        font.pixelSize: 14
                        color: sidebar.currentIndex === index ? "#ffffff" : "#8892b0"
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        sidebar.currentIndex = index
                        sidebar.pageSelected(model.page)
                    }
                }
            }
        }

        // Bottom status area
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 48
            color: "#16213e"

            Text {
                anchors.centerIn: parent
                text: "v1.0.0 | Protected"
                font.pixelSize: 11
                color: "#4ade80"
            }
        }
    }

    ListModel {
        id: navigationModel
        ListElement { title: "Dashboard"; icon: "\u2302"; page: "pages/dashboard/DashboardPage.qml" }
        ListElement { title: "Scanner"; icon: "\u2315"; page: "pages/scanner/ScannerPage.qml" }
        ListElement { title: "Firewall"; icon: "\u2616"; page: "pages/firewall/FirewallPage.qml" }
        ListElement { title: "Sandbox"; icon: "\u2610"; page: "pages/sandbox/SandboxPage.qml" }
        ListElement { title: "EDR"; icon: "\u2699"; page: "pages/edr/EDRPage.qml" }
        ListElement { title: "XDR"; icon: "\u2604"; page: "pages/xdr/XDRPage.qml" }
        ListElement { title: "SIEM"; icon: "\u2601"; page: "pages/siem/SIEMPage.qml" }
        ListElement { title: "Incidents"; icon: "\u26A0"; page: "pages/incidents/IncidentsPage.qml" }
        ListElement { title: "Assets"; icon: "\u2316"; page: "pages/assets/AssetsPage.qml" }
        ListElement { title: "Users"; icon: "\u263A"; page: "pages/users/UsersPage.qml" }
        ListElement { title: "Reports"; icon: "\u2637"; page: "pages/reports/ReportsPage.qml" }
        ListElement { title: "Settings"; icon: "\u2699"; page: "pages/settings/SettingsPage.qml" }
    }
}
