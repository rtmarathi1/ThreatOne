import QtQuick 2.15
import QtQuick.Window 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: mainWindow
    visible: true
    width: 1440
    height: 900
    minimumWidth: 1024
    minimumHeight: 768
    title: qsTr("ThreatOne Enterprise Cybersecurity Platform")
    color: ThemeManager.backgroundColor

    // Main layout with sidebar and content area
    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Navigation Sidebar
        NavigationSidebar {
            id: sidebar
            Layout.fillHeight: true
            Layout.preferredWidth: 260
            onPageSelected: function(page) {
                contentLoader.source = page
            }
        }

        // Main content area
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Top toolbar
            TopBar {
                id: topBar
                Layout.fillWidth: true
                Layout.preferredHeight: 64
            }

            // Page content loaded dynamically
            StackView {
                id: contentStack
                Layout.fillWidth: true
                Layout.fillHeight: true
                initialItem: "pages/dashboard/DashboardPage.qml"
            }

            Loader {
                id: contentLoader
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: false
            }
        }
    }

    // Application-level keyboard shortcuts
    Shortcut {
        sequence: "Ctrl+Q"
        onActivated: Qt.quit()
    }

    Shortcut {
        sequence: "F11"
        onActivated: {
            if (mainWindow.visibility === Window.FullScreen) {
                mainWindow.showNormal()
            } else {
                mainWindow.showFullScreen()
            }
        }
    }
}
