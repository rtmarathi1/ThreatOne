import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import "themes"
import "components"

// ThreatOne Enterprise - Main Application Window
// Production-quality Qt6 ApplicationWindow with StackView routing,
// responsive layout, page transitions, and keyboard shortcuts
ApplicationWindow {
    id: mainWindow
    visible: true
    width: 1440
    height: 900
    minimumWidth: 1024
    minimumHeight: 768
    title: qsTr("ThreatOne Enterprise Cybersecurity Platform")
    color: ThemeManager.backgroundColor

    // Track the current page path for duplicate-navigation guard
    property string currentPagePath: "pages/dashboard/DashboardPage.qml"

    // Responsive breakpoint: collapse sidebar when narrow
    property bool narrowMode: width < 1200

    onNarrowModeChanged: {
        if (narrowMode && !sidebar.collapsed) {
            sidebar.collapsed = true
        }
    }

    // Main layout: sidebar + content + status bar
    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Navigation Sidebar
            NavigationSidebar {
                id: sidebar
                Layout.fillHeight: true
                Layout.preferredWidth: sidebar.collapsed ? ThemeManager.sidebarCollapsedWidth : ThemeManager.sidebarExpandedWidth

                onPageSelected: function(page) {
                    if (mainWindow.currentPagePath === page)
                        return
                    contentStack.replace(page, {}, StackView.Transition)
                    mainWindow.currentPagePath = page
                    var idx = sidebar.currentIndex
                    if (idx >= 0 && idx < sidebar.flatItems.length) {
                        topBar.currentPageTitle = sidebar.flatItems[idx].title
                    }
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
                    Layout.preferredHeight: ThemeManager.topbarHeight
                    currentPageTitle: "Dashboard"
                    breadcrumb: "ThreatOne"
                }

                // Page content with StackView and transitions
                StackView {
                    id: contentStack
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    initialItem: "pages/dashboard/DashboardPage.qml"

                    // Page transition animations
                    pushEnter: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 0; to: 1
                            duration: ThemeManager.animNormal
                            easing.type: Easing.OutCubic
                        }
                        PropertyAnimation {
                            property: "x"
                            from: 30; to: 0
                            duration: ThemeManager.animMedium
                            easing.type: Easing.OutCubic
                        }
                    }
                    pushExit: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 1; to: 0
                            duration: ThemeManager.animFast
                        }
                    }
                    popEnter: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 0; to: 1
                            duration: ThemeManager.animNormal
                            easing.type: Easing.OutCubic
                        }
                        PropertyAnimation {
                            property: "x"
                            from: -30; to: 0
                            duration: ThemeManager.animMedium
                            easing.type: Easing.OutCubic
                        }
                    }
                    popExit: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 1; to: 0
                            duration: ThemeManager.animFast
                        }
                    }
                    replaceEnter: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 0; to: 1
                            duration: ThemeManager.animNormal
                            easing.type: Easing.OutCubic
                        }
                    }
                    replaceExit: Transition {
                        PropertyAnimation {
                            property: "opacity"
                            from: 1; to: 0
                            duration: ThemeManager.animFast
                        }
                    }
                }
            }
        }

        // Bottom status bar
        StatusBar {
            id: statusBar
            Layout.fillWidth: true
            Layout.preferredHeight: ThemeManager.statusBarHeight
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
            if (mainWindow.visibility === Window.FullScreen)
                mainWindow.showNormal()
            else
                mainWindow.showFullScreen()
        }
    }

    Shortcut {
        sequence: "Ctrl+B"
        onActivated: sidebar.collapsed = !sidebar.collapsed
    }

    // Number key navigation shortcuts (Ctrl+1 through Ctrl+9)
    Shortcut {
        sequence: "Ctrl+1"
        onActivated: navigateToIndex(0)
    }
    Shortcut {
        sequence: "Ctrl+2"
        onActivated: navigateToIndex(1)
    }
    Shortcut {
        sequence: "Ctrl+3"
        onActivated: navigateToIndex(2)
    }
    Shortcut {
        sequence: "Ctrl+4"
        onActivated: navigateToIndex(3)
    }
    Shortcut {
        sequence: "Ctrl+5"
        onActivated: navigateToIndex(4)
    }
    Shortcut {
        sequence: "Ctrl+6"
        onActivated: navigateToIndex(5)
    }
    Shortcut {
        sequence: "Ctrl+7"
        onActivated: navigateToIndex(6)
    }
    Shortcut {
        sequence: "Ctrl+8"
        onActivated: navigateToIndex(7)
    }
    Shortcut {
        sequence: "Ctrl+9"
        onActivated: navigateToIndex(8)
    }

    function navigateToIndex(idx) {
        if (idx >= 0 && idx < sidebar.flatItems.length) {
            sidebar.currentIndex = idx
            sidebar.pageSelected(sidebar.flatItems[idx].page)
        }
    }
}
