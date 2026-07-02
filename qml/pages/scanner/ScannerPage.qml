import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: scannerPage
    objectName: "scanner"
    color: ThemeManager.backgroundColor

    property var scannerViewModel: QtObject {
        property bool scanning: false
        property real progress: 0.0
        property int filesScanned: 12847
        property int threatsFound: 2
        property string elapsed: "00:03:27"
        property string eta: "00:12:15"
        property string currentFile: "/usr/lib/libc.so.6"
        property string scanType: "Full Scan"
    }

    property int currentTab: 0 // 0=launcher, 1=progress, 2=history, 3=results

    ScrollView {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingXL
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: ThemeManager.spacingXL

            // Header
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: ThemeManager.spacingXS
                    Text { text: "Threat Scanner"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Launch scans and review results"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
            }

            // Tab bar
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Scan Launcher", "Active Scan", "Scan History", "Results"]
                    Rectangle {
                        Layout.preferredHeight: 36
                        Layout.preferredWidth: tabLabel.implicitWidth + ThemeManager.spacingXL
                        radius: ThemeManager.radiusMedium
                        color: scannerPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: scannerPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor
                        border.width: 1
                        Text { id: tabLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: scannerPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: scannerPage.currentTab = index }
                    }
                }
            }

            // Tab content
            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 500
                sourceComponent: scannerPage.currentTab === 0 ? launcherTab :
                                 scannerPage.currentTab === 1 ? activeTab :
                                 scannerPage.currentTab === 2 ? historyTab : resultsTab
            }
        }
    }

    // Scan Launcher Tab
    Component {
        id: launcherTab
        GridLayout {
            columns: 3
            rowSpacing: ThemeManager.spacingNormal
            columnSpacing: ThemeManager.spacingNormal

            Repeater {
                model: ListModel {
                    ListElement { name: "Quick Scan"; desc: "Scan critical system areas and running processes"; duration: "~5 min"; iconText: "\u26A1"; scanColor: "#00d4ff" }
                    ListElement { name: "Full Scan"; desc: "Comprehensive scan of all files, registry, and boot sectors"; duration: "~45 min"; iconText: "\u2616"; scanColor: "#8b5cf6" }
                    ListElement { name: "Custom Scan"; desc: "Select specific directories, file types, and scan depth"; duration: "Varies"; iconText: "\u2699"; scanColor: "#3b82f6" }
                    ListElement { name: "Memory Scan"; desc: "Scan running processes and memory-resident threats"; duration: "~10 min"; iconText: "\u2318"; scanColor: "#f59e0b" }
                    ListElement { name: "IOC Scan"; desc: "Search for known indicators of compromise across the system"; duration: "~15 min"; iconText: "\uD83D\uDD0D"; scanColor: "#ef4444" }
                    ListElement { name: "YARA Scan"; desc: "Run custom YARA rules against files and processes"; duration: "Varies"; iconText: "\u2261"; scanColor: "#4ade80" }
                }
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 160
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        RowLayout {
                            Layout.fillWidth: true
                            Rectangle {
                                width: 36; height: 36; radius: ThemeManager.radiusMedium
                                color: model.scanColor
                                opacity: 0.15
                                Text { anchors.centerIn: parent; text: model.iconText; font.pixelSize: 16; color: model.scanColor }
                            }
                            Item { Layout.fillWidth: true }
                            Text { text: model.duration; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        }
                        Text { text: model.name; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                        Text { Layout.fillWidth: true; text: model.desc; font.pixelSize: ThemeManager.fontSizeSmall; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary; wrapMode: Text.WordWrap }
                        Item { Layout.fillHeight: true }
                        Rectangle {
                            Layout.fillWidth: true; height: 32; radius: ThemeManager.radiusMedium
                            color: ThemeManager.primaryColor
                            Text { anchors.centerIn: parent; text: "Start Scan"; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: ThemeManager.textOnPrimary }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { scannerPage.currentTab = 1 } }
                        }
                    }

                    MouseArea { anchors.fill: parent; z: -1; hoverEnabled: true; onEntered: parent.border.color = ThemeManager.primaryColor; onExited: parent.border.color = ThemeManager.borderColor }
                }
            }
        }
    }

    // Active Scan Tab
    Component {
        id: activeTab
        ColumnLayout {
            spacing: ThemeManager.spacingXL

            // Progress section
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 280
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                RowLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingXL
                    spacing: ThemeManager.spacingXL

                    ProgressRing {
                        Layout.preferredWidth: 180
                        Layout.preferredHeight: 180
                        progress: scannerViewModel.progress
                        label: scannerViewModel.scanType
                        running: scannerViewModel.scanning
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: ThemeManager.spacingMedium

                        Text { text: scannerViewModel.scanType + " in Progress"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }

                        GridLayout {
                            columns: 2
                            rowSpacing: ThemeManager.spacingSmall
                            columnSpacing: ThemeManager.spacingXXL

                            Text { text: "Files Scanned:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Text { text: scannerViewModel.filesScanned.toLocaleString(); font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: "Threats Found:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Text { text: scannerViewModel.threatsFound.toString(); font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: scannerViewModel.threatsFound > 0 ? ThemeManager.errorColor : ThemeManager.successColor; font.family: ThemeManager.fontFamily }
                            Text { text: "Elapsed Time:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Text { text: scannerViewModel.elapsed; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                            Text { text: "ETA:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            Text { text: scannerViewModel.eta; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamilyMono }
                        }

                        Text { text: "Current: " + scannerViewModel.currentFile; font.pixelSize: ThemeManager.fontSizeSmall; font.family: ThemeManager.fontFamilyMono; color: ThemeManager.textMuted; elide: Text.ElideMiddle; Layout.fillWidth: true }

                        RowLayout {
                            spacing: ThemeManager.spacingSmall
                            Rectangle { width: 90; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.warningColor; Text { anchors.centerIn: parent; text: "Pause"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: "#000000"; font.family: ThemeManager.fontFamily } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                            Rectangle { width: 90; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.errorColor; Text { anchors.centerIn: parent; text: "Stop"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: "#ffffff"; font.family: ThemeManager.fontFamily } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                        }
                    }
                }
            }

            // Real-time detection log
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 200
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingSmall

                    Text { text: "Detection Log"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

                    ListView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        model: ListModel {
                            ListElement { filePath: "/tmp/.cache/payload.bin"; threatName: "Trojan.Generic.Win32"; severity: "high"; action: "Quarantined" }
                            ListElement { filePath: "/home/user/Downloads/crack.exe"; threatName: "PUP.CoinMiner"; severity: "medium"; action: "Deleted" }
                        }
                        delegate: Rectangle {
                            width: ListView.view.width
                            height: 36
                            color: index % 2 === 0 ? "transparent" : ThemeManager.cardColor
                            radius: ThemeManager.radiusXS
                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: ThemeManager.spacingSmall
                                Rectangle { width: 6; height: 6; radius: 3; color: model.severity === "high" ? ThemeManager.errorColor : ThemeManager.warningColor }
                                Text { text: model.threatName; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.preferredWidth: 180 }
                                Text { text: model.filePath; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamilyMono; Layout.fillWidth: true; elide: Text.ElideMiddle }
                                Text { text: model.action; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.successColor; font.family: ThemeManager.fontFamily }
                            }
                        }
                    }
                }
            }
        }
    }

    // Scan History Tab
    Component {
        id: historyTab
        DataTable {
            title: "Scan History"
            columns: [
                { key: "date", label: "Date", width: 160 },
                { key: "type", label: "Scan Type", width: 140 },
                { key: "duration", label: "Duration", width: 100 },
                { key: "filesScanned", label: "Files", width: 100 },
                { key: "threats", label: "Threats", width: 80 },
                { key: "status", label: "Status", width: 100 }
            ]
            rows: [
                { date: "2024-12-15 14:30", type: "Full Scan", duration: "42:15", filesScanned: "245,891", threats: "0", status: "Clean" },
                { date: "2024-12-15 09:00", type: "Quick Scan", duration: "04:32", filesScanned: "12,847", threats: "2", status: "Threats Found" },
                { date: "2024-12-14 23:00", type: "Scheduled Full", duration: "48:03", filesScanned: "245,891", threats: "0", status: "Clean" },
                { date: "2024-12-14 16:45", type: "Memory Scan", duration: "08:12", filesScanned: "3,421", threats: "1", status: "Quarantined" },
                { date: "2024-12-14 10:00", type: "IOC Scan", duration: "12:33", filesScanned: "89,102", threats: "0", status: "Clean" },
                { date: "2024-12-13 22:00", type: "YARA Scan", duration: "15:47", filesScanned: "45,210", threats: "3", status: "Threats Found" },
                { date: "2024-12-13 14:00", type: "Quick Scan", duration: "05:01", filesScanned: "12,950", threats: "0", status: "Clean" },
                { date: "2024-12-12 23:00", type: "Scheduled Full", duration: "47:28", filesScanned: "245,100", threats: "1", status: "Quarantined" }
            ]
        }
    }

    // Results Tab
    Component {
        id: resultsTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            // Summary
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Threats"; value: "6"; trend: -15.0; icon: "\u26A0" }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Quarantined"; value: "4"; trend: 0; icon: "\u2616"; iconColor: ThemeManager.warningColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Deleted"; value: "2"; trend: 0; icon: "\u2715"; iconColor: ThemeManager.errorColor }
            }

            // Threat results cards
            ListView {
                Layout.fillWidth: true
                Layout.preferredHeight: 400
                clip: true
                spacing: ThemeManager.spacingSmall
                model: ListModel {
                    ListElement { threatName: "Trojan.Win32.Agent.bxf"; filePath: "/tmp/.cache/payload.bin"; severity: "critical"; action: "Quarantined"; mitre: "T1059.001 - PowerShell" }
                    ListElement { threatName: "PUP.Optional.CoinMiner"; filePath: "/home/user/Downloads/crack.exe"; severity: "high"; action: "Deleted"; mitre: "T1496 - Resource Hijacking" }
                    ListElement { threatName: "Adware.Generic.Browser"; filePath: "/opt/extensions/helper.dll"; severity: "medium"; action: "Quarantined"; mitre: "T1176 - Browser Extensions" }
                    ListElement { threatName: "Backdoor.Linux.Mirai.b"; filePath: "/var/tmp/.x"; severity: "critical"; action: "Deleted"; mitre: "T1090 - Connection Proxy" }
                    ListElement { threatName: "Rootkit.Linux.Agent"; filePath: "/lib/modules/hidden.ko"; severity: "critical"; action: "Quarantined"; mitre: "T1014 - Rootkit" }
                    ListElement { threatName: "Riskware.Keylogger"; filePath: "/usr/local/bin/kl"; severity: "high"; action: "Quarantined"; mitre: "T1056.001 - Keylogging" }
                }
                delegate: AlertCard {
                    width: ListView.view.width
                    severity: model.severity
                    title: model.threatName
                    description: "File: " + model.filePath + "  |  MITRE: " + model.mitre
                    source: model.action
                    timestamp: "Last scan"
                }
            }
        }
    }
}
