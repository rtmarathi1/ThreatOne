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
        property int filesScanned: 0
        property int threatsFound: 0
        property string elapsed: "00:00:00"
        property string eta: "--:--:--"
        property string currentFile: ""
        property string scanType: "Full Scan"
    }

    // Realistic file paths for scan simulation
    property var scanFilePaths: [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/bin/systemctl",
        "/etc/shadow",
        "/home/user/.ssh/authorized_keys",
        "/var/log/auth.log",
        "/usr/share/applications/firefox.desktop",
        "/opt/threatone/bin/engine",
        "/tmp/.cache/session_data",
        "/proc/self/maps",
        "/sys/kernel/security/apparmor/profiles",
        "/usr/lib/python3/dist-packages/pip/__init__.py",
        "/var/lib/docker/overlay2/layer/diff",
        "/etc/systemd/system/multi-user.target.wants",
        "/usr/local/share/ca-certificates/corp.crt",
        "/home/user/Documents/report_q4.xlsx",
        "/dev/shm/.hidden_proc",
        "/usr/lib/modules/5.15.0/kernel/drivers/net",
        "/boot/vmlinuz-5.15.0-generic",
        "/run/user/1000/dbus-session",
        "/snap/core22/current/usr/lib/snapd"
    ]

    // Scan elapsed time tracking
    property int scanElapsedSeconds: 0

    // Scan simulation timer
    Timer {
        id: scanTimer
        interval: 200
        running: scannerViewModel.scanning
        repeat: true
        onTriggered: {
            // Increment progress by random amount
            var increment = 0.005 + Math.random() * 0.015
            scannerViewModel.progress = Math.min(scannerViewModel.progress + increment, 1.0)

            // Increment files scanned
            scannerViewModel.filesScanned += Math.floor(50 + Math.random() * 150)

            // 1% chance to find a threat
            if (Math.random() < 0.01) {
                scannerViewModel.threatsFound += 1
            }

            // Cycle current file path
            var fileIdx = Math.floor(Math.random() * scannerPage.scanFilePaths.length)
            scannerViewModel.currentFile = scannerPage.scanFilePaths[fileIdx]

            // Check if scan complete
            if (scannerViewModel.progress >= 1.0) {
                scannerViewModel.progress = 1.0
                scannerViewModel.scanning = false
                scannerViewModel.currentFile = "Scan complete"
            }
        }
    }

    // Elapsed time update timer
    Timer {
        id: elapsedTimer
        interval: 1000
        running: scannerViewModel.scanning
        repeat: true
        onTriggered: {
            scannerPage.scanElapsedSeconds += 1
            var h = Math.floor(scannerPage.scanElapsedSeconds / 3600)
            var m = Math.floor((scannerPage.scanElapsedSeconds % 3600) / 60)
            var s = scannerPage.scanElapsedSeconds % 60
            scannerViewModel.elapsed = (h < 10 ? "0" : "") + h + ":" + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s

            // Calculate ETA based on progress
            if (scannerViewModel.progress > 0.01) {
                var totalEstimate = scannerPage.scanElapsedSeconds / scannerViewModel.progress
                var remaining = Math.floor(totalEstimate - scannerPage.scanElapsedSeconds)
                var eh = Math.floor(remaining / 3600)
                var em = Math.floor((remaining % 3600) / 60)
                var es = remaining % 60
                scannerViewModel.eta = (eh < 10 ? "0" : "") + eh + ":" + (em < 10 ? "0" : "") + em + ":" + (es < 10 ? "0" : "") + es
            }
        }
    }

    // Function to start a scan
    function startScan() {
        scannerViewModel.scanning = true
        scannerViewModel.progress = 0.0
        scannerViewModel.filesScanned = 0
        scannerViewModel.threatsFound = 0
        scannerViewModel.elapsed = "00:00:00"
        scannerViewModel.eta = "--:--:--"
        scannerViewModel.currentFile = "/usr/lib/x86_64-linux-gnu/libc.so.6"
        scannerPage.scanElapsedSeconds = 0
        scannerPage.currentTab = 1
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
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { scannerPage.startScan() } }
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
