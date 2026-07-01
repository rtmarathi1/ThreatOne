import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: edrPage
    objectName: "edr"
    color: ThemeManager.backgroundColor

    property var edrViewModel: QtObject {
        property int totalProcesses: 287
        property int suspiciousProcesses: 4
        property int fileEvents: 1523
        property int activeAlerts: 12
        property int behaviorDetections: 3
    }

    property int currentTab: 0

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
                    Text { text: "Endpoint Detection & Response"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Monitor processes, files, behaviors, and threats in real-time"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
            }

            // Stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Running Processes"; value: edrViewModel.totalProcesses.toString(); icon: "\u2318"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Suspicious"; value: edrViewModel.suspiciousProcesses.toString(); trend: 33.0; icon: "\u26A0"; iconColor: ThemeManager.warningColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "File Events (1h)"; value: edrViewModel.fileEvents.toLocaleString(); icon: "\u2261"; iconColor: ThemeManager.chart6 }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Active Alerts"; value: edrViewModel.activeAlerts.toString(); trend: -8.0; icon: "\u26A1"; iconColor: ThemeManager.errorColor }
            }

            // Tab bar
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Processes", "File Events", "Alerts", "Behavior Analysis", "Incident Timeline"]
                    Rectangle {
                        Layout.preferredHeight: 36
                        Layout.preferredWidth: edrTabLabel.implicitWidth + ThemeManager.spacingXL
                        radius: ThemeManager.radiusMedium
                        color: edrPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: edrPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor
                        border.width: 1
                        Text { id: edrTabLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: edrPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: edrPage.currentTab = index }
                    }
                }
            }

            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: edrPage.currentTab === 0 ? processesTab :
                                 edrPage.currentTab === 1 ? fileEventsTab :
                                 edrPage.currentTab === 2 ? alertsTab :
                                 edrPage.currentTab === 3 ? behaviorTab : timelineTab
            }
        }
    }

    Component {
        id: processesTab
        DataTable {
            title: "Process Tree"
            columns: [
                { key: "pid", label: "PID", width: 60 },
                { key: "name", label: "Process Name", width: 180 },
                { key: "user", label: "User", width: 100 },
                { key: "cpu", label: "CPU %", width: 70 },
                { key: "memory", label: "Memory", width: 90 },
                { key: "network", label: "Network", width: 90 },
                { key: "parent", label: "Parent", width: 80 },
                { key: "risk", label: "Risk", width: 70 }
            ]
            rows: [
                { pid: "1", name: "systemd", user: "root", cpu: "0.1", memory: "12 MB", network: "0 B/s", parent: "-", risk: "Low" },
                { pid: "847", name: "sshd", user: "root", cpu: "0.0", memory: "8 MB", network: "1.2 KB/s", parent: "1", risk: "Low" },
                { pid: "1204", name: "nginx", user: "www", cpu: "2.3", memory: "64 MB", network: "45 MB/s", parent: "1", risk: "Low" },
                { pid: "2891", name: "postgres", user: "postgres", cpu: "5.7", memory: "256 MB", network: "12 MB/s", parent: "1", risk: "Low" },
                { pid: "3456", name: "node", user: "app", cpu: "12.4", memory: "512 MB", network: "8 MB/s", parent: "1", risk: "Medium" },
                { pid: "4521", name: "svchost_x86.exe", user: "admin", cpu: "35.2", memory: "1.2 GB", network: "500 KB/s", parent: "3456", risk: "Critical" },
                { pid: "4788", name: "cmd.exe", user: "admin", cpu: "0.8", memory: "24 MB", network: "2 KB/s", parent: "4521", risk: "High" },
                { pid: "5102", name: "powershell.exe", user: "admin", cpu: "8.1", memory: "180 MB", network: "45 KB/s", parent: "4788", risk: "High" },
                { pid: "5234", name: "mimikatz.exe", user: "SYSTEM", cpu: "15.0", memory: "90 MB", network: "0 B/s", parent: "5102", risk: "Critical" },
                { pid: "6001", name: "chrome", user: "user", cpu: "4.2", memory: "800 MB", network: "2 MB/s", parent: "1", risk: "Low" }
            ]
        }
    }

    Component {
        id: fileEventsTab
        TimelineView {
            title: "File System Events"
            events: [
                { time: "14:32", title: "File Created: /tmp/.cache/payload.bin", description: "Process: svchost_x86.exe (PID 4521) - Size: 2.4 MB - Hash: a1b2c3...", severity: "critical" },
                { time: "14:31", title: "File Modified: /etc/shadow", description: "Process: powershell.exe (PID 5102) - Unauthorized access to credentials", severity: "critical" },
                { time: "14:30", title: "File Created: /var/tmp/.x", description: "Process: cmd.exe (PID 4788) - Hidden file in temp directory", severity: "high" },
                { time: "14:28", title: "File Accessed: /etc/passwd", description: "Process: mimikatz.exe (PID 5234) - Credential harvesting attempt", severity: "high" },
                { time: "14:25", title: "File Deleted: /var/log/auth.log", description: "Process: cmd.exe (PID 4788) - Log tampering detected", severity: "high" },
                { time: "14:20", title: "File Modified: /home/user/.bashrc", description: "Process: node (PID 3456) - Persistence mechanism added", severity: "medium" },
                { time: "14:15", title: "File Created: /opt/app/update.sh", description: "Process: nginx (PID 1204) - Legitimate deployment script", severity: "low" },
                { time: "14:10", title: "File Accessed: /var/lib/postgres/data", description: "Process: postgres (PID 2891) - Normal database operation", severity: "info" }
            ]
        }
    }

    Component {
        id: alertsTab
        ColumnLayout {
            spacing: ThemeManager.spacingSmall

            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingSmall
                Repeater {
                    model: ["All", "Critical", "High", "Medium", "Low"]
                    Rectangle {
                        width: sevFilterLabel.implicitWidth + 16; height: 28; radius: 14
                        color: index === 0 ? ThemeManager.primaryColor : Qt.rgba(ThemeManager.borderColor.r, ThemeManager.borderColor.g, ThemeManager.borderColor.b, 0.5)
                        Text { id: sevFilterLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Medium; color: index === 0 ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                    }
                }
            }

            ListView {
                Layout.fillWidth: true
                Layout.preferredHeight: 400
                clip: true
                spacing: ThemeManager.spacingSmall
                model: ListModel {
                    ListElement { alertSeverity: "critical"; alertTitle: "Credential Dumping Detected"; alertDesc: "mimikatz.exe executing LSASS memory dump on ADMIN-PC"; alertSource: "EDR"; alertTime: "2 min ago" }
                    ListElement { alertSeverity: "critical"; alertTitle: "Ransomware Behavior"; alertDesc: "Rapid file encryption detected in /home/user/documents"; alertSource: "Behavior"; alertTime: "5 min ago" }
                    ListElement { alertSeverity: "high"; alertTitle: "Lateral Movement via PsExec"; alertDesc: "Remote service creation on 10.0.1.45 from compromised host"; alertSource: "NDR"; alertTime: "8 min ago" }
                    ListElement { alertSeverity: "high"; alertTitle: "Suspicious PowerShell"; alertDesc: "Encoded command execution with network download cradle"; alertSource: "EDR"; alertTime: "12 min ago" }
                    ListElement { alertSeverity: "medium"; alertTitle: "Unusual Process Tree"; alertDesc: "cmd.exe spawned from nginx worker process"; alertSource: "EDR"; alertTime: "15 min ago" }
                    ListElement { alertSeverity: "medium"; alertTitle: "Registry Modification"; alertDesc: "Run key added for persistence: HKLM\\SOFTWARE\\..."; alertSource: "EDR"; alertTime: "20 min ago" }
                    ListElement { alertSeverity: "low"; alertTitle: "New Scheduled Task"; alertDesc: "Task 'WindowsUpdate' created with system privileges"; alertSource: "EDR"; alertTime: "25 min ago" }
                }
                delegate: AlertCard {
                    width: ListView.view.width
                    severity: model.alertSeverity
                    title: model.alertTitle
                    description: model.alertDesc
                    source: model.alertSource
                    timestamp: model.alertTime
                }
            }
        }
    }

    Component {
        id: behaviorTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            Text { text: "Behavior Analysis Detections"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }

            Repeater {
                model: ListModel {
                    ListElement { pattern: "Credential Access Chain"; confidence: 95; description: "Sequential execution: cmd.exe -> powershell.exe -> mimikatz.exe with LSASS access"; techniques: "T1003.001, T1059.001"; riskLevel: "Critical" }
                    ListElement { pattern: "Living off the Land"; confidence: 87; description: "Use of built-in tools (certutil, bitsadmin) for downloading external payloads"; techniques: "T1218, T1197"; riskLevel: "High" }
                    ListElement { pattern: "Defense Evasion"; confidence: 72; description: "Log deletion followed by timestamp manipulation on modified files"; techniques: "T1070.001, T1070.006"; riskLevel: "High" }
                }
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: model.riskLevel === "Critical" ? ThemeManager.severityCritical : ThemeManager.severityHigh
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall

                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: model.pattern; font.pixelSize: ThemeManager.fontSizeNormal; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Item { Layout.fillWidth: true }
                            Rectangle {
                                width: confLabel.implicitWidth + 12; height: 22; radius: ThemeManager.radiusSmall
                                color: model.confidence >= 90 ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15) : Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15)
                                Text { id: confLabel; anchors.centerIn: parent; text: "Confidence: " + model.confidence + "%"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Medium; color: model.confidence >= 90 ? ThemeManager.errorColor : ThemeManager.warningColor; font.family: ThemeManager.fontFamily }
                            }
                        }
                        Text { Layout.fillWidth: true; text: model.description; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; wrapMode: Text.WordWrap }
                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: "MITRE: " + model.techniques; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamilyMono }
                            Item { Layout.fillWidth: true }
                            Text { text: model.riskLevel; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: model.riskLevel === "Critical" ? ThemeManager.errorColor : ThemeManager.warningColor; font.family: ThemeManager.fontFamily }
                        }
                    }
                }
            }
        }
    }

    Component {
        id: timelineTab
        TimelineView {
            title: "Incident Correlation Timeline"
            events: [
                { time: "14:32", title: "Credential dump completed", description: "mimikatz.exe successfully dumped LSASS credentials - 12 hashes extracted", severity: "critical" },
                { time: "14:30", title: "LSASS access detected", description: "Process 5234 opened handle to lsass.exe with PROCESS_VM_READ", severity: "critical" },
                { time: "14:28", title: "Mimikatz execution", description: "mimikatz.exe launched from powershell with SeDebugPrivilege", severity: "critical" },
                { time: "14:25", title: "Privilege escalation", description: "Token impersonation: LocalService -> SYSTEM via named pipe", severity: "high" },
                { time: "14:22", title: "PowerShell download cradle", description: "IEX(New-Object Net.WebClient).DownloadString from 185.141.25.x", severity: "high" },
                { time: "14:18", title: "Initial compromise", description: "svchost_x86.exe spawned from malicious macro in invoice.docm", severity: "high" },
                { time: "14:15", title: "Email delivered", description: "Phishing email with attachment delivered to admin@corp.local", severity: "medium" },
                { time: "14:10", title: "Reconnaissance", description: "DNS queries to malicious infrastructure from infected endpoint", severity: "low" }
            ]
        }
    }
}
