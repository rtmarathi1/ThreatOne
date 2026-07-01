import QtQuick
import QtQuick.Layouts
import "../themes"

// Circular arc gauge showing overall security score with animated rendering
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
    border.width: 1

    property real score: 85.0
    property string label: "Security Score"
    property string grade: score >= 90 ? "A+" :
                           score >= 80 ? "A" :
                           score >= 70 ? "B" :
                           score >= 60 ? "C" :
                           score >= 50 ? "D" : "F"

    property color scoreColor: score >= 80 ? ThemeManager.successColor :
                               score >= 60 ? ThemeManager.warningColor :
                               ThemeManager.errorColor

    // Animated score for smooth transitions
    property real animatedScore: 0
    Behavior on animatedScore { NumberAnimation { duration: ThemeManager.animSlow; easing.type: Easing.OutCubic } }
    Component.onCompleted: animatedScore = score
    onScoreChanged: animatedScore = score

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        spacing: ThemeManager.spacingMedium

        Text {
            text: root.label
            font.pixelSize: ThemeManager.fontSizeMedium
            font.weight: Font.DemiBold
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textPrimary
        }

        // Gauge canvas
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Canvas {
                id: gaugeCanvas
                anchors.centerIn: parent
                width: Math.min(parent.width, parent.height) * 0.85
                height: width

                onPaint: {
                    var ctx = getContext("2d")
                    ctx.clearRect(0, 0, width, height)

                    var cx = width / 2
                    var cy = height / 2
                    var outerRadius = width / 2 - 8
                    var lineWidth = 14
                    var startAngle = Math.PI * 0.75
                    var endAngle = Math.PI * 2.25
                    var scoreAngle = startAngle + (endAngle - startAngle) * (root.animatedScore / 100)

                    // Background arc (track)
                    ctx.beginPath()
                    ctx.arc(cx, cy, outerRadius, startAngle, endAngle)
                    ctx.strokeStyle = ThemeManager.borderColor
                    ctx.lineWidth = lineWidth
                    ctx.lineCap = "round"
                    ctx.stroke()

                    // Score arc (filled portion)
                    if (root.animatedScore > 0) {
                        ctx.beginPath()
                        ctx.arc(cx, cy, outerRadius, startAngle, scoreAngle)
                        ctx.strokeStyle = root.scoreColor
                        ctx.lineWidth = lineWidth
                        ctx.lineCap = "round"
                        ctx.stroke()
                    }

                    // Glow effect on score arc end
                    if (root.animatedScore > 5) {
                        var glowX = cx + outerRadius * Math.cos(scoreAngle)
                        var glowY = cy + outerRadius * Math.sin(scoreAngle)
                        ctx.beginPath()
                        ctx.arc(glowX, glowY, lineWidth / 2 + 2, 0, Math.PI * 2)
                        ctx.fillStyle = root.scoreColor
                        ctx.globalAlpha = 0.3
                        ctx.fill()
                        ctx.globalAlpha = 1.0
                    }
                }

                // Repaint on score or theme change
                Connections {
                    target: root
                    function onAnimatedScoreChanged() { gaugeCanvas.requestPaint() }
                    function onScoreColorChanged() { gaugeCanvas.requestPaint() }
                }
            }

            // Center text overlay
            ColumnLayout {
                anchors.centerIn: parent
                spacing: 2

                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: Math.round(root.animatedScore).toString()
                    font.pixelSize: ThemeManager.fontSizeHero
                    font.weight: Font.Bold
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textPrimary
                }

                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "Grade " + root.grade
                    font.pixelSize: ThemeManager.fontSizeNormal
                    font.family: ThemeManager.fontFamily
                    color: root.scoreColor
                }
            }
        }

        // Score breakdown bar
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingSmall

            Repeater {
                model: [
                    { label: "Endpoint", val: 92 },
                    { label: "Network", val: 78 },
                    { label: "Identity", val: 85 }
                ]

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Rectangle {
                        Layout.fillWidth: true
                        height: 4
                        radius: 2
                        color: ThemeManager.borderColor

                        Rectangle {
                            width: parent.width * (modelData.val / 100)
                            height: parent.height
                            radius: 2
                            color: modelData.val >= 80 ? ThemeManager.successColor :
                                   modelData.val >= 60 ? ThemeManager.warningColor :
                                   ThemeManager.errorColor
                        }
                    }

                    Text {
                        Layout.fillWidth: true
                        text: modelData.label
                        font.pixelSize: ThemeManager.fontSizeXS
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textMuted
                        horizontalAlignment: Text.AlignHCenter
                    }
                }
            }
        }
    }
}
