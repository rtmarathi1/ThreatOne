import QtQuick
import QtQuick.Layouts
import "../themes"

// Metric card with title, large value, trend indicator, and sparkline
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: "transparent"
    border.color: ThemeManager.glassBorder
    border.width: 1
    implicitHeight: 120

    property string title: "Metric"
    property string value: "0"
    property string subtitle: ""
    property real trend: 0.0
    property bool trendPositive: trend >= 0
    property string trendText: (trendPositive ? "+" : "") + trend.toFixed(1) + "%"
    property color trendColor: trendPositive ? ThemeManager.successColor : ThemeManager.errorColor
    property string icon: ""
    property color iconColor: ThemeManager.primaryColor
    property var sparklineData: []

    // Gradient background
    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        gradient: Gradient {
            GradientStop { position: 0.0; color: ThemeManager.gradientStart }
            GradientStop { position: 1.0; color: ThemeManager.gradientEnd }
        }
        opacity: 0.9
    }

    // Left accent strip
    Rectangle {
        id: accentStrip
        width: 4
        height: parent.height - 16
        anchors.left: parent.left
        anchors.leftMargin: 8
        anchors.verticalCenter: parent.verticalCenter
        radius: 2
        color: root.iconColor
        opacity: 0.8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        anchors.leftMargin: ThemeManager.spacingLarge + 8
        spacing: ThemeManager.spacingSmall

        // Title row with icon
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingSmall

            Text {
                visible: root.icon !== ""
                text: root.icon
                font.pixelSize: ThemeManager.iconSizeMedium
                color: root.iconColor
            }

            Text {
                text: root.title
                font.pixelSize: ThemeManager.fontSizeSmall
                font.weight: Font.Medium
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textSecondary
                Layout.fillWidth: true
            }

            // Trend badge
            Rectangle {
                visible: root.trend !== 0
                width: trendLabel.implicitWidth + 8
                height: 18
                radius: ThemeManager.radiusSmall
                color: Qt.rgba(root.trendColor.r, root.trendColor.g, root.trendColor.b, 0.1)

                Text {
                    id: trendLabel
                    anchors.centerIn: parent
                    text: (root.trendPositive ? "\u2191" : "\u2193") + " " + root.trendText
                    font.pixelSize: ThemeManager.fontSizeXS
                    font.weight: Font.Medium
                    font.family: ThemeManager.fontFamily
                    color: root.trendColor
                }
            }
        }

        // Large value with smooth opacity transition
        Text {
            text: root.value
            font.pixelSize: ThemeManager.fontSizeHeading
            font.weight: Font.Bold
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textPrimary
            Behavior on opacity { NumberAnimation { duration: ThemeManager.animNormal } }
        }

        // Subtitle
        Text {
            visible: root.subtitle !== ""
            text: root.subtitle
            font.pixelSize: ThemeManager.fontSizeSmall
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textMuted
        }

        Item { Layout.fillHeight: true }

        // Sparkline
        Canvas {
            id: sparklineCanvas
            Layout.fillWidth: true
            height: 24
            visible: root.sparklineData.length > 1

            onPaint: {
                var ctx = getContext("2d")
                ctx.clearRect(0, 0, width, height)

                if (root.sparklineData.length < 2) return

                var maxVal = Math.max.apply(null, root.sparklineData)
                var minVal = Math.min.apply(null, root.sparklineData)
                var range = maxVal - minVal
                if (range === 0) range = 1

                var stepX = width / (root.sparklineData.length - 1)

                // Fill area
                ctx.beginPath()
                ctx.moveTo(0, height)
                for (var i = 0; i < root.sparklineData.length; i++) {
                    var y = height - ((root.sparklineData[i] - minVal) / range) * (height - 4) - 2
                    ctx.lineTo(i * stepX, y)
                }
                ctx.lineTo(width, height)
                ctx.closePath()
                ctx.fillStyle = root.iconColor
                ctx.globalAlpha = 0.12
                ctx.fill()
                ctx.globalAlpha = 1.0

                // Draw line
                ctx.beginPath()
                for (var j = 0; j < root.sparklineData.length; j++) {
                    var yy = height - ((root.sparklineData[j] - minVal) / range) * (height - 4) - 2
                    if (j === 0) ctx.moveTo(0, yy)
                    else ctx.lineTo(j * stepX, yy)
                }
                ctx.strokeStyle = root.iconColor
                ctx.lineWidth = 1.5
                ctx.stroke()
            }

            Connections {
                target: root
                function onSparklineDataChanged() { sparklineCanvas.requestPaint() }
            }

            Component.onCompleted: requestPaint()
        }
    }
}
