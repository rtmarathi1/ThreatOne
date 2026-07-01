import QtQuick
import QtQuick.Layouts
import "../themes"

// Metric card with title, large value, trend indicator, and sparkline
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
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

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
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

        // Large value
        Text {
            text: root.value
            font.pixelSize: ThemeManager.fontSizeHeading
            font.weight: Font.Bold
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textPrimary
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
                ctx.fillStyle = ThemeManager.primaryColor
                ctx.globalAlpha = 0.08
                ctx.fill()
                ctx.globalAlpha = 1.0

                // Draw line
                ctx.beginPath()
                for (var j = 0; j < root.sparklineData.length; j++) {
                    var yy = height - ((root.sparklineData[j] - minVal) / range) * (height - 4) - 2
                    if (j === 0) ctx.moveTo(0, yy)
                    else ctx.lineTo(j * stepX, yy)
                }
                ctx.strokeStyle = ThemeManager.primaryColor
                ctx.lineWidth = 1.5
                ctx.stroke()
            }

            Component.onCompleted: requestPaint()
        }
    }
}
