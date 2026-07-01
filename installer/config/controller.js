// ThreatOne Enterprise Installer - UI Customization Controller
// Qt Installer Framework controller script

function Controller() {
    installer.autoRejectMessageBoxes();
    installer.installationFinished.connect(function() {
        gui.clickButton(buttons.NextButton);
    });
}

Controller.prototype.IntroductionPageCallback = function() {
    var widget = gui.currentPageWidget();
    if (widget != null) {
        widget.title = "Welcome to ThreatOne Enterprise Setup";
        widget.MessageLabel.setText(
            "This wizard will guide you through the installation of " +
            "ThreatOne Enterprise Cybersecurity Platform.<br><br>" +
            "Click Next to continue."
        );
    }
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.TargetDirectoryPageCallback = function() {
    var widget = gui.currentPageWidget();
    if (widget != null) {
        widget.TargetDirectoryLineEdit.setText(installer.value("TargetDir"));
    }
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.ComponentSelectionPageCallback = function() {
    var widget = gui.currentPageWidget();
    if (widget != null) {
        // Core component is always selected and required
        widget.selectComponent("com.threatone.core");
    }
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.LicenseAgreementPageCallback = function() {
    var widget = gui.currentPageWidget();
    if (widget != null) {
        widget.AcceptLicenseRadioButton.setChecked(true);
    }
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.ReadyForInstallationPageCallback = function() {
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.PerformInstallationPageCallback = function() {
    gui.clickButton(buttons.NextButton);
};

Controller.prototype.FinishedPageCallback = function() {
    var widget = gui.currentPageWidget();
    if (widget != null) {
        var runCheckBox = widget.RunItCheckBox;
        if (runCheckBox) {
            runCheckBox.setChecked(false);
        }
    }
    gui.clickButton(buttons.FinishButton);
};
