// ThreatOne Core - Installation Script
// Qt Installer Framework installation hooks

function Component() {
    // Constructor
    component.loaded.connect(this, Component.prototype.loaded);
    installer.installationFinished.connect(this, Component.prototype.installationFinished);
}

Component.prototype.loaded = function() {
    // Component loaded callback
};

Component.prototype.createOperations = function() {
    // Call default implementation
    component.createOperations();

    var targetDir = installer.value("TargetDir");

    if (systemInfo.productType === "windows") {
        // Windows: Create Start Menu shortcut
        component.addOperation("CreateShortcut",
            targetDir + "/bin/threatone.exe",
            "@StartMenuDir@/ThreatOne Enterprise.lnk",
            "workingDirectory=" + targetDir,
            "iconPath=" + targetDir + "/bin/threatone.exe",
            "iconId=0",
            "description=Launch ThreatOne Enterprise"
        );

        // Windows: Create Desktop shortcut
        component.addOperation("CreateShortcut",
            targetDir + "/bin/threatone.exe",
            "@DesktopDir@/ThreatOne Enterprise.lnk",
            "workingDirectory=" + targetDir,
            "iconPath=" + targetDir + "/bin/threatone.exe",
            "iconId=0",
            "description=Launch ThreatOne Enterprise"
        );

        // Windows: Register file type for .threat files
        component.addOperation("RegisterFileType",
            "threat",
            targetDir + "/bin/threatone.exe '%1'",
            "ThreatOne Threat Report",
            "application/x-threatone",
            targetDir + "/bin/threatone.exe,0"
        );
    }

    if (systemInfo.productType === "linux" || systemInfo.kernelType === "linux") {
        // Linux: Create .desktop file
        component.addOperation("CreateDesktopEntry",
            "threatone.desktop",
            "Type=Application\n" +
            "Name=ThreatOne Enterprise\n" +
            "Comment=Enterprise Cybersecurity Platform\n" +
            "Exec=" + targetDir + "/bin/threatone\n" +
            "Icon=" + targetDir + "/share/icons/threatone.png\n" +
            "Categories=Security;System;Network;\n" +
            "Terminal=false\n" +
            "StartupNotify=true"
        );

        // Linux: Set executable permissions
        component.addOperation("Execute",
            "chmod", "+x", targetDir + "/bin/threatone"
        );

        // Linux: Set permissions on configuration directory
        component.addOperation("Execute",
            "chmod", "-R", "750", targetDir + "/etc"
        );
    }

    if (systemInfo.productType === "osx") {
        // macOS: Set executable permissions
        component.addOperation("Execute",
            "chmod", "+x", targetDir + "/bin/threatone"
        );
    }
};

Component.prototype.installationFinished = function() {
    // Post-installation actions
    if (installer.isInstaller() && installer.status === QInstaller.Success) {
        // Installation completed successfully
    }
};
