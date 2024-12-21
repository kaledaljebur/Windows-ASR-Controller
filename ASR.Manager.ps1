# Created by Kaled Aljebur as part of basic PowerShell practising with GPOs.
# This program is part of labs for Cert IV Cybersecurity students at Tafe QLD Australia.
# This program will manage the Attack Surface Reduction Rules, 19 updated rules from Microsoft.
# https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#asr-rule-to-guid-matrix
# The management include:
# List the status of all installed rules.
# Enable all rules.
# Disable all rules.
# Audit mode for all rules.
# Warn mode for all rules.
# Apply an action for a specific rule.
# Export and import rules - Jason file format.
##################
# As a requirements:
# Windows Defender must be enabled.
# This program should be running with administrator privileges.
##################
# Local GPO commands available here:
# https://learn.microsoft.com/en-us/defender-endpoint/enable-attack-surface-reduction#powershell
##################
# The rules can be added manually here:
# Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus
# \Microsoft Defender Exploit Guard\Attack Surface Reduction	

$rulesID = @(
    # Disable any not needed rules, no need to edit the program, just make sure only the last rule dont ends with comma.
    @("1", "Block abuse of exploited vulnerable signed drivers", "56a863a9-875e-4185-98a7-b882c64b5ce5"),
    @("2", "Block Adobe Reader from creating child processes", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"),
    @("3", "Block all Office applications from creating child processes", "d4f940ab-401b-4efc-aadc-ad5f3c50688a"),
    @("4", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"),
    @("5", "Block executable content from email client and webmail", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"),
    @("6", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion", "01443614-cd74-433a-b99e-2ecdc07bfc25"),
    @("7", "Block execution of potentially obfuscated scripts", "5beb7efe-fd9a-4556-801d-275e5ffc04cc"),
    @("8", "Block JavaScript or VBScript from launching downloaded executable content", "d3e037e1-3eb8-44c8-a917-57927947596d"),
    @("9", "Block Office applications from creating executable content", "3b576869-a4ec-4529-8536-b80a7769e899"),
    @("10", "Block Office applications from injecting code into other processes", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"),
    @("11", "Block Office communication application from creating child processes", "26190899-1602-49e8-8b27-eb1d0a1ce869"),
    @("12", "Block persistence through WMI event subscription", "e6db77e5-3df2-4cf1-b95a-636979351e5b"),
    @("13", "Block process creations originating from PSExec and WMI commands", "d1e49aac-8f56-4280-b9ba-993a6d77406c"),
    @("14", "Block rebooting machine in Safe Mode (preview)", "33ddedf1-c6e0-47cb-833e-de6133960387"), #Excluded in most guides
    @("15", "Block untrusted and unsigned processes that run from USB", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"),
    @("16", "Block use of copied or impersonated system tools (preview)", "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"), #Excluded in most guides
    @("17", "Block Webshell creation for Servers", "a8f5898e-1dc8-49a9-9878-85004b8a61e6"), #Excluded in most guides
    @("18", "Block Win32 API calls from Office macros", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"),
    @("19", "Use advanced protection against ransomware", "c1db55ab-c21a-4637-bb3f-a12568109d35")
)

function ruleIDSearch($value) {
    for ($i = 0; $i -le $rulesID.Count - 1 ; $i++) {
        if ($rulesID[$i][2] -eq $value) {
            $result = $rulesID[$i][1]
            return $result            
        }
    }
}

function appliedRulesStatus {
    #Print the rules status and export into Jason file
    Write-Host
    Write-Host "Make sure the window is wide enough to see full table, you may need to re-print!"
    Write-Host "If no output, then no rules been added before."
    Write-Host "You can select ""D: Create disabled rules"" from the Main Menu, then print again."
    Write-Host
    $asrRules = Get-MpPreference
    $ruleActions = $asrRules.AttackSurfaceReductionRules_Actions
    $installedRuleIds = $asrRules.AttackSurfaceReductionRules_Ids
    # This line belong to Table display method two
    # $output = @()
    Write-Host "Status  Rule Id                              Rule Description"
    Write-Host "------  -------                              ----------------"
    for ($i = 0; $i -lt $installedRuleIds.Count; $i++) {
        $ruleID = $installedRuleIds[$i]
        $status = $ruleActions[$i]
        $name = ruleIDSearch($installedRuleIds[$i])
        switch ($status) {
            '0' { $status = "Disabled" }
            '1' { $status = "Enabled" }
            '2' { $status = "Audit" }
            '6' { $status = "Warn" }
        }
        Write-Host $status $ruleID $name
        # # Table display method two: this method is faster than method one:
        # $output += @{RuleID = $ruleID; Status = $status; Name = $name }
        # # Table display method one: this method is shorter as a code but slow and it will display the content when the program exit:
        # [PSCustomObject]@{
        #     RuleID = $installedRuleIds[$i]
        #     Action = $ruleActions[$i]
        #     Name   = ruleIDSearch($installedRuleIds[$i])
        # }
    }
    # This line belong to Table display method two 
    # $output | ForEach { [PSCustomObject]$_ } | Format-Table -AutoSize

    # Export the status table into Jason:
    if (-not $output.Count -eq 0) {
        $inputOption = Read-Host "Export the table into Jason format? Y: for yes, or just hit Enter to cancel"
        if ($inputOption -eq "Y") {
            ConvertTo-Json -InputObject $output | Out-File -FilePath .\ASR.Manager.json
            Write-Host "The table has been exported to ASR.Manager.json"
            Write-Host
        }
    }
}

function allRulesMenu {    
    foreach ($item in $rulesID) {
        $result = $item[0] + ": " + $item[1]
        Write-Host "  $result"
    }
}

function importRulesMenu {
    Write-Host
    Write-Host "Make sure the Jason file is located in the same directory of this program, and it should be named ""ASR.Manager.json""" 
    Write-Host "To see the accepted Jason template, select "" D: Create disabled rules"", then selct "" P: Print the status of all applied rules"" to export in Jason" 
    Write-Host "The best way is you select the needed configurations from the main menu, then export as Jason, then import in your auther computers"
    Write-Host
    Write-Host "*******Select an action from this menu*******            "
    Write-Host "  Q: Quit the program"
    Write-Host "  H: Help"
    Write-Host "  B: Back to main menu"
    Write-Host "  I: Proceed with importing" 
    Write-Host
    $inputOption = Read-Host "Please enter your option"     
    switch ($inputOption) {            
        'Q' {
            Write-Host
            Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
            Write-Host
            Write-Output "Press any key to close this window ..."
            Read-Host
            exit 
        }
        'H' { helpMenu }
        'B' { mainMenu }
        'I' { importRules }
        default { Write-Host "The entered option is not in the menu, please select from the menu!" }
    }   
}

function importRules {
    $jsonPath = ".\ASR.Manager.json"
    $jsonFile = Get-Content -Path $jsonPath | ConvertFrom-Json
    $jsonArray = @()
    foreach ($i in $jsonFile) {
        $row = @()
        foreach ($property in $i.PSObject.Properties) {
            $row += $property.Value
        }
        $jsonArray += , $row
    }
    
    if ($jsonArray.Count -eq 0) {
        Read-Host "Empty Jason file, hit Enter to back for import menu ..."
        importRulesMenu
    }
    else {
        # List the content of Jason file $jsonArray before applying
        Write-Host
        Write-Host "The content of Jason file:"
        Write-Host "Status  Rule Id                              Rule Description"
        Write-Host "------  -------                              ----------------"
        for ($i = 0; $i -le $jsonArray.Count - 1 ; $i++) {
            Write-Host $jsonArray[$i][0] $jsonArray[$i][1] $jsonArray[$i][2]
        }
        # Ask to apply the Jason file
        Write-Host
        $inputOption = Read-Host "Apply the imported Json? Y: for yes, Enter: back to import menu"
        if ($inputOption -eq "Y") {
            Write-Host
            Write-Host "Start applying Jason file ..."
            Write-Host "Status  Rule Id                              Rule Description"
            Write-Host "------  -------                              ----------------"
            for ($i = 0; $i -le $jsonArray.Count - 1 ; $i++) {
                updateGPO $jsonArray[$i][1] $jsonArray[$i][0]
            }
            Write-Host 
            Write-Host "You can selct ""P: Print the status of all applied rules"" from the main menu for verification"
            Write-Host
        }
        else { importRulesMenu }
    }
}

function ruleExclusions ($ruleId, $excluded) {    
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionOnlyExclusions -Exclusions $excluded
}

function rulesExclusionsAll($excluded) {    
    # Set-MpPreference -AttackSurfaceReductionOnlyExclusions -Exclusions $excluded
    Write-Host $excluded
}

function rulesExclusionsAllStatus {
    Get-MpPreference | Select-Object AttackSurfaceReductionOnlyExclusions  
}

function exclusionMenu {
    while ($true) {
        showExclusionMenu
        $inputOption = Read-Host "Please enter your option"
        switch ($inputOption) {            
            'P' { rulesExclusionsAllStatus rulesExclusionsAllStatus }
            'B' { mainMenu }
            'A' {
                $exclusion = Read-Host "Enter the exclusion value"
                rulesExclusionsAll $exclusion
            }
            'Q' {
                Write-Host
                Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
                Write-Host
                Write-Output "Press any key to close this window ..."
                Read-Host
                exit 
            }
            'H' { helpMenu }
            default { Write-Host "The entered option is not in the menu, please select from the menu!" }
        }
        Write-Host "Press any key to list the menu again ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null   
    }
}
function showExclusionMenu {
    Clear-Host
    Write-Host
    Write-Host "************************Exclusion Menu************************"
    Write-Host "*******Select an action from this menu*******            "
    Write-Host "  Q: Quit the program"
    Write-Host "  H: Help"
    Write-Host "  P: Print the status of all applied exclusions"
    Write-Host "  A: Add exclusion for all rules"
    Write-Host "  B: Back to main menu"  
    Write-Host
    Write-Host "***Or select a specific rule to be actioned***           "
    allRulesMenu
    Write-Host "*************************************************************"
    Write-Host    
}
function showMainMenu {
    Clear-Host
    Write-Host
    Write-Host "**************************Main Menu**************************"
    Write-Host "*******Select an action from this menu*******            "
    Write-Host "  Q: Quit the program"
    Write-Host "  H: Help"
    Write-Host "  P: Print the status of all applied rules, and export in Jason file"
    Write-Host "  I: Import rules' settings from Jason file"
    Write-Host "  X: For exclusion actions" 
    Write-Host "  E: Enable all rules"
    Write-Host "  D: Create disabled rules, or disable all available rules"
    Write-Host "  A: Put all rules in Audit mode"
    Write-Host "  W: Put all rules in Warn mode"
    Write-Host
    Write-Host "***Or select a specific rule to be actioned***           "
    allRulesMenu
    Write-Host "*************************************************************"
    Write-Host
}

function updateGPO($valueName, $value) {
    switch ($value) {
        'D' { $action = "Disabled" }
        'E' { $action = "Enabled" }
        'A' { $action = "AuditMode" }
        'W' { $action = "Warn" }
        default { $action = $value }
    }
    Add-MpPreference -AttackSurfaceReductionRules_Ids $valueName -AttackSurfaceReductionRules_Actions $action
    $ruleName = ruleIDSearch($valueName)
    Write-Host $action $valueName $ruleName 
}

function updateGPOAll($value) {
    switch ($value) {            
        'A' { 
            for ($i = 0; $i -le $rulesID.Count - 1 ; $i++) {
                updateGPO $rulesID[$i][2] $value
                # You can also use the below:
                # (Get-MpPreference).AttackSurfaceReductionRules_Ids | 
                # Foreach {Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions AuditMode}
            }
            Write-Host "Done, all rules are in Audit mode!" 
        }
        'D' { 
            for ($i = 0; $i -le $rulesID.Count - 1 ; $i++) {
                updateGPO $rulesID[$i][2] $value
            }
            Write-Host "Done, all rules are Disabled!" 
        }
        'E' { 
            for ($i = 0; $i -le $rulesID.Count - 1 ; $i++) {
                updateGPO $rulesID[$i][2] $value
            }
            Write-Host "Done, all rules are Enabled!" 
        }
        'W' { 
            for ($i = 0; $i -le $rulesID.Count - 1 ; $i++) {
                updateGPO $rulesID[$i][2] $value
            }
            Write-Host "Done, all rules are Warn mode!" 
        }
    }    
}

function actionMenu ($valueNUmber) {
    $valueNUmber -= 1
    Write-Host
    Write-Host "Select an action for the rule:" $rulesID[$valueNUmber][1]
    Write-Host "*************Action Menu*************"
    Write-Host "  Q: Quit the program"
    Write-Host "  E: Enable"
    Write-Host "  D: Disable"
    Write-Host "  A: Audit"
    Write-Host "  W: Warn"
    Write-Host "  B: Back to Main Menu"
    Write-Host "**************************************"
    Write-Host
    $inputOption = Read-Host "Please enter your option"
    switch ($inputOption) {            
        { 'E', 'D', 'A', 'W' -contains $_ } { updateGPO $rulesID[$valueNUmber][2] $inputOption }
        # { 0..2 -contains $_ } { updateGPO $rulesID[$valueNUmber][2] $inputOption }
        # '6' { updateGPO $rulesID[$valueNUmber][2] $inputOption }
        'B' { mainMenu }
        'Q' {
            Write-Host
            Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
            Write-Host
            Write-Output "Press any key to close this window ..."
            Read-Host
            exit 
        }
        default { Write-Host "The entered option is not in the menu, please select from the menu!" }
    }    
}

function helpMenu {
    Write-Host
    Write-Host "Source https://learn.microsoft.com/en-us/defender-endpoint/enable-attack-surface-reduction#mdm"
    Write-Host "The action for each rule can be one of the following:"
    Write-Host "  Disable: its manual value is 0. Disable the attack surface reduction rule."
    Write-Host "  Block(Enable): its manual value is 1. Block action will enable the attack surface reduction rule." 
    Write-Host "  Audit: its manual value is 2. Audit action will evaluate how the attack surface reduction rule would impact your organization if enabled."
    Write-Host "  Warn: its manual value is 6. Enable the attack surface reduction rule but allow the end-user to bypass the block"
    Write-Host
}
function mainMenu {
    while ($true) {
        showMainMenu
        $inputOption = Read-Host "Please enter your option"
        switch ($inputOption) {            
            { 1..$rulesID.Count -contains $_ } { actionMenu($inputOption) }
            { 'A', 'D', 'E', 'W' -contains $_ } { updateGPOAll $inputOption }
            'P' { appliedRulesStatus }
            'I' { importRulesMenu }
            'X' { exclusionMenu }
            'Q' {
                Write-Host
                Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
                Write-Host
                Write-Output "Press any key to close this window ..."
                Read-Host
                exit 
            }
            'H' { helpMenu }
            default { Write-Host "The entered option is not in the menu, please select from the menu!" }
        }
        Write-Host "Press any key to list the menu again ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null   
    }
}

function elevatedPrivilegesCheck {
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $AdminPrivileges = $WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $AdminPrivileges) {
        Write-Host
        Write-Host "This program is not running with administrator privileges!"
        Write-Host "Please re-run it with administrator privileges."
        Write-Host
        Write-Host "Press any key to exit ..."
        Read-Host
        exit
    }     
}
elevatedPrivilegesCheck
mainMenu
