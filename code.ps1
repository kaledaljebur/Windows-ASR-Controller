# Created by Kaled Aljebur for basic students' practising of PowerShell and GPOs.
# This code will control the Attack Surface Reduction Rules.
##################
# Windows Defender Antivirus must be enabled for ASR rules to work.
# Ensure that your version of Windows supports ASR rules (Windows 10 Pro, Enterprise, or Education).
##################
# Local GPO commands available here:
# https://learn.microsoft.com/en-us/defender-endpoint/enable-attack-surface-reduction#powershell
##################
# The rules can be added here:
# Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus
# \Microsoft Defender Exploit Guard\Attack Surface Reduction	

$rulesID = @(
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
    @("14", "Block untrusted and unsigned processes that run from USB", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"),
    @("15", "Block Win32 API calls from Office macros", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"),
    @("16", "Use advanced protection against ransomware", "c1db55ab-c21a-4637-bb3f-a12568109d35")
)

function ruleIDSearch($value) {
    for ($i = 0; $i -le 15 ; $i++) {
        if ($rulesID[$i][2] -eq $value) {
            $result = $rulesID[$i][1]
            return $result
            break
        }
    }
}

function appliedRulesStatus {
    Write-Host "The status table will be printed after quitting this program!"
    # $asrRules = Get-MpPreference
    # $ruleActions = $asrRules.AttackSurfaceReductionRules_Actions
    # $ruleIds = $asrRules.AttackSurfaceReductionRules_Ids

    # for ($i = 0; $i -lt $ruleIds.Count; $i++) {
    #     [PSCustomObject]@{
    #         RuleID = $ruleIds[$i]
    #         Name   = ruleIDSearch($ruleIds[$i])
    #         Action = $ruleActions[$i]
    #     }
    # }
    # break
    foreach ($item in $rulesID) {
        
        $result = $item[0] + ": " + $item[1]
        Write-Host "$result"
    }

}

function allRulesMenu {    
    foreach ($item in $rulesID) {
        $result = $item[0] + ": " + $item[1]
        Write-Host "$result"
    }
}

function showMenu {
    # Clear-Host
    Write-Host
    Write-Host "********************Select from this menu********************"
    Write-Host "Q: Quit"
    Write-Host "P: Print the status of all applied rules"
    Write-Host "E: Enable all"
    Write-Host "D: Disable all"
    Write-Host "A: Audit all"    
    allRulesMenu
    Write-Host "*************************************************************"
    Write-Host
}

function updateGPO($valueName, $value) {
    switch ($value){
        '0'{$action="Disabled"}
        '1'{$action="Enabled"}
        '2'{$action="Audit"}
    }
    # $asrRuleAction = switch ($action) {
    #     "Block"     { [Microsoft.Management.Infrastructure.CimInstance]::Create('Microsoft.Security.Policies.ActionTypes.Block') }
    #     "Audit"     { [Microsoft.Management.Infrastructure.CimInstance]::Create('Microsoft.Security.Policies.ActionTypes.Audit') }
    #     "Disabled"  { [Microsoft.Management.Infrastructure.CimInstance]::Create('Microsoft.Security.Policies.ActionTypes.Disabled') }
    #     # default     { throw "Invalid action type: $action" }
    # }
    # Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled
    # Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions AuditMode
    # Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Warn
    # Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Disabled
    # Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
    # Add-MpPreference -AttackSurfaceReductionRules_Ids $valueName -AttackSurfaceReductionRules_Actions $value
    # Set-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions $asrRuleAction
    # Set-MpPreference -AttackSurfaceReductionRules_Ids $valueName.ToString() -AttackSurfaceReductionRules_Actions Disabled
    # Write-Host $valueName.ToString() $action
    # Write-Host "Name "$valueName "Action "$action "last "$asrRuleAction
    Set-MpPreference -AttackSurfaceReductionRules_Ids $valueName -AttackSurfaceReductionRules_Actions $action
    Write-Host "RuleID:" $valueName 
    Write-Host "New status:" $action 

    # $valueName.GetType();
}

function updateGPOAll($value) {
    switch ($value) {            
        'A' { 
            for ($i = 0; $i -le 15 ; $i++) {
                updateGPO $rulesID[$i][2] 2
            }
            Write-Host "Done, all rules are in Audit!" 
        }
        'D' { 
            for ($i = 0; $i -le 15 ; $i++) {
                updateGPO $rulesID[$i][2] 0
            }
            Write-Host "Done, all rules are Disabled!" 
        }
        'E' { 
            for ($i = 0; $i -le 15 ; $i++) {
                updateGPO $rulesID[$i][2] 1
            }
            Write-Host "Done, all rules are Enabled!" 
        }
    }    
}

function subMenu ($valueNUmber) {
    $valueNUmber -= 1
    Write-Host
    Write-Host "For the selected rule:" $rulesID[$valueNUmber][1]
    Write-Host "*****Select action from this menu*****"
    Write-Host "Q: Quit"
    Write-Host "1: Enable"
    Write-Host "0: Disable"
    Write-Host "2: Audit"
    Write-Host "B: Back to main menu"
    Write-Host "**************************************"
    Write-Host
    $input = Read-Host "Please enter your option"
    switch -Regex ($input) {            
        { 0..2 -contains $_ } { updateGPO $rulesID[$valueNUmber][2] $input }
        'B' { mainMenu }
        'Q' {
            Write-Host
            Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
            Write-Host
            Write-Output "Press any key to close this window..."
            Read-Host
            exit 
        }
        default { Write-Host "The entered option is not in the menu, please select from the menu!" }
    }    
}

function mainMenu {
    while ($true) {
        showMenu
        $input = Read-Host "Please enter your option"
        switch -Regex ($input) {            
            { 1..16 -contains $_ } { subMenu($input) }
            { 'A', 'D', 'E' -contains $_ } { updateGPOAll $input }
            'P' { appliedRulesStatus }
            'Q' {
                Write-Host
                Write-Host "Thanks, email me on kaledaljebur@gmail.com for any questions or suggestions ... " 
                Write-Host
                Write-Output "Press any key to close this window..."
                Read-Host
                exit 
            }
            default { Write-Host "The entered option is not in the menu, please select from the menu!" }
        }
        Write-Host "Press any key to to list the menu again ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null   
    }
}
mainMenu
