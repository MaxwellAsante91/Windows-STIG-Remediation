# Windows-STIG-Remediation
<#
.SYNOPSIS
    This PowerShell script configures BitLocker to require a PIN for pre-boot authentication by
    enabling "Require additional authentication at startup" with "Require startup PIN with TPM".

.NOTES
    Author          : Your Name
    LinkedIn        : linkedin.com/in/your-profile/
    GitHub          : github.com/your-username
    Date Created    : 2026-10-22
    Last Modified   : 2026-10-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000031
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-00-000031/

.TESTED ON
    Date(s) Tested  : 2026-10-22
    Tested By       : Your Name
    Systems Tested  : Windows 11 Pro (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run from an elevated (Administrator) PowerShell session.
    Re-run the Tenable DISA STIG scan afterwards to confirm the finding is resolved.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-00-000031).ps1
#>

# Registry location behind the GPO:
# Computer Configuration > Administrative Templates > Windows Components >
# BitLocker Drive Encryption > Operating System Drives > Require additional authentication at startup
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

# Create the registry key if it does not exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# 0 = Do not allow, 1 = Require, 2 = Allow (only one startup option may be set to "Require")
New-ItemProperty -Path $regPath -Name 'UseAdvancedStartup' -Value 1 -PropertyType DWord -Force | Out-Null  # Require additional authentication at startup: Enabled
New-ItemProperty -Path $regPath -Name 'EnableBDEWithNoTPM' -Value 0 -PropertyType DWord -Force | Out-Null  # Do not allow BitLocker without a compatible TPM
New-ItemProperty -Path $regPath -Name 'UseTPM'             -Value 0 -PropertyType DWord -Force | Out-Null  # TPM only: Do not allow
New-ItemProperty -Path $regPath -Name 'UseTPMKey'          -Value 0 -PropertyType DWord -Force | Out-Null  # TPM + startup key: Do not allow
New-ItemProperty -Path $regPath -Name 'UseTPMPIN'          -Value 1 -PropertyType DWord -Force | Out-Null  # TPM + startup PIN: Require
New-ItemProperty -Path $regPath -Name 'UseTPMKeyPIN'       -Value 0 -PropertyType DWord -Force | Out-Null  # TPM + startup key + PIN: Do not allow

# Apply the policy
gpupdate /target:computer /force | Out-Null

# Verify the remediation
$p = Get-ItemProperty -Path $regPath
if ($p.UseAdvancedStartup -eq 1 -and ($p.UseTPMPIN -eq 1 -or $p.UseTPMKeyPIN -eq 1)) {
    Write-Output "WN11-00-000031 remediated: BitLocker pre-boot PIN is required."
} else {
    Write-Output "WN11-00-000031 NOT remediated. Check values in $regPath."
}
