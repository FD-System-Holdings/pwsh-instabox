@{
    RootModule        = 'Instabox.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b43f7b9a-4f38-4d62-a2c0-9a7f3c86e101'
    Author            = 'Riley Carney'
    Copyright         = 'Copyright (c) 2026 Riley Carney. Licensed under the MIT License.'
    Description       = 'PowerShell 7+ application and module for managing instabox cloud sandboxes, files, SSH connections, ports, secrets, snapshots, and usage.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        # Auth & Config
        'Connect-Instabox',
        'Disconnect-Instabox',
        'Get-InstaboxMe',
        'Get-InstaboxSession',
        'Get-InstaboxConfig',
        'Set-InstaboxConfig',
        # Operations
        'Get-InstaboxOperation',
        'Wait-InstaboxOperation',
        # Templates
        'Get-InstaboxTemplate',
        # Sandboxes (Machines)
        'Get-InstaboxSandbox',
        'New-InstaboxSandbox',
        'Update-InstaboxSandbox',
        'Remove-InstaboxSandbox',
        'Start-InstaboxSandbox',
        'Stop-InstaboxSandbox',
        'Suspend-InstaboxSandbox',
        'Resume-InstaboxSandbox',
        'Invoke-InstaboxWake',
        'Copy-InstaboxSandbox',
        'Restore-InstaboxSandbox',
        # Files
        'Get-InstaboxFile',
        'Receive-InstaboxFile',
        'Send-InstaboxFile',
        'New-InstaboxUploadUrl',
        'New-InstaboxDirectory',
        'Rename-InstaboxFile',
        'Remove-InstaboxFile',
        # Connections & Exec
        'New-InstaboxSshToken',
        'Get-InstaboxSshToken',
        'Revoke-InstaboxSshToken',
        'New-InstaboxSshCertificate',
        'Enter-InstaboxSandbox',
        'Invoke-InstaboxExec',
        # Ports
        'Get-InstaboxPort',
        'Publish-InstaboxPort',
        'Unpublish-InstaboxPort',
        'Get-InstaboxPortToken',
        # Secrets
        'Get-InstaboxOrgSecret',
        'Set-InstaboxOrgSecret',
        'Remove-InstaboxOrgSecret',
        'Import-InstaboxOrgSecret',
        'Get-InstaboxSandboxSecret',
        'Set-InstaboxSandboxSecret',
        'Sync-InstaboxSandboxSecret',
        # Snapshots
        'Get-InstaboxSnapshot',
        'New-InstaboxSnapshot',
        'Remove-InstaboxSnapshot',
        'Get-InstaboxSnapshotFile',
        # Usage
        'Get-InstaboxUsage',
        # Interactive TUI
        'Start-InstaboxApp'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('instabox', 'sandbox', 'ssh', 'cloud', 'cli')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
