[CmdletBinding()]
Param(
  [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
  [string]$SSHKey
)

Begin {

  Set-Variable -Name sshAdminKeysFile -Option Constant -Value "$($env:ProgramData)/ssh/administrators_authorized_keys"


  Function Add-AclRule {

    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [System.Security.AccessControl.NativeObjectSecurity]$Acl,
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Identity,
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [System.Security.AccessControl.FileSystemRights]$Rights,
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [System.Security.AccessControl.AccessControlType]$AccessControl
    )

    $aclRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $AccessControl)
    $acl.SetAccessRule($aclRule)

  }

  Function Set-SSHAdminKeysAcl {

    [CmdletBinding()]
    Param()

    $acl = Get-ACl -Path $sshAdminKeysFile

    # The first parameter enables inheritance for child objects - although that
    # doesn't actually have any effect in this case as the ACL is for a file.
    # The second parameter disables inheritance from parent containers.
    $acl.SetAccessRuleProtection($true, $false)

    # Add an ACL rule allowing administrators full control
    Add-AclRule -Acl $acl -Identity "Administrators" -Rights "FullControl" -AccessControl "Allow"

    # Add an ACL rule allowing SYSTEM full control
    Add-AclRule -Acl $acl -Identity "SYSTEM" -Rights "FullControl" -AccessControl "Allow"

    # Save the ACL
    $acl | Set-Acl

  }


}


Process {

  Foreach ($key in $SSHKey) {

    # Write the new SSH key to the admin keys file
    $key | Out-File -FilePath $sshAdminKeysFile -Encoding utf8 -Append

  }

}

End {

  # Set the ACL on the admin keys file
  Set-SSHAdminKeysAcl

}

