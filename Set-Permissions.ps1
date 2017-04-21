#Function to set groups permissions in specified shares
# $share has to be FQDN

#Example:
#Set-Permissions -FileSystemAccessRights Read -objGroup $GroupName -domaingGroup $domain -Server $RWDC
#Set-Permissions -FileSystemAccessRights Modify -objGroup $GroupName -domaingGroup $domain -Server $RWDC
#Set-Permissions -FileSystemAccessRights FullControl -objGroup $GroupName -domaingGroup $domain -Server $RWDC
#Set-Permissions -FileSystemAccessRights ListDirectory -objGroup $GroupName -domaingGroup $domain -Server $RWDC

function Set-Permissions {
    param(
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "File System Rights Parameter not specified.")]
        [System.Security.AccessControl.FileSystemRights]$FileSystemAccessRights,
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "Group Name Parameter not specified.")]
        [string]$objGroup,
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "Domain Parameter not specified.")]
        [string]$domainGroup,
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $false, HelpMessage = "Domain Controller Parameter not specified.")]
        [string]$RWDC,
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = "ContainerInherit, ObjectInherit",
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags = "None",
        [System.Security.AccessControl.AccessControlType]$objType = "Allow"
    )
    Write-Output "Managing Permissions for $groupname in $share... please wait...`n"
    try {
        if ($RWDC) {
            $objsearch = (Get-ADGroup $groupname -Server $RWDC | Select Name).Name
        }
        else {
            $objsearch = (Get-ADGroup $groupname | Select Name).Name
        }
    }
    catch {
        Write-Host "Can't find Group $groupname in AD."
        break
    }
    [string]$objfinal = "$domaingroup" + "\" + $objsearch
    $NewAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($objfinal, $FileSystemAccessRights, $InheritanceFlags, $PropagationFlags, $objType)
    
    if ($currentACL) { Remove-Variable currentACL }
    
    $currentACL = Get-Acl $sharefull
    
    $var = 0
    while ($error -eq $true -or $var -eq 0) {
        try {
            $var++
            $error = $false
            Write-Host "Trying to apply permissions. Try no. $var ..."
            $currentACL.AddAccessRule($NewAccessRule)
            Write-Output "`DONE!`n"
        }
        catch {
            $error = $true
            New-Sleep 5
        }
    }
    Set-Acl -AclObject $currentACL $sharefull
}