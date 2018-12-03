<#
 .Author
  Andrew Harris
  Microsoft Corporation
  aharri@microsoft.com

 .Synopsis
  Discover cPassword attributes in policies on a DC, looking for the "cpassword" attribute
  This is linked to MS14-025 vulnerability, which most customers simply "patch" but don't 
  do this search to manually look for existing cpassword.
 
 .Description
  This script is now a few generations better than one we provided publically as it:
  1. Provides account name
  2. Provides cpassword (encrypted as stored in SYSVOL)
  3. States if the account is _actually_ enabled or disabled
  
  In addition it automatically detects the SYSVOL which previously had to be provided.  This
  is only useful, however, if actually ran on the Domain Controller.

 .Link
  Custom code based off of: 
  https://support.microsoft.com/en-us/kb/2962486
#>


function Get-SettingsWithCPassword{
	param(
		[Parameter(Mandatory=$False)]
		[string]$Path = "$env:windir\SYSVOL\domain"
	 )
	#---------------------------------------------------------------------------------------------------------------
	$isGPModuleAvailable = $false
	$impactedPrefs = { "Groups.xml", "ScheduledTasks.xml","Services.xml", "DataSources.xml", "Drives.xml" }
	#----------------------------------------------------------------------------------------------------------------
	# import Group olicy module if available
	#----------------------------------------------------------------------------------------------------------------
	if (-not (Get-Module -name "GroupPolicy"))
	{
	   if (Get-Module -ListAvailable | 
			 Where-Object { $_.Name -ieq "GroupPolicy" })
		{
			$isGPModuleAvailable = $true
			Import-Module "GroupPolicy"
		}
		else
		{
			Write-Warning "Unable to import Group Policy module for PowerShell. Therefore, GPO guids will be reported. 
						   Run this script on DC to obtain the GPO names, or use the Get-GPO cmdlet (on DC) to obtain the GPO name from GPO guid."
		}
	}
	else
	{
		$isGPModuleAvailable = $true
	}
	#-----------------------------------------------------------------------------------
	# Check whether Path is valid. Enumerateerate all settings that contain cpassword. 
	#-----------------------------------------------------------------------------------
	if (Test-Path $Path )
	{
		Find-SettingsWithCpassword $Path
	}
	else
	{
		Write-Warning "No such directory: $Path"
	} 
}

Function Find-SettingsWithCpassword ( [string]$sysvolLocation )
{
    # GPMC tree paths
    $commonPath = " -> Preferences -> Control Panel Settings -> "
    $driveMapPath = " -> Preferences -> Windows Settings -> "
    
    # Recursively obtain all the xml files within the SYVOL location
    $impactedXmls = Get-ChildItem $sysvolLocation -Recurse -Filter "*.xml" | Where-Object { $impactedPrefs -cmatch $_.Name }
    
    
    # Each xml file contains multiple preferences. Iterate through each preference to check whether it
    # contains cpassword attribute and display it.
    foreach ( $file in $impactedXmls )
    {
        $fileFullPath = $file.FullName
        
        # Set GPP category. If file is located under Machine folder in SYSVOL
        # the setting is defined under computer configuration otherwise the 
        # setting is a to user configuration  
        if ( $fileFullPath.Contains("Machine") )
        {
            $category = "Computer Configuration"
        }
        elseif ( $fileFullPath.Contains("User") )
        {
            $category = "User Configuration"
        }
        else
        {
            $category = "Unknown"
        }
        # Obtain file content as XML
        try
        {
            [xml]$xmlFile = get-content $fileFullPath -ErrorAction Continue
        }
        catch [Exception]{
            Write-Output $_.Exception.Message
        }
        if ($null -eq $xmlFile)
        {
            continue
        }
        switch ( $file.BaseName )
        {
            Groups 
            { 
                $gppWithCpassword = $xmlFile.SelectNodes("Groups/User") | where-Object { [String]::IsNullOrEmpty($_.Properties.cpassword) -eq $false }
                $preferenceType = "Local Users"
            }
            ScheduledTasks
            {
                $gppWithCpassword  = $xmlFile.SelectNodes("ScheduledTasks/*") | where-Object { [String]::IsNullOrEmpty($_.Properties.cpassword) -eq $false }
                $preferenceType = "Scheduled Tasks"
            }
            DataSources
            {
                $gppWithCpassword = $xmlFile.SelectNodes("DataSources/DataSource") | where-Object { [String]::IsNullOrEmpty($_.Properties.cpassword) -eq $false }
                $preferenceType = "Data sources"
            }
            Drives
            {
                $gppWithCpassword = $xmlFile.SelectNodes("Drives/Drive") | where-Object { [String]::IsNullOrEmpty($_.Properties.cpassword) -eq $false }
                $preferenceType = "Drive Maps"
            }
            Services
            {
                $gppWithCpassword = $xmlFile.SelectNodes("NTServices/NTService") | where-Object { [String]::IsNullOrEmpty($_.Properties.cpassword) -eq $false }
                $preferenceType = "Services"
            }
            default
            {   # clear gppWithCpassword and preferenceType for next item.
                try
                {
                    Clear-Variable -Name gppWithCpassword -ErrorAction SilentlyContinue
                    Clear-Variable -Name preferenceType -ErrorAction SilentlyContinue
                }
                catch [Exception]{
                    Write-Output "cPassword enumeration issue."
                }
            }
        }
        if ($null -ne $gppWithCpassword){
            # Build GPO name from GUID extracted from filePath 
            $guidRegex = [regex]"\{(.*)\}"
            $match = $guidRegex.match($fileFullPath)
            if ($match.Success){
               $gpoGuid = $match.groups[1].value
               $gpoName = $gpoGuid
            }
            else{
               $gpoName = "Unknown"
            }
            if($isGPModuleAvailable -eq $true){
                try {   
                    $gpoInfo = Get-GPO -Guid $gpoGuid -ErrorAction Continue
                    $gpoName = $gpoInfo.DisplayName
                }
                catch [Exception] {
                    Write-Output $_.Exception.Message 
                }
            }
            # display prefrences that contain cpassword
            foreach ( $gpp in $gppWithCpassword )
            {
                if ( $preferenceType -eq "Drive Maps" )
                {
                    $prefLocation = $category + $driveMapPath + $preferenceType
                }
                else
                {
                    $prefLocation = $category + $commonPath + $preferenceType
                }
                $obj = New-Object -typeName PSObject 
                $obj | Add-Member -MemberType NoteProperty -Name GPOName    -Value ($gpoName)      -PassThru |
                       Add-Member -MemberType NoteProperty -name Preference -Value ($gpp.Name)     -PassThru |
                       Add-Member -MemberType NoteProperty -name Path       -Value ($prefLocation) -PassThru |
                       Add-Member -MemberType NoteProperty -Name Username   -Value ($gpp.Properties.userName)     -PassThru |
                       Add-Member -MemberType NoteProperty -Name cpassword   -Value ($gpp.Properties.cpassword)     -PassThru |
                       Add-Member -MemberType NoteProperty -Name AcctDisabled   -Value ($gpp.Properties.acctDisabled)
                Write-Output $obj 
            }
        } # end if $gppWithCpassword
    } # end foreach $file
} # end functions Get-PoliciesWithCpassword