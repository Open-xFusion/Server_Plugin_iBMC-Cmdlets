# Copyright (C) 2020-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.	
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: iBMC RAID Controller module Cmdlets #>

function Get-iBMCRAIDControllers {
<#
.SYNOPSIS
Query information about the RAID controller resource collection of a server.

.DESCRIPTION
Query information about the RAID controller resource collection of a server.
This cmdlet works only after BIOS boot is complete when the RAID controller card supports out-of-band management or after iBMA 2.0 has been installed and started.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[][]
Returns an array of PSObject indicates all RAID controller resources if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $RAID = Get-iBMCRAIDControllers -Session $Session
PS C:\> $RAID

Host                     : 192.168.1.1
Id                       : RAIDStorage0
Name                     : RAID Card1 Controller
Description              : RAID Controller
Status                   : @{State=Enabled; Health=OK}
SpeedGbps                : 12
FirmwareVersion          : 5.010.00-0839
SupportedDeviceProtocols : {SAS}
Manufacturer             :
Model                    : SAS3508
SupportedRAIDLevels      : {RAID0, RAID1, RAID5, RAID6...}
Mode                     : Non-RAID
CachePinnedState         : False
SASAddress               : 5505dac310072000
ConfigurationVersion     : 4.1610.00-0149
MemorySizeMiB            : 2048
MaintainPDFailHistory    : True
CopyBackState            : True
SmarterCopyBackState     : True
JBODState                : False
OOBSupport               : True
CapacitanceName          :
CapacitanceStatus        : @{State=Absent; Health=}
DriverInfo               : @{DriverName=; DriverVersion=}
DDRECCCount              : 0
MinStripeSizeBytes       : 65536
MaxStripeSizeBytes       : 1048576
Drives                   : {HDDPlaneDisk0, HDDPlaneDisk1}

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCRAIDControllersHealth
Set-iBMCRAIDController
Restore-iBMCRAIDController
Connect-iBMC
Disconnect-iBMC
#>
  [CmdletBinding()]
  param (
    [RedfishSession[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    $Session
  )

  begin {
  }

  process {
    Assert-ArrayNotNull $Session 'Session'

    $Logger.info("Invoke Get iBMC RAID controller resources function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC RAID controller resources now"))
      
      # server oem info
      $OEM = $RedfishSession.Oem
      $ExcludeProperties = @("@odata.id", "AssociatedCard", "MemberId", "PHYStatus")
      $Controllers = New-Object System.Collections.ArrayList
      $StoragePaths = Get-StoragePathCollection $RedfishSession
      $StoragePaths | ForEach-Object {
        $Storage = Invoke-RedfishRequest $RedfishSession $_ | ConvertFrom-WebResponse
        $Controller = Merge-OemProperties $Storage.StorageControllers[0] $OEM
        $CleanUpController = Copy-ObjectExcludes $Controller $ExcludeProperties

        $MixinId = New-Object PSObject
        $MixinId | Add-Member -MemberType NoteProperty "Id" $Storage.Id
        $MixinId | Add-Member -MemberType NoteProperty "Controller" $CleanUpController

        $Result = Merge-NestProperties $MixinId @("Controller")

        $Drives = New-Object System.Collections.ArrayList
        $Storage.Drives | ForEach-Object {
          $DriveOdataId = $_."@odata.id"
          $DriveId = $DriveOdataId.split("/")[-1]
          [Void] $Drives.Add($DriveId)
        }
        $Result | Add-Member -MemberType NoteProperty "Drives" $Drives

        [Void] $Controllers.Add($(Update-SessionAddress $RedfishSession $Result))
      }
      return ,$Controllers.ToArray()
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC RAID controller resources task"))
        [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock @($RedfishSession)))
      }
      $Results = Get-AsyncTaskResults $tasks
      return ,$Results
    }
    finally {
      Close-Pool $pool
    }
  }

  end {
  }
}

function Get-iBMCRAIDControllersHealth {
<#
.SYNOPSIS
Query health information about the RAID resources of a server.

.DESCRIPTION
Query health information about the RAID resources of a server including summary health status and every RAID controller health status.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[]
Returns PSObject indicates RAID health status of server if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $health = Get-iBMCRAIDControllersHealth -Session $session
PS C:\> $health | fl

Host            : 192.168.1.1
Summary         : @{HealthRollup=OK}
ID#RAIDStorage0 : @{Health=OK; State=Enabled; Name=RAID Card1 Controller}
ID#RAIDStorage1 : @{Health=OK; State=Enabled; Name=PCIe Card 5 (RAID) Controller}

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCRAIDControllers
Set-iBMCRAIDController
Restore-iBMCRAIDController
Connect-iBMC
Disconnect-iBMC
#>
  [CmdletBinding()]
  param (
    [RedfishSession[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    $Session
  )

  begin {
  }

  process {
    Assert-ArrayNotNull $Session 'Session'

    $Logger.info("Invoke Get iBMC RAID health function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC RAID health now"))

      $GetSystemPath = "/Systems/$($RedfishSession.Id)"
      $System = Invoke-RedfishRequest $RedfishSession $GetSystemPath | ConvertFrom-WebResponse
      
      # server oem info
      $OEM = $RedfishSession.Oem
      $Health = New-Object PSObject -Property @{
        Host    = $RedfishSession.Address;
        Summary = $System.Oem.$OEM.StorageSummary.Status;
      }

      $StatusPropertyOrder = @("Health", "State")
      $StoragePaths = Get-StoragePathCollection $RedfishSession
      $StoragePaths | ForEach-Object {
        $Storage = Invoke-RedfishRequest $RedfishSession $_ | ConvertFrom-WebResponse
        $Controller = $Storage.StorageControllers[0]
        $Status = Copy-ObjectProperties $Controller.Status $StatusPropertyOrder
        $Status | Add-member Noteproperty "Name" $Controller.Name
        $Health | Add-Member Noteproperty "ID#$($Storage.ID)" $Status
      }

      return $Health
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC RAID health task"))
        [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock @($RedfishSession)))
      }
      $Results = Get-AsyncTaskResults $tasks
      return ,$Results
    }
    finally {
      Close-Pool $pool
    }
  }

  end {
  }
}

function Set-iBMCRAIDController {
<#
.SYNOPSIS
Modify properties of the specified RAID controller of a server.

.DESCRIPTION
Modify properties of the specified RAID controller of a server.
This cmdlet works only after BIOS boot is complete when the RAID controller card supports out-of-band management or after iBMA 2.0 has been installed and started.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER StorageId
Indicates the identifier of the storage to modify.
The Id properties of "Get-iBMCRAIDControllers" cmdlet's return value represents Storage ID.

.PARAMETER CopyBackEnabled
Indicates Whether copyback is enabled.
Support values are powershell boolean value: $true(1), $false(0).

.PARAMETER SmarterCopyBackEnabled
Indicates Whether SMART error copyback is enable.
Before enabling this function, enable CopyBack first.
Support values are powershell boolean value: $true(1), $false(0).

.PARAMETER JBODEnabled
Indicates Whether JBOD is enable.
Support values are powershell boolean value: $true(1), $false(0).

.OUTPUTS
Null
Returns null if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> Set-iBMCRAIDController -Session $session -StorageId RAIDStorage0 `
          -CopyBackEnabled $true -SmarterCopyBackEnabled $true -JBODEnabled $true

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCRAIDControllers
Get-iBMCRAIDControllersHealth
Restore-iBMCRAIDController
Connect-iBMC
Disconnect-iBMC
#>
  [CmdletBinding()]
  param (
    [RedfishSession[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Session,

    [String[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $StorageId,

    [bool[]]
    [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $CopyBackEnabled,

    [bool[]]
    [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $SmarterCopyBackEnabled,

    [bool[]]
    [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $JBODEnabled
  )

  begin {
  }

  process {
    Assert-ArrayNotNull $Session 'Session'
    Assert-ArrayNotNull $StorageId 'StorageId'
    $StorageIdList = Get-MatchedSizeArray $Session $StorageId
    $CopyBackEnabledList = Get-OptionalMatchedSizeArray $Session $CopyBackEnabled
    $SmarterCopyBackEnabledList = Get-OptionalMatchedSizeArray $Session $SmarterCopyBackEnabled
    $JBODEnabledList = Get-OptionalMatchedSizeArray $Session $JBODEnabled

    $Logger.info("Invoke Set iBMC RAID controller resources function")

    $ScriptBlock = {
      param($RedfishSession, $StorageId, $Payload)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Set iBMC RAID controller now"))
      $Path = "/Systems/$($RedfishSession.Id)/Storages/$StorageId"

      # server oem info
      $OEM = $RedfishSession.Oem
      $FullfilPayload = @{
          "StorageControllers" = @(
          @{
            "Oem"= @{
              $OEM = $Payload;
            }
          }
        )
      }

      $Logger.info($(Trace-Session $RedfishSession "Sending payload: $($FullfilPayload | ConvertTo-Json -Depth 5)"))
      $Response = Invoke-RedfishRequest $RedfishSession $Path 'PATCH' $FullfilPayload
      Resolve-RedfishPartialSuccessResponse $RedfishSession $Response | Out-Null
      return $null
    }

    try {
      $ParametersList = New-Object System.Collections.ArrayList
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]

        if ($CopyBackEnabledList[$idx] -eq $false -and $SmarterCopyBackEnabledList[$idx] -eq $true) {
          throw $(Get-i18n ERROR_COPYBACK_SHOULD_BE_ENABLED)
        }

        $Payload = Remove-EmptyValues @{
          "CopyBackState" = $CopyBackEnabledList[$idx];
          "SmarterCopyBackState" = $SmarterCopyBackEnabledList[$idx];
          "JBODState" = $JBODEnabledList[$idx];
        }

        if ($Payload.Count -eq 0) {
          throw $(Get-i18n ERROR_NO_UPDATE_PAYLOAD)
        }

        $Parameters = @($RedfishSession, $StorageIdList[$idx], $Payload)
        [Void] $ParametersList.Add($Parameters)
      }

      $pool = New-RunspacePool $Session.Count
      $tasks = New-Object System.Collections.ArrayList
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Set iBMC RAID controller task"))
        [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock $ParametersList[$idx]))
      }

      $Results = Get-AsyncTaskResults $tasks
      return ,$Results
    }
    finally {
      Close-Pool $pool
    }
  }

  end {
  }
}

function Restore-iBMCRAIDController {
<#
.SYNOPSIS
Restore default settings of the specified controller of a server.

.DESCRIPTION
Restore default settings of the specified controller of a server.
This cmdlet works only after BIOS boot is complete when the RAID controller card supports out-of-band management or after iBMA 2.0 has been installed and started.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER StorageId
Indicates the identifier of the storage to restore.
The Id properties of "Get-iBMCRAIDControllers" cmdlet's return value represents Storage ID.

.OUTPUTS
PSObject[]
Returns null if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> Restore-iBMCRAIDController -Session $Session -StorageId RAIDStorage0

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCRAIDControllers
Get-iBMCRAIDControllersHealth
Set-iBMCRAIDController
Connect-iBMC
Disconnect-iBMC
#>
  [CmdletBinding()]
  param (
    [RedfishSession[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    $Session,

    [String[]]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
    $StorageId
  )

  begin {
  }

  process {
    Assert-ArrayNotNull $Session 'Session'
    Assert-ArrayNotNull $StorageId 'StorageId'
    $StorageIdList = Get-MatchedSizeArray $Session $StorageId

    $Logger.info("Invoke Restore iBMC RAID controller resources function")

    $ScriptBlock = {
      param($RedfishSession, $StorageId)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Restore iBMC RAID controller now"))
      
      # server oem info
      $OEM = $RedfishSession.Oem
      $Action = "Actions/Oem/$OEM/Storage.RestoreStorageControllerDefaultSettings"
      $Path = "/Systems/$($RedfishSession.Id)/Storages/$StorageId/$Action"
      $Response = Invoke-RedfishRequest $RedfishSession $Path 'POST'
      Resolve-RedfishPartialSuccessResponse $RedfishSession $Response | Out-Null
      return $null
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Parameters = @($RedfishSession, $StorageIdList[$idx])
        $Logger.info($(Trace-Session $RedfishSession "Submit Restore iBMC RAID controller task"))
        [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock $Parameters))
      }
      $Results = Get-AsyncTaskResults $tasks
      return ,$Results
    }
    finally {
      Close-Pool $pool
    }
  }

  end {
  }
}