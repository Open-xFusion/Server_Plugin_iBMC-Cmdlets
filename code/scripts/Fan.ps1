# Copyright (C) 2020-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.	
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: iBMC Fan module Cmdlets #>

function Get-iBMCFans {
<#
.SYNOPSIS
Query information about the fan resource collection of a server.

.DESCRIPTION
Query information about the fan resource collection of a server.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[][]
Returns an array of PSObject indicates all fan resources if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $FansArray = Get-iBMCFans -Session $session
PS C:\> $FansArray

Host                      : 192.168.1.1
MemberId                  : 0
Name                      : Fan Module1 Front
Reading                   : 4920
LowerThresholdNonCritical :
LowerThresholdCritical    :
LowerThresholdFatal       :
UpperThresholdNonCritical :
UpperThresholdCritical    :
UpperThresholdFatal       :
MinReadingRange           :
MaxReadingRange           :
Status                    : @{State=Enabled; Health=OK}
ReadingUnits              : RPM
PartNumber                : 02311VSF
Position                  : chassis
SpeedRatio                : 32

Host                      : 192.168.1.1
MemberId                  : 1
Name                      : Fan Module2 Front
Reading                   : 4800
LowerThresholdNonCritical :
LowerThresholdCritical    :
LowerThresholdFatal       :
UpperThresholdNonCritical :
UpperThresholdCritical    :
UpperThresholdFatal       :
MinReadingRange           :
MaxReadingRange           :
Status                    : @{State=Enabled; Health=OK}
ReadingUnits              : RPM
PartNumber                : 02311VSF
Position                  : chassis
SpeedRatio                : 32

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCFansHealth
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

    $Logger.info("Invoke Get iBMC Fan resources function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC Fan resources now"))

      $GetThermalPath = "/Chassis/$($RedfishSession.Id)/Thermal"
      $Thermal = Invoke-RedfishRequest $RedfishSession $GetThermalPath | ConvertFrom-WebResponse
      
      # server oem info
      $OEM = $RedfishSession.Oem
      $FanList = New-Object System.Collections.ArrayList
      $Thermal.Fans | ForEach-Object {
        $CleanupOdata = $_ | Clear-OdataProperties
        $Cleanup =  Merge-OemProperties $CleanupOdata $OEM
        [Void] $FanList.Add($(Update-SessionAddress $RedfishSession $Cleanup))
      }
      return ,$FanList.ToArray()
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC Fan resources task"))
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

function Get-iBMCFansHealth {
<#
.SYNOPSIS
Query health information about the fan resources of a server.

.DESCRIPTION
Query health information about the fan resources of a server including summary health status and every fan health status.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[]
Returns PSObject indicates fan health status of server if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $health = Get-iBMCFansHealth -Session $session
PS C:\> $health | fl

Host       : 192.168.1.1
Summary    : @{HealthRollup=OK}
MemberId#0 : @{Health=OK; State=Enabled; Name=Fan Module1 Front}
MemberId#1 : @{Health=OK; State=Enabled; Name=Fan Module2 Front}
MemberId#2 : @{Health=OK; State=Enabled; Name=Fan Module3 Front}
MemberId#3 : @{Health=OK; State=Enabled; Name=Fan Module4 Front}

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

Get-iBMCFans
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

    $Logger.info("Invoke Get iBMC fan health function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC fan Health now"))

      $GetThermalPath = "/Chassis/$($RedfishSession.Id)/Thermal"
      $Thermal = Invoke-RedfishRequest $RedfishSession $GetThermalPath | ConvertFrom-WebResponse
      
      # server oem info
      $OEM = $RedfishSession.Oem
      $Health = New-Object PSObject -Property @{
        Host    = $RedfishSession.Address;
        Summary = $Thermal.Oem.$OEM.FanSummary.Status;
      }

      $StatusPropertyOrder = @("Health", "State")
      $Thermal.Fans | ForEach-Object {
        $Status = Copy-ObjectProperties $_.Status $StatusPropertyOrder
        $Status | Add-member Noteproperty "Name" $_.Name
        $Health | Add-Member Noteproperty "MemberId#$($_.MemberId)" $Status
      }

      return $Health
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC fan Health task"))
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