# Copyright (C) 2020-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: A Redfish Client PowerShell scripts. #>

# . $PSScriptRoot/Common.ps1

try { [RedfishSession] | Out-Null } catch {
Add-Type @'
  public class RedfishSession
  {
    public System.String Id ;
    public System.String Name ;
    public System.String ManagerType ;
    public System.String FirmwareVersion ;
    public System.String UUID ;
    public System.String Model ;
    public System.String Health ;
    public System.String State ;
    public System.String DateTime ;
    public System.String DateTimeLocalOffset ;
    public System.String Oem ;

    public System.String Address ;
    public System.String BaseUri ;
    public System.String Location ;
    public System.Boolean Alive ;
    public System.String AuthToken ;
    public System.Boolean TrustCert ;
  }
'@
}

function New-RedfishSession {
<#
.SYNOPSIS
Create sessions for iBMC Redfish REST API.

.DESCRIPTION
Creates sessions for iBMC Redfish REST API. The session object returned which has members:

- Id - ID of the specified manager resource.
- Name - Name of the specified manager resource.
- ManagerType - Specific type of the specified manager resource.
- FirmwareVersion - Firmware version of the specified manager resource.
- UUID - UUID of the specified manager resource.
- Model - Model of the specified manager resource.
- Health - manager resource health status.
- State - whether the manager resource is enabled.
- DateTime - System time of the specified manager resource.
- DateTimeLocalOffset - Time zone of the specified manager resource.
- Oem - Custom properties.
- Address - iBMC IP address
- BaseUri - Redfish API
- Location - which is used for logging out of the session
- Alive - identify whether the session is alive or not
- AuthToken - identify the session
- TrustCert - server certificate authentication is disabled or enabled

.PARAMETER Address
IP address or Hostname of the target iBMC Redfish API.

.PARAMETER Username
Username of iBMC account to access the iBMC Redfish API.

.PARAMETER Password
Password of iBMC account to access the iBMC Redfish API.

.PARAMETER Credential
PowerShell PSCredential object having username and passwword of iBMC account to access the iBMC.

.PARAMETER TrustCert
If this switch parameter is present then server certificate authentication is disabled for this iBMC connection.
If not present, server certificate is enabled by default.

.NOTES
See typical usage examples in the Redfish.ps1 file installed with this module.

.INPUTS
System.String
You can pipe the Address i.e. the hostname or IP address to New-RedfishSession.

.OUTPUTS
System.Management.Automation.PSCustomObject
New-RedfishSession returns a RedfishSession Object which contains - AuthToken, BaseUri, Location, TrustCert and Alive.

.EXAMPLE
PS C:\> $session = New-RedfishSession -Address 192.168.1.1 -Username root -Password password


PS C:\> $session | fl


RootUri      : https://192.168.1.1/redfish/v1/
X-Auth-Token : this-is-a-sample-token
Location     : https://192.168.1.1/redfish/v1/Sessions/{session-id}/
RootData     : @{@odata.context=/redfish/v1/$metadata#ServiceRoot/; @odata.id=/redfish/v1/; @odata.type=#ServiceRoot.1.0.0.ServiceRoot; AccountService=; Chassis=; EventService=; Id=v1; JsonSchemas=; Links=; Managers=; Name=HP RESTful Root Service; Oem=; RedfishVersion=1.0.0; Registries=; SessionService=; Systems=; UUID=8dea7372-23f9-565f-9396-2cd07febbe29}

.EXAMPLE
PS C:\> $credential = Get-Credential
PS C:\> $session = New-RedfishSession -Address 192.168.1.1 -Credential $credential
PS C:\> $session | fl

RootUri      : https://192.168.1.1/redfish/v1/
X-Auth-Token : this-is-a-sample-token
Location     : https://192.168.1.1/redfish/v1/Sessions/{session-id}/
RootData     : @{@odata.context=/redfish/v1/$metadata#ServiceRoot/; @odata.id=/redfish/v1/; @odata.type=#ServiceRoot.1.0.0.ServiceRoot; AccountService=; Chassis=; EventService=; Id=v1; JsonSchemas=; Links=; Managers=; Name=HP RESTful Root Service; Oem=; RedfishVersion=1.0.0; Registries=; SessionService=; Systems=; UUID=8dea7372-23f9-565f-9396-2cd07febbe29}

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  [cmdletbinding(DefaultParameterSetName = 'AccountSet')]
  param
  (
    [System.String]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    $Address,

    [System.String]
    [parameter(ParameterSetName = "AccountSet", Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
    $Username,

    [System.String]
    [parameter(ParameterSetName = "AccountSet", Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
    $Password,

    [PSCredential]
    [parameter(ParameterSetName = "CredentialSet", Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
    $Credential,

    [switch]
    [parameter(Mandatory = $false)]
    $TrustCert
  )

  # Fetch session with Credential by default if `Credential` is set
  if ($null -ne $Credential) {
    $username = $Credential.UserName
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $passwd = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  }
  elseif ($Username -ne '' -and $Password -ne '') {
    $username = $username
    $passwd = $password
  }
  else {
    throw $i18n.ERROR_INVALID_CREDENTIALS
  }

  # create a new session object for redfish server of $address
  $session = New-Object RedfishSession
  $session.Address = $Address
  $session.TrustCert = $TrustCert

  [IPAddress]$ipAddress = $null
  if ([IPAddress]::TryParse($Address, [ref]$ipAddress)) {
    if (([IPAddress]$Address).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $Address.IndexOf('[') -eq -1) {
      $Address = '[' + $Address + ']'
    }
  }

  $session.BaseUri = "https://$Address"


  $Logger.info("Create Redfish session For $($session.BaseUri) now")

  # New session
  $path = "/SessionService/Sessions"
  $method = "POST"
  $payload = @{'UserName' = $username; 'Password' = $passwd; }
  $response = Invoke-RedfishRequest -Session $session -Path $path -Method $method -Payload $payload
  $response.close()

  # set session properties
  $session.Location = $response.Headers['Location']
  $session.AuthToken = $response.Headers['X-Auth-Token']
  $session.Alive = $true

  # get bmc resource Id (BladeN, SwiN, N)
  $managers = Invoke-RedfishRequest -Session $session -Path "/Managers" | ConvertFrom-WebResponse
  $managerOdataId = $managers.Members[0].'@odata.id'

  # get bmc manager
  $manager = Invoke-RedfishRequest -Session $session -Path $managerOdataId | ConvertFrom-WebResponse

  $session.Id = $manager.Id
  $session.Name = $manager.Name
  $session.ManagerType = $manager.ManagerType
  $session.FirmwareVersion = $manager.FirmwareVersion
  $session.UUID = $manager.UUID
  $session.Model = $manager.Model
  $session.DateTime = $manager.DateTime
  $session.DateTimeLocalOffset = $manager.DateTimeLocalOffset
  $session.State = $manager.Status.State
  $session.Health = $manager.Status.Health
  if (!$manager.Oem -or !$manager.Oem.psobject.properties.name) {
    $session.Oem = 'Huawei'
  } else {
    $session.Oem = $manager.Oem.psobject.properties.name
  }
  return $session
}


function Close-RedfishSession {
<#
.SYNOPSIS
Close a specified session of iBMC Redfish Server.

.DESCRIPTION
Close a specified session of iBMC Redfish Server by sending HTTP Delete request to location holds by "Location" property in Session object passed as parameter.

.PARAMETER Session
Session object that created by New-RedfishSession cmdlet.

.NOTES
The Session object will be detached from iBMC Redfish Server. And the Session can not be used by cmdlets which required Session parameter again.

.INPUTS
You can pipe the session object to Close-RedfishSession. The session object is obtained from executing New-RedfishSession cmdlet.

.OUTPUTS
This cmdlet does not generate any output.


.EXAMPLE
PS C:\> Close-RedfishSession -Session $session
PS C:\>

This will disconnect the session given in the variable $session

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  param
  (
    [RedfishSession]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position=0)]
    $session
  )

  if ($null -eq $session -or $session -isnot [RedfishSession]) {
    throw $([string]::Format($(Get-i18n ERROR_PARAMETER_ILLEGAL), 'Session'))
  }

  $method = "DELETE"
  $path = $session.Location
  $response = Invoke-RedfishRequest -Session $session -Path $path -Method $method
  $response.close()

  $success = $response.StatusCode.value__ -lt 400
  $session.Alive = !$success
  return $session
}


function Test-RedfishSession {
<#
.SYNOPSIS
Test whether a specified session of iBMC Redfish Server is still alive

.DESCRIPTION
Test whether a specified session of iBMC Redfish Server is still alive by sending a HTTP get request to Session Location Uri.

.PARAMETER Session
Session object that created by New-RedfishSession cmdlet.

.INPUTS
You can pipe the session object to Test-RedfishSession. The session object is obtained from executing New-RedfishSession cmdlet.

.OUTPUTS
true if still alive else false


.EXAMPLE
PS C:\> Test-RedfishSession -Session $session
PS C:\>

true

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  param
  (
    [RedfishSession]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position=0)]
    $Session
  )

  if ($null -eq $session -or $session -isnot [RedfishSession]) {
    throw $([string]::Format($(Get-i18n ERROR_PARAMETER_ILLEGAL), 'Session'))
  }

  try {
    $method = "GET"
    $path = $session.Location
    Invoke-RedfishRequest -Session $session -Path $path -Method $method | Out-Null
  } catch {
    # we do not care about the reason of failure.
    # if any exception is thrown, we treat it as session timeout
    $session.Alive = $false
  }

  return $session
}

function Wait-RedfishTasks {
<#
.SYNOPSIS
Wait redfish tasks util success or failed

.DESCRIPTION
Wait redfish tasks util success or failed

.PARAMETER Session
Session array that created by New-RedfishSession cmdlet.

.PARAMETER Task
Task array that return by redfish async job API

.OUTPUTS

.EXAMPLE
PS C:\> Wait-RedfishTasks $Sessions $Tasks
PS C:\>

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    $ThreadPool,

    [RedfishSession[]]
    [parameter(Mandatory = $true, Position=1)]
    $Sessions,

    [PSObject[]]
    [parameter(Mandatory = $true, Position=2)]
    $Tasks,

    [Parameter(Mandatory = $false, Position = 3)]
    [switch]
    $ShowProgress
  )

  begin {
    Assert-NotNull $ThreadPool
    Assert-ArrayNotNull $Sessions
    Assert-ArrayNotNull $Tasks
  }

  process {
    function Write-TaskProgress($RedfishSession, $Task) {
      # server oem info
      $OEM = $RedfishSession.Oem
      if ($ShowProgress) {
        if ($Task -isnot [Exception]) {
          $TaskState = $Task.TaskState
          if ($TaskState -eq 'Running') {
            $TaskPercent = $Task.Oem.$OEM.TaskPercentage
            if ($null -eq $TaskPercent) {
              $TaskPercent = 0
            } else {
              $TaskPercent = [int]$TaskPercent.replace('%', '')
            }

            $Logger.Info($(Trace-Session $RedfishSession "Task percent: $TaskPercent"))
            Write-Progress -Id $Task.Guid -Activity $Task.ActivityName -PercentComplete $TaskPercent `
              -Status "$($TaskPercent)% $(Get-i18n MSG_PROGRESS_PERCENT)"
          }
          elseif ($TaskState -eq 'Completed') {
            $Logger.Info($(Trace-Session $RedfishSession "Task Completed"))
            Write-Progress -Id $Task.Guid -Activity $Task.ActivityName -Completed -Status $(Get-i18n MSG_PROGRESS_COMPLETE)
          }
          elseif ($TaskState -eq 'Exception') {
            $ToJson = $Task | ConvertTo-Json
            $Logger.Info($(Trace-Session $RedfishSession "Task failed. Response: $ToJson"))
            Write-Progress -Id $Task.Guid -Activity $Task.ActivityName -Completed -Status $(Get-i18n MSG_PROGRESS_FAILED)
          }
        }
      }
    }

    $Logger.info("Start wait for all redfish tasks done")

    $GuidPrefix = [string] $(Get-RandomIntGuid)
    # initialize tasks
    for ($idx=0; $idx -lt $Tasks.Count; $idx++) {
      $Task = $Tasks[$idx]
      $Session = $Sessions[$idx]
      if ($Task -isnot [Exception] -and $null -ne $Task) {
        $TaskGuid = [int]$($GuidPrefix + $idx)
        $Task | Add-Member -MemberType NoteProperty 'index' $idx
        $Task | Add-Member -MemberType NoteProperty 'Guid' $TaskGuid
        $Task | Add-Member -MemberType NoteProperty 'ActivityName' "[$($Session.Address)] $($Task.Name)"
        Write-TaskProgress $Session $Task
      }
    }

    while ($true) {
      $RunningTasks = @($($Tasks | Where-Object {$_ -isnot [Exception]} | Where-Object TaskState -in @('Running', 'New')))
      $Logger.info("Remain running task count: $($RunningTasks.Count)")

      if ($RunningTasks.Count -eq 0) {
        break
      }
      Start-Sleep -Seconds 1
      # filter running task and fetch task new status
      $AsyncTasks = New-Object System.Collections.ArrayList
      for ($idx=0; $idx -lt $RunningTasks.Count; $idx++) {
        $RunningTask = $RunningTasks[$idx]
        $Parameters = @($Sessions[$RunningTask.index], $RunningTask)
        $ScriptBlock = {
          param($RedfishSession, $RunningTask)
          return $(Get-RedfishTask $RedfishSession $RunningTask)
        }
        [Void] $AsyncTasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock $Parameters))
      }
      # new updated task list
      $ProcessedTasks = @($(Get-AsyncTaskResults $AsyncTasks))
      for ($idx=0; $idx -lt $ProcessedTasks.Count; $idx++) {
        $ProcessedTask = $ProcessedTasks[$idx]
        $RedfishSession = $Sessions[$ProcessedTask.index]
        # update task
        $Tasks[$ProcessedTask.index] = $ProcessedTask
        Write-TaskProgress $RedfishSession $ProcessedTask
      }
    }

    $FinishedTasks = @($($Tasks | Where-Object {$_ -isnot [Exception]}))
    for ($idx=0; $idx -lt $FinishedTasks.Count; $idx++) {
      $FinishedTask = $FinishedTasks[$idx]
      $RedfishSession = $Sessions[$FinishedTask.index]
      $Properties = @(
        "^Id$", "^Name$", "^ActivityName$", "^TaskState$",
        "^StartTime$", "^EndTime$", "^TaskStatus$"
      )
      $CleanTask = Copy-ObjectProperties $FinishedTask $Properties
      $OEM = $RedfishSession.Oem
      $TaskPercent = "None"
      if ($null -ne $FinishedTask.Oem.$OEM.TaskPercentage) {
        $TaskPercent = $FinishedTask.Oem.$OEM.TaskPercentage
      }
      $CleanTask | Add-Member -MemberType NoteProperty "TaskPercent" $TaskPercent
      if ($FinishedTask.TaskState -ne $BMC.TaskState.Completed) {
        # for remote url and local /tmp directory, the response is different 
        $Message = "None"
        if ($null -ne $FinishedTask."error") {
          $Logger.info("return response contain error member")
          $Message = $FinishedTask."error"."@Message.ExtendedInfo"[0]."Message"
        } elseif ($null -ne $FinishedTask."Messages") {
          $Message = $FinishedTask."Messages"
        }
        $CleanTask | Add-Member -MemberType NoteProperty "Messages" $Message
      }
      $CleanTask = $(Update-SessionAddress $RedfishSession $CleanTask)
      # update task
      $Tasks[$FinishedTask.index] = $CleanTask
    }


    $Logger.info("All redfish tasks done")
    return ,$Tasks
  }

  end {
  }
}


function Wait-SPFileTransfer {
<#
.SYNOPSIS
Wait SP file transfer util success or failed

.DESCRIPTION
Wait SP file transfer util success or failed

.PARAMETER Session
Session array that created by New-RedfishSession cmdlet.

.PARAMETER Task
Task array that return by redfish async job API

.OUTPUTS

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    $ThreadPool,

    [RedfishSession[]]
    [parameter(Mandatory = $true, Position=1)]
    $Sessions,

    [PSObject[]]
    [parameter(Mandatory = $true, Position=2)]
    $SPFWUpdates,

    [Parameter(Mandatory = $false, Position = 3)]
    [switch]
    $ShowProgress
  )

  begin {
    Assert-NotNull $ThreadPool
    Assert-ArrayNotNull $Sessions
    Assert-ArrayNotNull $SPFWUpdates
  }

  process {
    function Write-SPTransferProgress($RedfishSession, $SPFWUpdate) {
      if ($ShowProgress) {
        if ($SPFWUpdate -isnot [Exception]) {
          # percent is reliable, transfer state is not reliable
          $Percent = $SPFWUpdate.TransferProgressPercent
          if ([string]::IsNullOrEmpty($Percent)) {
            $Percent = 0
          }
          $Logger.Info($(Trace-Session $RedfishSession "Task $($SPFWUpdate.ActivityName) is $Percent%"))
          if ($Percent -ge 0 -and $Percent -lt 100) {
            Write-Progress -Id $SPFWUpdate.Guid -Activity $SPFWUpdate.ActivityName -PercentComplete $Percent `
            -Status "$($Percent)% $(Get-i18n MSG_PROGRESS_PERCENT)"
          } elseif ($Percent -eq 100) {
            Write-Progress -Id $SPFWUpdate.Guid -Activity $SPFWUpdate.ActivityName -Status $(Get-i18n MSG_PROGRESS_COMPLETE)
          } elseif ($Percent -lt 0) {
            Write-Progress -Id $SPFWUpdate.Guid -Activity $SPFWUpdate.ActivityName -Status $(Get-i18n MSG_PROGRESS_FAILED)
          }
        }
      }
    }

    $Logger.info("Start wait for all SPFW Update files transfer done")
    $GuidPrefix = [string] $(Get-RandomIntGuid)
    # initialize tasks
    for ($idx=0; $idx -lt $SPFWUpdates.Count; $idx++) {
      $SPFWUpdate = $SPFWUpdates[$idx]
      $Session = $Sessions[$idx]
      if ($SPFWUpdate -isnot [Exception]) {
        $Guid = [int]$($GuidPrefix + $idx)
        $SPFWUpdate | Add-Member -MemberType NoteProperty 'index' $idx
        $SPFWUpdate | Add-Member -MemberType NoteProperty 'Guid' $Guid
        $SPFWUpdate | Add-Member -MemberType NoteProperty 'ActivityName' "[$($Session.Address)] $($SPFWUpdate.Name)"
        $SPFWUpdate | Add-Member -MemberType NoteProperty 'TargetFileName' $SPFWUpdate.TransferFileName
        Write-SPTransferProgress $Session $SPFWUpdate
      }
    }

    $FirstRound = $true
    while ($true) {
      if ($FirstRound) {
        $FirstRound = $false
        $Transfering = @($($SPFWUpdates | Where-Object {$_ -isnot [Exception]} | Where-Object {$_.TransferState -ne 'Failure'}))
      } else {
        # current base on the transfer progress to determine task running or not
        # TransferState is not reliable
        $Transfering = @($($SPFWUpdates | Where-Object {$_ -isnot [Exception]} | Where-Object {($_.TransferProgressPercent -ge 0 -and $_.TransferProgressPercent -lt 100) -or [string]::IsNullOrEmpty($_.TransferProgressPercent)}))
      }
      $Logger.info("Remain Transfering task count: $($Transfering.Count)")
      if ($Transfering.Count -eq 0) {
        break
      }
      Start-Sleep -Milliseconds 1000
      # filter running task and fetch task new status
      $AsyncTasks = New-Object System.Collections.ArrayList
      for ($idx=0; $idx -lt $Transfering.Count; $idx++) {
        $Pending = $Transfering[$idx]
        $Parameters = @($Sessions[$Pending.index], $Pending)
        $ScriptBlock = {
          param($RedfishSession, $Pending)
          $SPFWUpdate = Get-SPFWUpdate $RedfishSession $Pending
          return $SPFWUpdate
        }
        [Void] $AsyncTasks.Add($(Start-ScriptBlockThread $pool $ScriptBlock $Parameters))
      }
      # new updated task list
      $Processed = @($(Get-AsyncTaskResults $AsyncTasks))
      for ($idx=0; $idx -lt $Processed.Count; $idx++) {
        $ProcessedTask = $Processed[$idx]
        $RedfishSession = $Sessions[$ProcessedTask.index]
        # update task
        $SPFWUpdates[$ProcessedTask.index] = $ProcessedTask
        Write-SPTransferProgress $RedfishSession $ProcessedTask
      }
    }

    $FinishedFiles = @($($SPFWUpdates | Where-Object {$_ -isnot [Exception]}))
    for ($idx=0; $idx -lt $FinishedFiles.Count; $idx++) {
      $Finished = $FinishedFiles[$idx]
      $RedfishSession = $Sessions[$Finished.index]
      $Properties = @(
        "^Name$", "^ActivityName$", "^TransferState$", "^TransferFileName$",
        "^TransferProgressPercent$", "^FileList$", "^Messages$"
      )
      $Clone = Copy-ObjectProperties $Finished $Properties
      $SPFWUpdates[$Finished.index] = Update-SessionAddress $RedfishSession $Clone
    }

    $Logger.info("All SPFW Update file transfer done")
    return $SPFWUpdates
  }

  end {
  }
}

function Get-SPFWUpdate {
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $Session,

    [PSObject]
    [parameter(Mandatory = $true, Position=1)]
    $SPFWUpdate
  )

  begin {
    Assert-NotNull $Session
    Assert-NotNull $SPFWUpdate
  }

  process {
    function Update-FileListIfNeccess($Session, $SPFWUpdate) {
      $SuccessStatus = @('Completed', 'Success')
      if ($SPFWUpdate.TransferState -in $SuccessStatus) {
        # try to get new FileList after success
        Start-Sleep -Seconds 3
        $TryTimes = 20
        while ($TryTimes -gt 0) {
          $SPUPdateData = Invoke-RedfishRequest $Session $OdataId | ConvertFrom-WebResponse
          if ($null -ne $SPUPdateData) {
            $Logger.info("update the sp firmware update information")
            $SPFWUpdate.FileList = $SPUPdateData.FileList
            $SPFWUPdate.TransferProgressPercent = $SPUPdateData.TransferProgressPercent
            $SPFWUPdate.TransferState = $SPUPdateData.TransferState
            break
          }
          $TryTimes = $TryTimes - 1
          Start-Sleep -Seconds 1
        }
      }
      return $SPFWUpdate
    }

    $OdataId = $SPFWUpdate.'@odata.id'
    $SuccessStatus = @('Completed', 'Success')
    if ($SPFWUpdate.TransferState -in $SuccessStatus) {
      return Update-FileListIfNeccess $Session $SPFWUpdate
    } else {
      $NewSPFWUpdate = Invoke-RedfishRequest $Session $OdataId | ConvertFrom-WebResponse
      $NewSPFWUpdate | Add-Member -MemberType NoteProperty 'index' $SPFWUpdate.index
      $NewSPFWUpdate | Add-Member -MemberType NoteProperty 'Guid' $SPFWUpdate.Guid
      $NewSPFWUpdate | Add-Member -MemberType NoteProperty 'ActivityName' $SPFWUpdate.ActivityName
      $NewSPFWUpdate | Add-Member -MemberType NoteProperty 'TargetFileName' $SPFWUpdate.TargetFileName
      return Update-FileListIfNeccess $Session $NewSPFWUpdate
    }
  }

  end {
  }
}

function Get-RedfishTask {
<#
.SYNOPSIS
Wait a redfish task util success or failed

.DESCRIPTION
Wait a redfish task util success or failed

.PARAMETER Session
Session object that created by New-RedfishSession cmdlet.

.PARAMETER Task
Task object that return by redfish async job API

.OUTPUTS

.EXAMPLE
PS C:\> Wait-RedfishTask $session $task
PS C:\>

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

#>
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $Session,

    [PSObject]
    [parameter(Mandatory = $true, Position=1)]
    $Task
  )

  begin {
    Assert-NotNull $Session
    Assert-NotNull $Task
  }

  process {
    $TaskOdataId = $Task.'@odata.id'
    $NewTask = Invoke-RedfishRequest $Session $TaskOdataId | ConvertFrom-WebResponse
    $NewTask | Add-Member -MemberType NoteProperty 'index' $Task.index
    $NewTask | Add-Member -MemberType NoteProperty 'Guid' $Task.Guid
    $NewTask | Add-Member -MemberType NoteProperty 'ActivityName' $Task.ActivityName
    return $NewTask
  }

  end {
  }
}

function Invoke-RedfishFirmwareUpload {
  [cmdletbinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $Session,

    [System.String]
    [parameter(Mandatory = $true, Position=1)]
    $FileName,

    [System.String]
    [parameter(Mandatory = $true, Position=2)]
    $FilePath,

    [Switch]
    [parameter(Mandatory = $false, Position=3)]
    $ContinueEvenFailed
  )

  $Logger.info($(Trace-Session $Session "Uploading $FilePath as $FileName to ibmc"))
  $Request = New-RedfishRequest $Session '/UpdateService/FirmwareInventory' 'POST'
  $Request.Timeout = 300 * 1000
  $Request.ReadWriteTimeout = 300 * 1000
  try {
    $UTF8Encoder = [System.Text.Encoding]::UTF8
    $Boundary = "----$($(Get-Date).Ticks)"
    $BoundaryAsBytes = $UTF8Encoder.GetBytes("--$Boundary`r`n")

    $Request.ContentType = "multipart/form-data; boundary=$Boundary"
    $Request.KeepAlive = $true

    $RequestStream = $Request.GetRequestStream()
    $RequestStream.Write($BoundaryAsBytes, 0, $BoundaryAsBytes.Length)

    $Header = "Content-Disposition: form-data; name=`"imgfile`"; filename=`"$($FileName)`"`
      `r`n`r`n"
    $HeaderAsBytes = $UTF8Encoder.GetBytes($Header)
    $RequestStream.Write($HeaderAsBytes, 0, $HeaderAsBytes.Length)

    $bytesRead = 0
    $Buffer = New-Object byte[] 4096
    $FileStream = New-Object IO.FileStream $FilePath ,'Open','Read'
    while (($bytesRead = $FileStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
      $RequestStream.Write($Buffer, 0, $bytesRead)
    }
    $FileStream.Close()

    $Trailer = $UTF8Encoder.GetBytes("`r`n--$boundary--`r`n")
    $RequestStream.Write($Trailer, 0, $Trailer.Length)
    $RequestStream.Close()

    $Response = $Request.GetResponse() | ConvertFrom-WebResponse
    return $Response.success
  }
  catch {
    # .Net HttpWebRequest will throw Exception if response is not success (status code is great than 400)
    Resolve-RedfishFailureResponse $Session $Request $_ $ContinueEvenFailed
  }
  finally {
    if ($null -ne $RequestStream -and $RequestStream -is [System.IDisposable]) {
      $RequestStream.Dispose()
    }
  }
}

function Invoke-FileUploadIfNeccessary ($RedfishSession, $ImageFilePath, $SupportSchema) {
  # iBMC local storage protocol handle
  $IsBMCFileProtocol = ($ImageFilePath.StartsWith("file:///tmp", "CurrentCultureIgnoreCase") `
                          -or $ImageFilePath.StartsWith("/tmp", "CurrentCultureIgnoreCase"))
  if ($IsBMCFileProtocol -and 'file' -in $SupportSchema) {
    return $ImageFilePath
  }

  $SupportSchemaString = $SupportSchema -join ", "
  $SecureFileUri = $ImageFilePath
  if($ImageFilePath -match "//(.+):(.+)@") {
    $SecureFileUri = $ImageFilePath -replace "//(.+):(.+)@", "//****:****@"
  }

  $Schema = Get-NetworkUriSchema $ImageFilePath
  if ($Schema -notin $SupportSchema) {
    $Logger.warn($(Trace-Session $RedfishSession "File $SecureFileUri is not in support schema: $SupportSchemaString"))
    throw $([string]::Format($(Get-i18n ERROR_FILE_URI_NOT_SUPPORT), $SecureFileUri, $SupportSchemaString))
  }

  if ($Schema -eq 'file') {
    $Logger.info($(Trace-Session $RedfishSession"File $SecureFileUri is a local file, upload to bmc now"))
    $Ext = [System.IO.Path]::GetExtension($ImageFilePath)
    if ($null -eq $Ext -or $Ext -eq '') {
      $UploadFileName = "$(Get-RandomIntGuid).hpm"
    } else {
      $FileName = $ImageFilePath.Split("/").Split("\")
      $UploadFileName = $FileName[-1]
    }

    # upload image file to bmc
    $Logger.Info($(Trace-Session $RedfishSession "$SecureFileUri is a local file, upload to iBMC now"))
    Invoke-RedfishFirmwareUpload $RedfishSession $UploadFileName $ImageFilePath | Out-Null
    $Logger.Info($(Trace-Session $RedfishSession "File uploaded as $UploadFileName success"))
    return "/tmp/web/$UploadFileName"
  }

  $Logger.info($(Trace-Session $RedfishSession "File $SecureFileUri is 'network' file, it's support directly."))
  return Resolve-NetworkUriSchema $ImageFilePath
}


function Invoke-RedfishRequest {
  [cmdletbinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $Session,

    [System.String]
    [parameter(Mandatory = $true, Position=1)]
    $Path,

    [System.String]
    [parameter(Mandatory = $false, Position=2)]
    [ValidateSet('Get', 'Delete', 'Put', 'Post', 'Patch')]
    $Method = 'Get',

    [System.Object]
    [parameter(Mandatory = $false, Position=3)]
    $Payload,

    [System.Object]
    [parameter(Mandatory = $false, Position=4)]
    $Headers,

    [Switch]
    [parameter(Mandatory = $false, Position=5)]
    $ContinueEvenFailed
  )

  $Request = New-RedfishRequest $Session $Path $Method $Headers

  try {
    if ($method -in @('Put', 'Post', 'Patch')) {
      if ($null -eq $Payload -or '' -eq $Payload) {
        $PayloadString = '{}'
      } elseif ($Payload -is [string]) {
        $PayloadString = $Payload
      } else {
        $PayloadString = $Payload | ConvertTo-Json -Depth 5
      }

      $Encoder = [System.Text.Encoding]::ASCII
      $PayloadAsBytes = $Encoder.GetBytes($PayloadString)

      $Request.ContentType = 'application/json'
      $Request.ContentLength = $PayloadAsBytes.length

      $RequestStream = $Request.GetRequestStream()
      $RequestStream.Write($PayloadAsBytes, 0, $PayloadAsBytes.length)
      $RequestStream.Flush()
      $RequestStream.close()
    }

    return $Request.GetResponse()
  }
  catch {
    # .Net HttpWebRequest will throw Exception if response is not success (status code is great than 400)
    Resolve-RedfishFailureResponse $Session $Request $_ $ContinueEvenFailed
  }
  finally {
    # if ($null -ne $StreamWriter -and $StreamWriter -is [System.IDisposable]) {
    #   $StreamWriter.Dispose()
    # }
  }
}

function New-RedfishRequest {
  [cmdletbinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $Session,

    [System.String]
    [parameter(Mandatory = $true, Position=1)]
    $Path,

    [System.String]
    [parameter(Mandatory = $false, Position=2)]
    [ValidateSet('Get', 'Delete', 'Put', 'Post', 'Patch')]
    $Method = 'Get',

    [System.Object]
    [parameter(Mandatory = $false, Position=3)]
    $Headers
  )

  if ($Path.StartsWith("https://", "CurrentCultureIgnoreCase")) {
    $OdataId = $Path
  }
  elseif ($Path.StartsWith("/redfish/v1", "CurrentCultureIgnoreCase")) {
    $OdataId = "$($session.BaseUri)$($Path)"
  }
  else {
    $OdataId = "$($session.BaseUri)/redfish/v1$($Path)"
  }
  $IfMatchMissing = ($null -eq $Headers -or 'If-Match' -notin $Headers.Keys)
  if ($IfMatchMissing -and $method -in @('Put', 'Patch')) {
    $Logger.Info($(Trace-Session $Session "No if-match present, will auto load etag now"))
    $Response = Invoke-RedfishRequest -Session $Session -Path $Path
    $OdataEtag = $Response.Headers.get('ETag')
    $Response.close()
  }

  $Logger.info($(Trace-Session $Session "Invoke [$Method] $Path"))

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [System.Net.HttpWebRequest] $Request = [System.Net.WebRequest]::Create($OdataId)
  $Request.Timeout = 120 * 1000
  $Request.ReadWriteTimeout = 90 * 1000

  $Request.ServerCertificateValidationCallback = {
    param($Source, $certificate, $Chain, $errors)
    if ($errors -eq 'None') {
      $Logger.warn("There is not SSL policy errors")
      return $true
    }

    if ($true -eq $Session.TrustCert) {
      $Logger.info("TrustCert present, Ignore HTTPS certification")
      return $true
    }

    # use the ca root certificate to form certificate chain
    if ($errors.HasFlag([Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors)) {
      $Logger.info("failed to form certificate chain from remote site, please make sure install the CA root certificate")
      return $false;
    }

    # if no certificate for the server site
    if ($errors.HasFlag([Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable)) {
      $Logger.info("failed to get certificate chain from remote site, please make sure server site has server certificate")
      return $false;
    }

    return $true
  }

  $Request.Method = $Method.ToUpper()

  $Request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  $Request.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip

  if ($null -ne $session.AuthToken) {
    $Request.Headers.Add('X-Auth-Token', $session.AuthToken)
  }

  if ($null -ne $Headers) {
    $Headers.Keys | ForEach-Object {
      $Request.Headers.Add($_, $Headers.Item($_))
    }
  }

  if ($null -ne $OdataEtag) {
    $Request.Headers.Add('If-Match', $OdataEtag)
  }
  return $Request
}


function Resolve-RedfishFailureResponse ($Session, $Request, $Ex, $ContinueEvenFailed) {
  try {
    $Logger.Warn(($(Trace-Session $Session $Ex)))
    $response = $Ex.Exception.InnerException.Response
    if ($null -ne $response) {
      $StatusCode = $response.StatusCode.value__
      if ($StatusCode -eq 403){
        throw $(Get-i18n "FAIL_NO_PRIVILEGE")
      }
      elseif ($StatusCode -eq 500) {
        throw $(Get-i18n "FAIL_INTERNAL_SERVICE")
      }
      elseif ($StatusCode -eq 501) {
        throw $(Get-i18n "FAIL_NOT_SUPPORT")
      }

      if ($ContinueEvenFailed -and $StatusCode -ne 401) {
        return $response
      }

      $Content = Get-WebResponseContent $response
      $Message = "[$($Request.Method)] $($response.ResponseUri) -> code: $StatusCode; content: $Content"
      $Logger.warn($(Trace-Session $Session $Message))

      $Failures = Get-RedfishResponseFailures $Content
      if ($null -ne $Failures -and $Failures.Count -gt 0) {
        throw $($Failures -join "`n")
      }

      throw $Ex.Exception
    } else {
      throw $Ex.Exception
    }
  } catch {
    throw "[$($Session.Address)] $($_.Exception.Message)"
  }
}


function Resolve-RedfishPartialSuccessResponse($RedfishSession, $Response) {
  $Uri = $Response.ResponseUri
  $StatusCode = $Response.StatusCode.value__
  $ResponseContent = Get-WebResponseContent $Response
  $Failures = Get-RedfishResponseFailures $ResponseContent
  if ($null -ne $Failures -and $Failures.Count -gt 0) {
    $Message = "[$($Response.Method)] $Uri -> code: $StatusCode; content: $ResponseContent"
    $Logger.warn($(Trace-Session $RedfishSession $Message))
    $FailuresToString = $($Failures -join "`n")
    throw "[$($RedfishSession.Address)] $($FailuresToString)"
  } else {
    return $ResponseContent | ConvertFrom-Json
  }
}


function ConvertFrom-WebResponse {
  param (
    [System.Net.HttpWebResponse]
    [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Response
  )

  return Get-WebResponseContent $Response | ConvertFrom-Json
}

function Get-WebResponseContent {
  param (
    [System.Net.HttpWebResponse]
    [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Response
  )
  try {
    $stream = $response.GetResponseStream()
    $streamReader = New-Object System.IO.StreamReader($stream)
    $content = $streamReader.ReadToEnd()
    return $content
  }
  finally {
    $streamReader.close()
    $stream.close()
    $response.close()
  }
}

function Get-RedfishResponseFailures {
  param (
    [String]
    $ResponseContent
  )
  $result = $ResponseContent | ConvertFrom-Json

  $Partial = $false
  $ExtendedInfo = $result.error.'@Message.ExtendedInfo'
  if ($ExtendedInfo.Count -eq 0) {
    $Partial = $true
    $ExtendedInfo = $result.'@Message.ExtendedInfo'
  }

  if ($ExtendedInfo.Count -eq 1) {
    $Severity = $ExtendedInfo[0].Severity
    if ($Severity -eq $BMC.Severity.OK) {
      return $null
    }
  }

  if ($ExtendedInfo.Count -gt 0) {
    $Prefix = "Failure:"
    $indent = " " * $Prefix.Length
    $Failures = New-Object System.Collections.ArrayList

    if ($Partial) {
      [Void] $Failures.Add($(Get-i18n FAIL_TO_MODIFY_ALL))
    }

    for ($idx = 0; $idx -lt $ExtendedInfo.Count; $idx++) {
      $Failure = $ExtendedInfo[$idx]
      $Resolution = "Resolution: $($Failure.Resolution)"
      if ($idx -eq 0 -and -not $Partial) {
        [Void] $Failures.Add("$Prefix [$($Failure.Severity)] $($Failure.Message) $Resolution")
      } else {
        [Void] $Failures.Add("$indent [$($Failure.Severity)] $($Failure.Message) $Resolution")
      }
    }

    return $Failures
  }

  return $null
}

function Get-StoragePathCollection {
<#
.SYNOPSIS
Get the path of RAID storage collection

.DESCRIPTION

.PARAMETER Session
Get the path of RAID storage collection

.OUTPUTS
String[]
RAID storage odata id array

#>
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $RedfishSession
  )

  $GetStoragesPath = "/Systems/$($RedfishSession.Id)/Storages"
  $Storages = Invoke-RedfishRequest $RedfishSession $GetStoragesPath | ConvertFrom-WebResponse

  $OdataIdList = New-Object System.Collections.ArrayList
  for ($idx = 0; $idx -lt $Storages.Members.Count; $idx++) {
    $StoragePath = $Storages.Members[$idx]."@odata.id"
    if ($StoragePath -like '*/RAIDStorage*') {
      [Void] $OdataIdList.Add($StoragePath)
    } else {
      continue
    }
  }

  return ,$OdataIdList.ToArray()
}


function Get-VolumeOdataId {
  <#
  .DESCRIPTION
  Fetch logical drive odata-id by Id
  #>
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $RedfishSession,

    [String]
    [parameter(Mandatory = $true, Position=1)]
    $VolumeId
  )

  $StoragePaths = Get-StoragePathCollection $RedfishSession
  for ($idx = 0; $idx -lt $StoragePaths.Count; $idx++) {
    $StoragePath = $StoragePaths[$idx]
    $GetVolumesPath = "$StoragePath/Volumes"
    $Volumes = Invoke-RedfishRequest $RedfishSession $GetVolumesPath | ConvertFrom-WebResponse
    for ($i = 0; $i -lt $Volumes.Members.Count; $i++) {
      $Volume = $Volumes.Members[$i]
      if ($Volume."@odata.id" -eq "$GetVolumesPath/$VolumeId") {
        return $Volume."@odata.id"
      }
    }
  }

  return $null
}

function Assert-VolumeExistence {
  <#
  .DESCRIPTION
  Assert StorageId and VolumeId Existence
  #>
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $RedfishSession,

    [String]
    [parameter(Mandatory = $true, Position=1)]
    $StorageId,

    [String]
    [parameter(Mandatory = $true, Position=2)]
    $VolumeId
  )

  Assert-StorageExistence $RedfishSession $StorageId

  $GetVolumesPath = "/Systems/$($RedfishSession.Id)/Storages/$StorageId/Volumes"
  $Volumes = Invoke-RedfishRequest $RedfishSession $GetVolumesPath | ConvertFrom-WebResponse
  for ($i = 0; $i -lt $Volumes.Members.Count; $i++) {
    $Volume = $Volumes.Members[$i]

    if ($Volume."@odata.id".EndsWith("$GetVolumesPath/$VolumeId")) {
      $VolumeIdExists = $true
      break
    }
  }

  if (-not $VolumeIdExists) {
    $ErrorDetail = [String]::Format($(Get-i18n ERROR_VOLUMEID_NOT_EXISTS), $VolumeId)
    throw "[$($RedfishSession.Address)] $ErrorDetail"
  }
}

function Assert-StorageExistence {
  <#
  .DESCRIPTION
  Assert StorageId Existence
  #>
  [CmdletBinding()]
  param (
    [RedfishSession]
    [parameter(Mandatory = $true, Position=0)]
    $RedfishSession,

    [String]
    [parameter(Mandatory = $true, Position=1)]
    $StorageId
  )

  $GetStoragesPath = "/Systems/$($RedfishSession.Id)/Storages/$StorageId"
  $Response = Invoke-RedfishRequest $RedfishSession $GetStoragesPath -ContinueEvenFailed
  $StatusCode = $Response.StatusCode.value__
  if ($StatusCode -eq 404) {
    $ErrorDetail = [String]::Format($(Get-i18n ERROR_STORAGE_ID_NOT_EXISTS), $StorageId)
    throw "[$($RedfishSession.Address)] $ErrorDetail"
  }
}
