# Copyright (C) 2020-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.	
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: iBMC Systems module Cmdlets #>

function Get-iBMCSystemInfo {
<#
.SYNOPSIS
Get system resource details of the server.

.DESCRIPTION
Get system resource details of the server.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
String
Returns iBMC Asset Tag if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $System = Get-iBMCSystemInfo $session
PS C:\> $System

Host             : 192.168.1.1
Id               : 1
Name             : Computer System
AssetTag         : my test
Manufacturer     : xFusion
Model            : 2288H V5
SerialNumber     : 2102311TYBN0J3000293
UUID             : 877AA970-58F9-8432-E811-80345C184638
HostName         :
PartNumber       : 02311TYB
HostingRole      : {ApplicationServer}
Status           : @{State=Disabled; Health=OK}
PowerState       : Off
Boot             : @{BootSourceOverrideTarget=Pxe; BootSourceOverrideEnabled=Continuous; BootSourceOverrideMode=Legacy; BootSourceOverride
                    Target@Redfish.AllowableValues=System.Object[]}
TrustedModules   :
BiosVersion      : 0.81
ProcessorSummary : @{Count=2; Model=Central Processor; Status=}
MemorySummary    : @{TotalSystemMemoryGiB=128; Status=}
PCIeDevices      : {}
PCIeFunctions    : {}
Oem              : @{xFusion=}

PS C:\> $System.Boot | fl

BootSourceOverrideTarget                         : Pxe
BootSourceOverrideEnabled                        : Continuous
BootSourceOverrideMode                           : Legacy
BootSourceOverrideTarget@Redfish.AllowableValues : {None, Pxe, Floppy, Cd...}


.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

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

    $Logger.info("Invoke Get iBMC System function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC System now"))
      $Path = "/Systems/$($RedfishSession.Id)"
      $Response = Invoke-RedfishRequest $RedfishSession $Path | ConvertFrom-WebResponse
      $Properties = @(
        "Id", "Name", "AssetTag", "Manufacturer", "Model", "SerialNumber", "UUID",
        "HostName", "PartNumber", "HostingRole", "Status", "PowerState", "Boot", "TrustedModules",
        "BiosVersion", "ProcessorSummary", "MemorySummary", "PCIeDevices", "PCIeFunctions",
        "Oem"
      )

      $System = Copy-ObjectProperties $Response $Properties

      $Excludes = @(
        "InfiniBandInterfaces", "NetworkBondings", "ProcessorView",
        "MemoryView", "ProcessorsHistoryUsageRate", "MemoryHistoryUsageRate",
        "NetworkHistoryUsageRate"
      )

      # server oem info
      $OEMInfo = $RedfishSession.Oem
      $Oem = Copy-ObjectExcludes $Response.Oem.$OEMInfo $Excludes
      $System.Oem.$OEMInfo = $Oem
      return Update-SessionAddress $RedfishSession $System
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC System task"))
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


function Get-iBMCSystemNetworkSettings {
<#
.SYNOPSIS
Get system resource details of the server.

.DESCRIPTION
Get system resource details of the server. Server OS system and iBMA should be installed to support this cmdlet.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[][]
Returns iBMC System LinkUp Ethernet Interfaces if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1-5 -Credential $credential -TrustCert
PS C:\> $Interfaces = Get-iBMCSystemNetworkSettings $session
PS C:\> $Interfaces

Host                : 192.168.1.1
Id                  : mainboardLOMPort1
Name                : System Ethernet Interface
PermanentMACAddress : xx:xx:xx:xx:xx:xx
MACAddress          : xx:xx:xx:xx:xx:xx
LinkStatus          : LinkUp
IPv4Addresses       : {@{Address=192.168.1.10; SubnetMask=255.255.0.0; Gateway=10.1.0.1; AddressOrigin=}}
IPv6Addresses       : {@{Address=fe80::20; PrefixLength=10; AddressOrigin=SLAAC; AddressState=},
                      @{Address=fe80::21;PrefixLength=10; AddressOrigin=SLAAC; AddressState=},
                      @{Address=fe80::22; PrefixLength=10; AddressOrigin=Static; AddressState=}}
IPv6DefaultGateway  : fe80::1
InterfaceType       : Physical
BandwidthUsage      : 0
BDF                 : 0000:1a:00.0

Host                : 192.168.1.3
Id                  : mainboardLOMPort2
Name                : System Ethernet Interface
PermanentMACAddress : xx:xx:xx:xx:xx:xx
MACAddress          : xx:xx:xx:xx:xx:xx
LinkStatus          : NoLink
IPv4Addresses       : {}
IPv6Addresses       : {}
IPv6DefaultGateway  :
InterfaceType       : Physical
BandwidthUsage      :
BDF                 : 0000:1a:00.1

Host                : 192.168.1.4
Id                  : mainboardLOMPort3
Name                : System Ethernet Interface
PermanentMACAddress : xx:xx:xx:xx:xx:xx
MACAddress          : xx:xx:xx:xx:xx:xx
LinkStatus          :
IPv4Addresses       : {}
IPv6Addresses       : {}
IPv6DefaultGateway  :
InterfaceType       : Physical
BandwidthUsage      :
BDF                 : 0000:1a:00.2

Host                : 192.168.1.5
Id                  : mainboardLOMPort4
Name                : System Ethernet Interface
PermanentMACAddress : xx:xx:xx:xx:xx:xx
MACAddress          : xx:xx:xx:xx:xx:xx
LinkStatus          : NoLink
IPv4Addresses       : {}
IPv6Addresses       : {}
IPv6DefaultGateway  :
InterfaceType       : Physical
BandwidthUsage      :
BDF                 : 0000:1a:00.3

.LINK
https://github.com/Open-xFusion/Server_Plugin_iBMC-Cmdlets

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

    $Logger.info("Invoke Get iBMC System Networking Settings function")

    $ScriptBlock = {
      param($RedfishSession)
      $(Get-Logger).info($(Trace-Session $RedfishSession "Invoke Get iBMC System Networking Settings now"))
      $GetInterfacesPath = "/Systems/$($RedfishSession.Id)/EthernetInterfaces"
      $EthernetInterfaces = Invoke-RedfishRequest $RedfishSession $GetInterfacesPath | ConvertFrom-WebResponse
      $Results = New-Object System.Collections.ArrayList
      for ($idx=0; $idx -lt $EthernetInterfaces.Members.Count; $idx++) {
        $Member = $EthernetInterfaces.Members[$idx]
        $EthernetInterface = Invoke-RedfishRequest $RedfishSession $Member.'@odata.id' | ConvertFrom-WebResponse

        # server oem info
        $OEM = $RedfishSession.Oem
        $Properties = @(
          "Id", "Name", "PermanentMACAddress", "MACAddress", "LinkStatus",
          "IPv4Addresses", "IPv6Addresses", "IPv6DefaultGateway"
        )
        $Clone = Copy-ObjectProperties $EthernetInterface $Properties
        $Clone | Add-Member -MemberType NoteProperty "InterfaceType" $EthernetInterface.Oem.$OEM.InterfaceType
        $Clone | Add-Member -MemberType NoteProperty "BandwidthUsage" $EthernetInterface.Oem.$OEM.BandwidthUsage
        $Clone | Add-Member -MemberType NoteProperty "BDF" $EthernetInterface.Oem.$OEM.BDF
        $Clone = Update-SessionAddress $RedfishSession $Clone
        [Void] $Results.add($Clone)
      }

      if ($Results.Count -eq 0) {
        throw $(Get-i18n FAIL_NO_LINKUP_INTERFACE)
      }

      return ,$Results.ToArray()
    }

    try {
      $tasks = New-Object System.Collections.ArrayList
      $pool = New-RunspacePool $Session.Count
      for ($idx = 0; $idx -lt $Session.Count; $idx++) {
        $RedfishSession = $Session[$idx]
        $Logger.info($(Trace-Session $RedfishSession "Submit Get iBMC System Networking Settings task"))
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
