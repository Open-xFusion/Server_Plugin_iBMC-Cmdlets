# Copyright (C) 2020-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: Common Utilities #>

# . $PSScriptRoot/I18n.ps1
# . $PSScriptRoot/Logger.ps1
# . $PSScriptRoot/Threads.ps1

function Write-Input {
  param($input)
  return $input
}

function Convert-IPV4Segment($IPSegment) {
<#
.DESCRIPTION
Convert a specified ip segment expression to all possible int ip segment array

.EXAMPLE
PS C:\>  Convert-IPV4Segment 3-4,5,10
PS C:\> 3 4 5 10

#>
  $result = @()
  $IPSegment.Split(',') | ForEach-Object {
    $split = $_.Split('-')
    $result += $($([int]$split[0])..$([int]$split[-1]))
  }
  return $result
}

function ConvertFrom-IPRangeString {
  param (
    [String][parameter(Mandatory = $true)] $IPRangeString
  )

  $port_regex = ':([1-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])'

  $hostnameSection = "([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])"
  [regex] $hostnameRegex = "^$hostnameSection(\.$hostnameSection)+($port_regex)?`$"

  # $ipv4Section = '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
  # $ipv4RangedSection = "$ipv4Section(-$ipv4Section)?"
  # $ipv4RangeSectionWithComma = "$ipv4RangedSection(,$ipv4RangedSection)*"
  # [regex] $ipv4_regex = "^($ipv4RangeSectionWithComma(\.$ipv4RangeSectionWithComma){3})($port_regex)?`$"

  # TODO add ipv6 range support
  # $ipv6Section='[0-9A-Fa-f]{1,4}'
  # $ipv6RangedSection="$ipv6Section(-$ipv6Section)?"
  # $ipv6RangedSectionWithComma="$ipv6RangedSection(,$ipv6RangedSection)*"

  # try to treat it as ipv4
  $IPV4 = ConvertFrom-IPV4RangeString $IPRangeString
  if ($IPV4 -ne $false) {
    return ,$IPV4
  }

  # try to treat it as hostname
  if ($IPRangeString -match $hostnameRegex) {
    return ,@($IPRangeString)
  }

  # try to treat it as ipv6
  $IPV6 = ConvertFrom-IPV6RangeString $IPRangeString
  if ($IPV6 -ne $false) {
    return ,$IPV6
  }

  throw $([string]::Format($(Get-i18n ERROR_ILLEGAL_ADDR), $IPRangeString))
}


function ConvertFrom-IPV4RangeString {
  param(
    [String][parameter(Mandatory = $false)] $IPRangeString
  )
  $port_regex = ':([1-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])'
  $ipv4Section = '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
  $ipv4RangedSection = "$ipv4Section(-$ipv4Section)?"
  $ipv4RangeSectionWithComma = "$ipv4RangedSection(,$ipv4RangedSection)*"
  [regex] $ipv4_regex = "^($ipv4RangeSectionWithComma(\.$ipv4RangeSectionWithComma){3})($port_regex)?`$"

  $matches = $ipv4_regex.Matches($IPRangeString)
  if ($matches.Count -eq 1) {
    $singleIpRange = $matches[0].Groups[1].Value
    $port = $IPRangeString -replace $singleIpRange, ''

    $segments = $singleIpRange.Split('.')
    $segment1 =  Convert-IPV4Segment $segments[0]
    $segment2 =  Convert-IPV4Segment $segments[1]
    $segment3 =  Convert-IPV4Segment $segments[2]
    $segment4 =  Convert-IPV4Segment $segments[3]

    $IPArray = New-Object System.Collections.ArrayList
    foreach ($s1 in $segment1) {
      foreach ($s2 in $segment2) {
        foreach ($s3 in $segment3) {
          foreach ($s4 in $segment4) {
            [Void] $IPArray.Add("$(@($s1, $s2, $s3, $s4) -join '.')$port")
          }
        }
      }
    }
    return ,$IPArray.ToArray()
  }

  return $false
}

function ConvertFrom-IPV6RangeString {
  param(
    [String][parameter(Mandatory = $false)] $IPRangeString
  )
  try {

    $Zone = ''
    $Suffix = ''
    $Prefix = ''

    # handle []
    if ($IPRangeString.StartsWith('[')) {
      $Prefix = '['
      $Suffix = $IPRangeString.Substring($IPRangeString.IndexOf(']'))
      $IPRangeString = $IPRangeString.Substring(1, $IPRangeString.IndexOf(']') - 1)
    }

    # handle %eth0
    if ($IPRangeString.IndexOf('%') -gt 0) {
      $Zone = $IPRangeString.Substring($IPRangeString.IndexOf('%'))
      $IPRangeString = $IPRangeString.Substring(0, $IPRangeString.IndexOf('%'))
    }

    # if ($IPRangeString.StartsWith("::")) {
    #   $IPRangeString = "0$IPRangeString"
    # }

    $segments = New-Object System.Collections.ArrayList
    $split = $IPRangeString -split ':'
    $split | ForEach-Object {
      [void] $segments.Add($(Convert-IPV6Segment $_))
    }

    $IPV6Array = $(Merge-IPSegments $segments.ToArray() ':')
    $Results = New-Object System.Collections.ArrayList
    for ($idx = 0; $idx -lt $IPV6Array.Count; $idx++) {
      $IsIPV6 = $false
      [IPAddress]$ipv6 = $null
      if ([IPAddress]::TryParse($IPV6Array[$idx], [ref]$ipv6)) {
        if ($ipv6.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
          $IsIPV6 = $true
        }
      }

      if (-not $IsIPV6) {
        throw $([string]::Format($(Get-i18n ERROR_ILLEGAL_ADDR), $IPRangeString))
      }

      [void] $Results.add("$Prefix$($IPV6Array[$idx])$Zone$Suffix")
    }
    return ,$Results.ToArray()
  } catch {
    throw $([string]::Format($(Get-i18n ERROR_ILLEGAL_ADDR), $IPRangeString))
  }
}

function Merge-IPSegments {
  [CmdletBinding()]
  param(
    [String[][]]$segments,
    [String]$join
  )

  if ($segments.Length -gt 2) {
    $results = New-Object System.Collections.ArrayList
    $First, $Rest = $segments
    $merged = $(Merge-IPSegments $Rest ':')
    foreach ($s1 in $First) {
      foreach ($s2 in $merged) {
        [Void] $results.Add("$s1$join$s2")
      }
    }
    return ,$results.ToArray()
  }

  if ($segments.Length -eq 2) {
    $results = New-Object System.Collections.ArrayList
    foreach ($s1 in $segments[0]) {
      foreach ($s2 in $segments[1]) {
        [Void] $results.Add("$s1$join$s2")
      }
    }
    return ,$results.ToArray()
  }
}

function Convert-IPV6Segment {
<#
.DESCRIPTION
Convert a specified ip segment expression to all possible int ip segment array

.EXAMPLE
PS C:\> $result = Convert-IPV6Segment "20F1-20F2,20F4,20F6-20F8"
PS C:\> $result | Should -be @('20F1', '20F2', '20F4', '20F6', '20F7', '20F8')

#>
  param([string]$IPSegment)

  $IntResults = @()
  if ($null -ne $IPSegment -and $IPSegment -ne '') {
    if ($IPSegment.indexOf('.') -ge 0) {
      return ConvertFrom-IPV4RangeString $IPSegment
    }

    $IPSegment.Split(',') | ForEach-Object {
      # if segment contains '.', treat it as ipv4
      $split = $_.Split('-')
      if ($split.count -gt 2) {
        throw $(Get-i18n ERROR_ILLEGAL_ADDR)
      }
      $from = Invoke-Expression "0x$($split[0])"
      $to = Invoke-Expression "0x$($split[-1])"
      $IntResults += $($from..$to)
    }
  } else {
    return @('')
  }

  $result = New-Object System.Collections.ArrayList
  for ($idx = 0; $idx -lt $IntResults.Count; $idx++) {
    [void] $result.add($IntResults[$idx].ToString('x'))
  }
  return ,$result.ToArray()
}


function Get-MatchedSizeArray {
  [CmdletBinding()]
  param($Source, $Target, $SourceName, $TargetName)

  if ($Target.Count -eq 1 -and $Source.Count -ne 1) {
    $Target = $Target * $Source.Count
  }
  if ($Source.Count -ne $Target.Count) {
    throw $([string]::Format($(Get-i18n ERROR_PARAMETER_COUNT_DIFFERERNT), $SourceName, $TargetName))
  }

  return , $Target
}

function Get-OptionalMatchedSizeArray {
  [CmdletBinding()]
  param($Source, $Target)

  if ($null -eq $Target -or $Target.Count -eq 0) {
    $empty = @($null) * $Source.Count
    return , $empty
  }
  else {
    $matched = Get-MatchedSizeArray $Source $Target 'source' 'target'
    return , $matched
  }
}


function Get-OptionalMatchedSizeMatrix {
  [CmdletBinding()]
  param($Source, $Target, $ValidSet, $SourceName, $TargetName)

  if ($null -eq $Target -or $Target.Count -eq 0) {
    $empty = @($null) * $Source.Count
    return , $empty
  }
  else {
    # every element in the matrix should be an array
    if ($Target -isnot [array]) {
      throw [String]::Format($(Get-i18n ERROR_MUST_BE_MATRIX), $TargetName)
    }

    for ($idx = 0; $idx -lt $Target.Count; $idx++) {
      $element = $Target[$idx]
      if ($element -isnot [array]) {
        throw [String]::Format($(Get-i18n ERROR_ELEMENT_NOT_ARRAY), $TargetName)
      }

      if ($null -ne $ValidSet) {
        $diff = Compare-Object $ValidSet $element | ? {$_.sideindicator -eq "=>"} | % {$_.inputobject}
        if ($null -ne $diff -and $diff.Count -gt 0) {
          $ValidSetString = $ValidSet -join ", "
          $DiffString = $diff -join ", "
          throw [String]::Format($(Get-i18n ERROR_ELEMENT_ILLEGAL), $TargetName, $DiffString, $ValidSetString)
        }
      }
    }

    $matched = Get-MatchedSizeArray $Source $Target $SourceName $TargetName
    return , $matched
  }
}

function Assert-NotNull($Parameter, $ParameterName) {
  if ($null -eq $Parameter) {
    throw $([string]::Format($(Get-i18n ERROR_PARAMETER_EMPTY), $ParameterName))
  }
}

function Assert-ArrayNotNull($Parameter, $ParameterName) {
  if ($null -eq $Parameter -or $Parameter.Count -eq 0 -or $Parameter -contains $null) {
    throw $([string]::Format($(Get-i18n ERROR_PARAMETER_ARRAY_EMPTY), $ParameterName))
  }
}

function Remove-EmptyValues {
  [CmdletBinding()]
  param (
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Target
  )

  $hash = @{}
  if ($null -ne $Target) {
    foreach ($key in $Target.Keys) {
      $value = $Target.Item($key)
      if ($null -ne $value) {
        if ($value -is [array] -and $value.count -eq 0) {
          continue
        }
        if ($value -is [hashtable] -and $value.count -eq 0) {
          continue
        }
        if ($value -is [string] -and $value -eq '') {
          continue
        }
        [Void]$hash.Add($key, $value)
      }
    }
  }
  return $hash
}

function Remove-NoneValues {
  [CmdletBinding()]
  param (
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Source
  )

  $hash = @{}
  if ($null -ne $Source) {
    foreach ($key in $Source.Keys) {
      $value = $Source.Item($key)
      if ($null -ne $value) {
        [Void]$hash.Add($key, $value)
      }
    }
  }
  return $hash
}

function Get-PlainPassword {
  [CmdletBinding()]
  param ($SecurePassword)

  if ($null -ne $SecurePassword -and $SecurePassword -is [SecureString]) {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
  }
  return $SecurePassword
}

function Get-RandomIntGuid {
  return $(Get-Random -Maximum 1000000)
}

function Trace-Session ($Session, $message) {
  return "[$($Session.Address)] $message"
}

function Copy-ObjectProperties ($Source, $Properties) {
  $Clone = New-Object PSObject
   foreach ($key in $Properties) {
    foreach ($member in $Source.psobject.properties.name) {
      if ($key.indexOf("^") -ne -1 -and $member -match $key) {
        $Clone | Add-Member -MemberType NoteProperty "$member" $Source."$member" -Force
      } elseif ($key.indexOf("^") -eq -1 -and  $member -eq $key) {
        $Clone | Add-Member -MemberType NoteProperty "$member" $Source."$member" -Force
      }
    }
  }
  return $Clone
}

function Copy-ObjectExcludes ($Source, $excludes) {
  $Clone = New-Object PSObject
  $Properties = $Source.psobject.properties.Name
  $Properties | ForEach-Object {
    if ($_ -notin $excludes) {
      $Clone | Add-Member -MemberType NoteProperty "$_" $Source."$_"
    }
  }
  return $Clone
}

function Clear-OdataProperties {
<#
  Clear Odata Properties of redfish response
#>
  [CmdletBinding()]
  param (
    [psobject]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Source
  )
  return Copy-ObjectExcludes $Source $BMC.OdataProperties
}

function Merge-OemProperties {
<#
  Merge Redfish Odata Oem properties to main body
#>
  [CmdletBinding()]
  param (
    [psobject]
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Source,
	
	[String]
	[parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $OEM
  )

  if ($Source.Oem.$OEM) {
    return Merge-NestProperties $Source @('Oem', $OEM)
  }

  return $Source
}

function Merge-NestProperties {
<#
  Merge Redfish Odata Oem properties to main body
#>
  [CmdletBinding()]
  param (
    [psobject]
    [parameter(Mandatory = $true)]
    $Source,

    [String[]]
    [parameter(Mandatory = $true)]
    $NestKeys
  )
  $Clone = $Source | Select-Object -Property * -ExcludeProperty $NestKeys[0]

  $Nest = $Source
  for ($idx = 0; $idx -lt $NestKeys.Length; $idx++) {
    $key = $NestKeys[$idx]
    $Nest = $Nest."$key"
  }

  # $Logger.Info("Nest is $Nest")
  $Properties = $Nest.psobject.properties.Name
  $Properties | ForEach-Object {
    $Clone | Add-Member -MemberType NoteProperty $_ $Nest."$_"
  }
  return $Clone
}

function Resolve-EnumValues {
  [CmdletBinding()]
  param (
    [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Source
  )
  $hash = @{}
  if ($null -ne $Source) {
    foreach ($key in $Source.Keys) {
      $value = $Source.Item($key)
      if ($value -is [Enum]) {
        [Void] $hash.Add($key, $value.toString())
      }
      elseif ($value -is [Array]) {
        $Converted = New-Object System.Collections.ArrayList
        $value | ForEach-Object {
          if ($_ -is [Enum]) {
            [Void] $Converted.Add($_.toString())
          } else {
            [Void] $Converted.Add($_)
          }
        }
        [Void] $hash.Add($key, $Converted)
      }
      else {
        [Void]$hash.Add($key, $value)
      }
    }
  }
  return $hash
}


function Get-EnumNames {
  param(
    [string]$enum
  )

  $Names = New-Object System.Collections.ArrayList
  [enum]::getvalues([type]$enum) | ForEach-Object {
    [Void] $Names.add($_.toString())
  }
  return $Names.ToArray()
}

function Protect-NetworkUriUserInfo {
  [CmdletBinding()]
  param (
    [string] $NetworkPath
  )
  try {
    $encodeUrl = [System.Web.HTTPUtility]::UrlEncode($NetworkPath)
    $
    $NetworkUri = New-Object System.Uri($encodeUrl)
    if($NetworkUri.UserInfo.Length -gt 0) {
      return $NetworkUri.AbsoluteUri -replace $NetworkUri.UserInfo, "***:***"
    }
    $Logger.info("network path doesn't contain user information, returning original data")
    return CoverUp-NetworkPathUserInfo $NetworkPath
  } catch {
    $Logger.info("network path cannot convert to uri normally, returning original data")
    return CoverUp-NetworkPathUserInfo $NetworkPath
  }
}

function CoverUp-NetworkPathUserInfo {
  [CmdletBinding()]
    param (
      [string] $NetworkPath
    )
    if ([string]::IsNullOrEmpty($NetworkPath)) {
      return $NetworkPath
    }

    if ($NetworkPath -match "//(.+):(.+)@") {
      $Logger.info("network path contains user info pattern, going to cover up")
      return $NetworkPath -replace "//(.+):(.+)@", "//****:****@"
    }
    $Logger.info("network path does not contain user info pattern, returning original path")
    return $NetworkPath
}


function Resolve-NetworkUriSchema {
  [CmdletBinding()]
  param (
    [string] $NetworkPath
  )
  try {
    $NetworkUri = New-Object System.Uri($NetworkPath)
    $Schema = $NetworkUri.Scheme
    if($NetworkPath.StartsWith($Schema, "CurrentCultureIgnoreCase")) {
      return "$($Schema.ToLower())$($NetworkPath.Substring($Schema.Length))"
    }
    $Logger.info("network path does not start with $Schema, return original data")
    return $NetworkPath
  } catch {
    $Logger.info("network path can't turn into system uri, return original data")
    return $NetworkPath
  }
}

function Get-NetworkUriSchema {
  [CmdletBinding()]
  param (
    [string] $NetworkPath
  )
  $Schema = ""
  try {
    $NetworkUri = New-Object System.Uri($NetworkPath)
    $Schema = $NetworkUri.Scheme
    return $Schema
  } catch {
    $Logger.info("network path can't turn into system uri, return substring result")
    $Schema = $NetworkPath.Substring(0, $NetworkPath.indexOf("://"))
    return $Schema
  }
}


function Update-SessionAddress {
  [CmdletBinding()]
  param (
    [RedfishSession] [parameter(Mandatory = $true)] $Session,
    [PSObject] [parameter(Mandatory = $true)] $Target
  )

  $Clone = New-Object PSObject -Property @{
    Host    = $Session.Address;
  }

  if ($null -ne $Target) {
    $Properties = $Target.psobject.properties.Name
    $Properties | ForEach-Object {
      $Clone | Add-Member -MemberType NoteProperty "$_" $Target."$_"
    }
  }

  # $Logger.info("return: $($Clone.psobject.properties.Name)")
  # $Logger.info("return: $($Clone.Host)")
  return $Clone
}


function Close-Pool ($pool) {
  if ($null -ne $pool) {
    $pool.close()
  }
}


function Assert-NetworkUriInSchema ($RedfishSession, $FilePath, $SupportSchema) {
  # iBMC local storage protocol handle
  $IsBMCFileProtocol = ($FilePath.StartsWith("file:///tmp", "CurrentCultureIgnoreCase") `
                          -or $FilePath.StartsWith("/tmp", "CurrentCultureIgnoreCase"))
  if ($IsBMCFileProtocol -and 'file' -in $SupportSchema) {
    return $FilePath
  }


  $SupportSchemaString = $SupportSchema -join ", "
  $Schema = ""
  try {
    $ImageFileUri = New-Object System.Uri($FilePath)
    $Schema = $ImageFileUri.Scheme
  } catch {
    $Logger.info("Image file uri can not convert to system uri")
    $Schema = $FilePath.Substring(0, $FilePath.IndexOf("://"))
  }
  $SecureFileUri = Protect-NetworkUriUserInfo $FilePath
  if ($Schema -notin $SupportSchema) {
    $Logger.warn($(Trace-Session $RedfishSession "File $SecureFileUri is not in support schema: $SupportSchemaString"))
    throw $([string]::Format($(Get-i18n ERROR_FILE_URI_NOT_SUPPORT), $ImageFileUri, $SupportSchemaString))
  }

  return Resolve-NetworkUriSchema $FilePath
}


function ConvertTo-PlainString {
  [CmdletBinding()]
  param (
    [System.Object] [parameter(Mandatory = $true)] $SensitiveString,
    [System.String] [parameter(Mandatory = $true)] $ParameterName
  )

  # if ($SensitiveString -isnot [SecureString] -and $SensitiveString -isnot [String]) {
  #   throw $([string]::Format($(Get-i18n ERROR_INVAIL_SENSITIVE_STRING), $ParameterName))
  # }

  $PlainPasswd = $SensitiveString.ToString()
  if ($SensitiveString -is [SecureString]) {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SensitiveString)
    $PlainPasswd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    return $PlainPasswd
  }

  return $PlainPasswd
}

function Assert-IsSensitiveString {
  [CmdletBinding()]
  param (
    [System.Object[]] [parameter(Mandatory = $true)] $SensitiveStringList,
    [System.String] [parameter(Mandatory = $true)] $ParameterName
  )

  for ($idx=0; $idx -lt $SensitiveStringList.Count; $idx++) {
    $SensitiveString = $SensitiveStringList[$idx]
    if ($SensitiveString -isnot [SecureString] -and $SensitiveString -isnot [String]) {
      throw $([string]::Format($(Get-i18n ERROR_INVAIL_SENSITIVE_STRING), $ParameterName))
    }
  }

}

function Get-EthernetInterfaces-ID ($Session){
  $EthernetInterfaces_ID = ""
  try {
    $Path = "/Managers/$($Session.Id)/EthernetInterfaces"
    $Response = Invoke-RedfishRequest $Session $Path | ConvertFrom-WebResponse
    $EthernetInterfaces_URL = $Response.Members[0]."@odata.id"
    $EthernetInterfaces_ID = $EthernetInterfaces_URL.Split("/")[-1]   
  } catch {
    throw "[$($Session.Address)] $($_.Exception.Message)"
  }
  return $EthernetInterfaces_ID
}

function Assert-IPv4 ($IPv4Address) {
  if ($null -ne $IPv4Address){
    $parttern = "^(((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))$"
    $match = $IPv4Address -match $parttern
    return $match 
  }
  return $true
}

function Assert-IPv6 ($IPv6Address) {
  if ($null -ne $IPv6Address){
    $parttern = "^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    $match = $IPv6Address -match $parttern
    return $match 
  }
  return $true
}

function Get-SensitiveInfo {
  $Logger.info("GUI to get sensitive info")
  $credential = Get-Credential
  if ((-not ($credential.username -match "^[^:@/]+$")) -or (-not ($credential.GetNetworkCredential().password -match "^[^:@/]+$"))) {
    throw $(Get-i18n ERROR_INVALID_CHARACTER)
  }
  return "$($credential.username):$($credential.GetNetworkCredential().password)"
}

function Get-CompleteUri() {
  [CmdletBinding()]
  param (
    [System.String] [parameter(Mandatory = $true)] $SensitiveInfo,
    [System.String] [parameter(Mandatory = $true)] $Uri
  )
  $InsertIndex = 2
  $Logger.info("get Complete Uri")
  $index = $Uri.Indexof('//')
  if (-1 -eq $index) {
    $Logger.Error('Invalid file uri')
    throw $(Get-i18n ERROR_INVALID_PARAMETERS)
  }
  $Uri = $Uri.Insert($index + $InsertIndex, "$($SensitiveInfo)@")
  return $Uri
}

function Get-AccountInfo {
  $Logger.info("GUI to get account info")
  $credential = Get-Credential -Message $(Get-i18n MSG_ENTER_ACCOUNT)
  # for the regular expression, please refer to powreshell escape rules
  # rules are based on redfish api documents
  if ((-not ($credential.username -match '^(?!#)[^<>&''"/\\%\s]{1,16}$')) -or (-not ($credential.GetNetworkCredential().password -match "^.{1,20}$"))) {
    throw $(Get-i18n ERROR_INVALID_CHARACTER)
  }
  $SecondCredential = Get-Credential -Message $(Get-i18n MSG_REENTER_ACCOUNT) -UserName $credential.username
  if ((-not ($SecondCredential.username -match '^(?!#)[^<>&''"/\\%\s]{1,16}$')) -or (-not ($SecondCredential.GetNetworkCredential().password -match "^.{1,20}$"))) {
    throw $(Get-i18n ERROR_INVALID_CHARACTER)
  }
  if (($credential.username -ne $SecondCredential.username) -or ($credential.GetNetworkCredential().password -ne $SecondCredential.GetNetworkCredential().password)) {
    throw $(Get-i18n ERROR_PASSWORD_DIFFERENT)
  }
  return @($($credential.username), $($credential.GetNetworkCredential().password))
}