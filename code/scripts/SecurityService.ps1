# Copyright (C) 2021 xFusion Technologies Co., Ltd. All rights reserved.	
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: iBMC Security module Cmdlets #>

function Get-iBMCSecurityService {
<#
.SYNOPSIS
Query information about the security services supported by the server.

.DESCRIPTION
Query information about the security services supported by the server.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.OUTPUTS
PSObject[]
Returns Array of PSObject indicates all security services supported by the server if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Get-iBMCSecurityService -Session $Session
PS C:\> $Result | fl

Host                           : 192.168.1.1
Id                             : SecurityService
Name                           : Security Service
SessionTokenLength             : 16
SecurityControlVersion         : 1
MasterKeyUpdateInterval        : 0
HttpsTransferCertVerification  : False
SOLAutoOSLockEnabled           : False
SOLAutoOSLockKey               : 0
RemoteHttpsServerCertChainInfo : {}

This example shows how to query information about the security services supported by the server


Set-iBMCSecurityService
Import-iBMCRemoteHttpsServerCrl
Remove-iBMCRemoteHttpsServerRootCA
Import-iBMCRemoteHttpsServerRootCA
Connect-iBMC
Disconnect-iBMC

#>
    [CmdletBinding()]
    param (
        [RedfishSession[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Session
    )

    begin {
    }

    process {
        Assert-ArrayNotNull $Session 'Session'
        $Logger.info("Invoke query information about the security services supported by the server")

        # get security service
        $GetSecurityServiceBlock = {
            param($Session)
            $(Get-Logger).info($(Trace-Session $Session "Invoke query information about the security services supported by the server now"))
            
            # Obtains the information returned by the Redfish interface 
            $Path = "/Managers/$($Session.Id)/SecurityService"
            $Response = Invoke-RedfishRequest $Session $Path | ConvertFrom-WebResponse

            # Obtains specified information
            $Properties = @(
                "Id",
                "Name",
                "SessionTokenLength",
                "SecurityControlVersion",
                "MasterKeyUpdateInterval",
                "HttpsTransferCertVerification",
                "SOLAutoOSLockEnabled",
                "SOLAutoOSLockKey",
                "RemoteHttpsServerCertChainInfo",
                "RemoteHttpsServerRootCA"
            )
            $SecurityService = Copy-ObjectProperties $Response $Properties

            # Add IP address
            $SecurityServices = $(Update-SessionAddress $Session $SecurityService)
            
            return $SecurityServices
        }

        try {
            $tasks = New-Object System.Collections.ArrayList
            $pool = New-RunspacePool $Session.Count
            for ($idx = 0; $idx -lt $Session.Count; $idx++) {
                $RedfishSession = $Session[$idx]
                $Logger.info($(Trace-Session $RedfishSession "Submit query information about the security services supported by the server task"))
                [Void] $tasks.Add($(Start-ScriptBlockThread $pool $GetSecurityServiceBlock @($RedfishSession)))
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
    
function Set-iBMCSecurityService {
<#
.SYNOPSIS
Modify the security service collection supported by the server.

.DESCRIPTION
Modify the security service collection supported by the server.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER HttpsTransferCertVerification
Setting of the remote HTTPS server certificate verification.
Support values are powershell boolean value: $true(1), $false(0).

.OUTPUTS
PSObject[]
Returns the security service object array if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Set-iBMCSecurityService -Session $Session -HttpsTransferCertVerification $true
PS C:\> $Result

Host                          : 192.168.1.1
Id                            : SecurityService
Name                          : Security Service
HttpsTransferCertVerification : true

Modify the security service properties of a server.


Get-iBMCSecurityService
Import-iBMCRemoteHttpsServerCrl
Remove-iBMCRemoteHttpsServerRootCA
Import-iBMCRemoteHttpsServerRootCA
Connect-iBMC
Disconnect-iBMC

#>
    [CmdletBinding()]
    param (
        [RedfishSession[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position=0)]
        $Session,

        [Boolean[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position=1)]
        $HttpsTransferCertVerification
    )

    begin {
    }

    process {
        Assert-ArrayNotNull $Session 'Session'
        Assert-ArrayNotNull $HttpsTransferCertVerification 'HttpsTransferCertVerification'
        $Enableds = Get-MatchedSizeArray $Session $HttpsTransferCertVerification 'Session' 'HttpsTransferCertVerification'

        $SetSecurityServiceBlock = {
            param($Session, $SecurityServiceEnabled)
            $Payload = @{HttpsTransferCertVerification=$SecurityServiceEnabled;}
            # Get etag
            $Path = "/Managers/$($Session.Id)/SecurityService"
            $GetResponse = Invoke-RedfishRequest $Session $Path
            $Headers = @{'If-Match'=$GetResponse.Headers['Etag'];}
            
            # Modify the security service
            $Response = Invoke-RedfishRequest $Session $Path 'Patch' $Payload $Headers
            $SetSecurityService = Resolve-RedfishPartialSuccessResponse $Session $Response
            $Properties = @("Id", "Name", "HttpsTransferCertVerification")
            $PrettySecurityService = Copy-ObjectProperties $SetSecurityService $Properties

            # Add an IP address in the command output
            return $(Update-SessionAddress $Session $PrettySecurityService)
        }

        try {
            $tasks = New-Object System.Collections.ArrayList
            $pool = New-RunspacePool $Session.Count
            for ($idx=0; $idx -lt $Session.Count; $idx++) {
                $RedfishSession = $Session[$idx]
                $Parameters = @($RedfishSession, $Enableds[$idx])
                $Logger.info($(Trace-Session $RedfishSession "Submit modify the security service task"))
                [Void] $tasks.Add($(Start-ScriptBlockThread $pool $SetSecurityServiceBlock $Parameters))
            }
            return Get-AsyncTaskResults -AsyncTasks $tasks
        }
        finally {
            Close-Pool $pool
        }
    }

    end {
    }
}

function Import-iBMCRemoteHttpsServerRootCA {
<#
.SYNOPSIS
Import the root certificate of a remote HTTPS server.

.DESCRIPTION
Import the root certificate of a remote HTTPS server.
1. Certificate of the same usage cannot be imported repeatedly.
2. When importing certificate with a specified ID, the new certificate will replace the old certificate if there is a certificate at this location.
3. When importing certificate without a specified ID, certificate usage must be specified.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER CertPath
The root certificate file path of a remote HTTPS server, The file name extension must be .crt .cer or .pem

File path support:
1. import from local storage, example: c:\ca.crt or \\192.168.1.2\ca.crt
2. import from ibmc local temporary storage, example: /tmp/ca.crt
3. import from remote storage, example: protocol://username:password@hostname/directory/ca.crt
    support protocol list: sftp, https, nfs, cifs, scp

.PARAMETER CertID
ID of the root certificate used to authenticate the remote HTTPS server.
Support integer value range: [5, 8]

.PARAMETER Usage
Usage of the certificate
Available usage value set is:
- "FileTransfer" 

.OUTPUTS
PSObject[]
Returns the import root certificate of a remote HTTPS server task array if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Import-iBMCRemoteHttpsServerRootCA -Session $session -CertPath 'c:\https.crt' -CertID 5
PS C:\> $Result

Host              : 192.168.1.1
MessageId         : Base.1.0.Success
RelatedProperties : 
Message           : Successfully Completed Request.
MessageArgs       : 
Severity          : OK
Resolution        : None

This example shows how to import root certificate from local file

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Import-iBMCRemoteHttpsServerRootCA -Session $session -CertPath 'nfs://10.1.1.100/data/https.crt' -Usage FileTransfer
PS C:\> $Result

Host         : 192.168.1.1
Id           : 1
Name         : remote https server ca import
ActivityName : [192.168.1.1] remote https server ca import
TaskState    : Completed
StartTime    : 2019-11-28T16:44:46+08:00
EndTime      : 2019-11-28T16:44:47+08:00
TaskStatus   : OK
TaskPercent  : 100%

This example shows how to import root certificate from remote file

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $Tasks = Import-iBMCRemoteHttpsServerRootCA $session 'sftp://192.168.1.2/data/https.crt' -SecureEnabled

Host         : 192.168.1.1
Id           : 2
Name         : remote https server ca import
ActivityName : [192.168.1.1] remote https server ca import
TaskState    : Completed
StartTime    : 2018-11-14T17:54:54+08:00
EndTime      : 2018-11-14T17:56:06+08:00
TaskStatus   : OK
TaskPercent  : 100%

This example shows how to import the root certificate from SFTP file with secure parameter


Get-iBMCSecurityService
Set-iBMCSecurityService
Remove-iBMCRemoteHttpsServerRootCA
Import-iBMCRemoteHttpsServerCrl
Connect-iBMC
Disconnect-iBMC

#>
    [CmdletBinding()]
    param (
        [RedfishSession[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        $Session,

        [string[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        $CertPath,

        [int[]]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(5, 8)]
        $CertID,

        [HttpsCertUsage[]]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Usage,

        [switch]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $SecureEnabled
    )

    begin {
    }

    process {
        Assert-ArrayNotNull $Session 'Session'
        Assert-ArrayNotNull $CertPath 'CertPath'
        $CertPathList = Get-MatchedSizeArray $Session $CertPath 'Session' 'CertPath'
        $CertIDList = Get-OptionalMatchedSizeArray $Session $CertID
        $UsageList = Get-OptionalMatchedSizeArray $Session $Usage

        if ($SecureEnabled) {
            $SensitiveInfo = @(Get-SensitiveInfo)
            $SensitiveInfoList = Get-OptionalMatchedSizeArray $Session $SensitiveInfo
        }

        $Logger.info("Invoke import the root certificate of a remote HTTPS server")

        $ImportCertBlock = {
            param($RedfishSession, $Payload)
            
            $CertFilePath = $Payload.Content
            if ($CertFilePath.StartsWith("/tmp")) {
                $Payload.Content = $CertFilePath
            } else {
                $ContentURI = Invoke-FileUploadIfNeccessary $RedfishSession $CertFilePath $BMC.HttpsCertSupportSchema
                $Payload.Content = $ContentURI
            }

            $Clone = $Payload.clone()
            $Clone.Content = Protect-NetworkUriUserInfo $Payload.Content
            $Logger.info($(Trace-Session $RedfishSession "Sending payload: $($Clone | ConvertTo-Json)"))
            $Path = "/redfish/v1/Managers/$($RedfishSession.Id)/SecurityService/Actions/SecurityService.ImportRemoteHttpsServerRootCA"
            $Response = Invoke-RedfishRequest $RedfishSession $Path 'Post' $Payload
            return $Response | ConvertFrom-WebResponse
        }

        try {
            $pool = New-RunspacePool $Session.Count
            $Tasks = New-Object System.Collections.ArrayList
            for ($idx = 0; $idx -lt $Session.Count; $idx++) {
                $RedfishSession = $Session[$idx]
                $CertificateFilePath = $CertPathList[$idx]
                if ($SecureEnabled) {
                    $SensitiveInfo = $SensitiveInfoList[$idx]
                    $CertificateFilePath = Get-CompleteUri $SensitiveInfo $CertificateFilePath
                }

                $Payload = @{
                    Type="URI";
                    Content=$CertificateFilePath;
                    RootCertId=$CertIDList[$idx];
                    Usage=$UsageList[$idx];
                } | Remove-EmptyValues | Resolve-EnumValues

                if ($null -eq $Payload.RootCertId -and $null -eq $Payload.Usage) {
                    throw $(Get-i18n ERROR_HTTPS_CERT_ANY_INVALID)
                }

                $Logger.info($(Trace-Session $RedfishSession "Submit import the root certificate of a remote HTTPS server task"))
                $Parameters = @($RedfishSession, $Payload)
                [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ImportCertBlock $Parameters))          
            }
            
            $RedfishTasks = Get-AsyncTaskResults $tasks
            $Logger.Info("Import the root certificate of a remote HTTPS server task: " + $RedfishTasks)
            return Wait-RedfishTasks $pool $Session $RedfishTasks -ShowProgress
        }
        finally {
            Close-Pool $pool
        }
    }

    end {
    }
}

function Remove-iBMCRemoteHttpsServerRootCA {
<#
.SYNOPSIS
Delete the certificate of a remote HTTPS server.

.DESCRIPTION
Delete the certificate of a remote HTTPS server.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER CertID
ID of the root certificate used to authenticate the remote HTTPS server.
Support integer value range: [5, 8]

.OUTPUTS
PSObject[]
Returns the import root certificate of a remote HTTPS server task array if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> Remove-iBMCRemoteHttpsServerRootCA -Session $session -CertID 5

This example shows how to delete the certificate of a remote HTTPS server


Get-iBMCSecurityService
Set-iBMCSecurityService
Import-iBMCRemoteHttpsServerRootCA
Import-iBMCRemoteHttpsServerCrl
Connect-iBMC
Disconnect-iBMC

#>
    [CmdletBinding()]
    param (
        [RedfishSession[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        $Session,

        [int32[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateRange(5, 8)]
        $CertID
    )

    begin {
    }

    process {
        Assert-ArrayNotNull $Session 'Session'
        Assert-ArrayNotNull $CertID 'CertID'
        $CertIDList = Get-MatchedSizeArray $Session $CertID 'Session' 'CertID'

        $Logger.info("Invoke delete the root certificate of a remote HTTPS server")

        $DeleteCertBlock = {
            param($RedfishSession, $RootCertID)

            $Payload = @{'RootCertId'=$RootCertID}
            $Logger.info($(Trace-Session $RedfishSession "Sending payload: $($Payload | ConvertTo-Json)"))
            $Path = "/redfish/v1/Managers/$($RedfishSession.Id)/SecurityService/Actions/SecurityService.DeleteRemoteHttpsServerRootCA"
            Invoke-RedfishRequest $RedfishSession $Path 'POST' $Payload | Out-Null
            return $Null
        }

        try {
            $pool = New-RunspacePool $Session.Count
            $Tasks = New-Object System.Collections.ArrayList
            for ($idx = 0; $idx -lt $Session.Count; $idx++) {
                $RedfishSession = $Session[$idx]
                $RootCertID = $CertIDList[$idx]

                $Logger.info($(Trace-Session $RedfishSession "Submit delete the root certificate of a remote HTTPS server task"))
                $Parameters = @($RedfishSession, $RootCertID)
                [Void] $tasks.Add($(Start-ScriptBlockThread $pool $DeleteCertBlock $Parameters))          
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

function Import-iBMCRemoteHttpsServerCrl {
<#
.SYNOPSIS
Import the CRL of a remote HTTPS server.

.DESCRIPTION
Import the CRL of a remote HTTPS server.
1. Certificate of the same usage cannot be imported repeatedly.
2. When importing certificate with a specified ID, the new certificate will replace the old certificate if there is a certificate at this location.
3. When importing certificate without a specified ID, certificate usage must be specified.

.PARAMETER Session
iBMC redfish session object which is created by Connect-iBMC cmdlet.
A session object identifies an iBMC server to which this cmdlet will be executed.

.PARAMETER CertPath
The the CRL file path of a remote HTTPS server, The file name extension must be .crl

File path support:
1. import from local storage, example: c:\ca.crl or \\192.168.1.2\ca.crl
2. import from ibmc local temporary storage, example: /tmp/ca.crl
3. import from remote storage, example: protocol://username:password@hostname/directory/ca.crl
    support protocol list: sftp, https, nfs, cifs, scp

.PARAMETER CertID
ID of the root certificate object that issues the CRL.
Support integer value range: [5, 8]

.PARAMETER Usage
Usage of the certificate
Available usage value set is:
- "FileTransfer" 

.OUTPUTS
PSObject[]
Returns the import the CRL of a remote HTTPS server task array if cmdlet executes successfully.
In case of an error or warning, exception will be returned.

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Import-iBMCRemoteHttpsServerCrl -Session $session -CertPath 'c:\https.crl' -CertID 1
PS C:\> $Result

Host              : 192.168.1.1
MessageId         : Base.1.0.Success
RelatedProperties : 
Message           : Successfully Completed Request.
MessageArgs       : 
Severity          : OK
Resolution        : None

This example shows how to import the CRL of a remote HTTPS server from local file

.EXAMPLE

PS C:\> $Credential = Get-Credential
PS C:\> $Session = Connect-iBMC -Address 192.168.1.1 -Credential $Credential -TrustCert
PS C:\> $Result = Import-iBMCRemoteHttpsServerCrl -Session $session -CertPath 'nfs://10.1.1.100/data/https.crl' -Usage FileTransfer
PS C:\> $Result

Host         : 192.168.1.1
Id           : 1
Name         : remote https server crl import
ActivityName : [192.168.1.1] remote https server crl import
TaskState    : Completed
StartTime    : 2019-11-28T16:44:46+08:00
EndTime      : 2019-11-28T16:44:47+08:00
TaskStatus   : OK
TaskPercent  : 100%

This example shows how to import the CRL of a remote HTTPS server from remote file

.EXAMPLE

PS C:\> $credential = Get-Credential
PS C:\> $session = Connect-iBMC -Address 192.168.1.1 -Credential $credential -TrustCert
PS C:\> $Tasks = Import-iBMCRemoteHttpsServerCrl $session 'sftp://192.168.1.2/data/https.crl' -SecureEnabled

Host         : 192.168.1.1
Id           : 2
Name         : remote https server crl import
ActivityName : [192.168.1.1] remote https server crl import
TaskState    : Completed
StartTime    : 2018-11-14T17:54:54+08:00
EndTime      : 2018-11-14T17:56:06+08:00
TaskStatus   : OK
TaskPercent  : 100%

This example shows how to import the CRL of a remote HTTPS server from SFTP file with secure parameter


Get-iBMCSecurityService
Set-iBMCSecurityService
Remove-iBMCRemoteHttpsServerRootCA
Import-iBMCRemoteHttpsServerRootCA
Connect-iBMC
Disconnect-iBMC

#>
    [CmdletBinding()]
    param (
        [RedfishSession[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        $Session,

        [string[]]
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        $CertPath,

        [int32[]]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(5, 8)]
        $CertID,

        [HttpsCertUsage[]]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Usage,

        [switch]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $SecureEnabled
    )

    begin {
    }

    process {
        Assert-ArrayNotNull $Session 'Session'
        Assert-ArrayNotNull $CertPath 'CertPath'
        $CertPathList = Get-MatchedSizeArray $Session $CertPath 'Session' 'CertPath'
        $CertIDList = Get-OptionalMatchedSizeArray $Session $CertID
        $UsageList = Get-OptionalMatchedSizeArray $Session $Usage

        if ($SecureEnabled) {
            $SensitiveInfo = @(Get-SensitiveInfo)
            $SensitiveInfoList = Get-OptionalMatchedSizeArray $Session $SensitiveInfo
        }

        $Logger.info("Invoke import the CRL of a remote HTTPS server")

        $ImportCrlBlock = {
            param($RedfishSession, $Payload)
            
            $CertFilePath = $Payload.Content
            if ($CertFilePath.StartsWith("/tmp")) {
                $Payload.Content = $CertFilePath
            } else {
                $ContentURI = Invoke-FileUploadIfNeccessary $RedfishSession $CertFilePath $BMC.HttpsCertSupportSchema
                $Payload.Content = $ContentURI
            }

            $Clone = $Payload.clone()
            $Clone.Content = Protect-NetworkUriUserInfo $Payload.Content
            $Logger.info($(Trace-Session $RedfishSession "Sending payload: $($Clone | ConvertTo-Json)"))
            $Path = "/redfish/v1/Managers/$($RedfishSession.Id)/SecurityService/Actions/SecurityService.ImportRemoteHttpsServerCrl"
            $Response = Invoke-RedfishRequest $RedfishSession $Path 'Post' $Payload
            return $Response | ConvertFrom-WebResponse
        }

        try {
            $pool = New-RunspacePool $Session.Count
            $Tasks = New-Object System.Collections.ArrayList
            for ($idx = 0; $idx -lt $Session.Count; $idx++) {
                $RedfishSession = $Session[$idx]
                $CertificateFilePath = $CertPathList[$idx]
                if ($SecureEnabled) {
                    $SensitiveInfo = $SensitiveInfoList[$idx]
                    $CertificateFilePath = Get-CompleteUri $SensitiveInfo $CertificateFilePath
                }

                $Payload = @{
                    Type="URI";
                    Content=$CertificateFilePath;
                    RootCertId=$CertIDList[$idx];
                    Usage=$UsageList[$idx];
                } | Remove-EmptyValues | Resolve-EnumValues

                if ($null -eq $Payload.RootCertId -and $null -eq $Payload.Usage) {
                    throw $(Get-i18n ERROR_HTTPS_CERT_ANY_INVALID)
                }

                $Logger.info($(Trace-Session $RedfishSession "Submit import the CRL of a remote HTTPS server task"))
                $Parameters = @($RedfishSession, $Payload)
                [Void] $tasks.Add($(Start-ScriptBlockThread $pool $ImportCrlBlock $Parameters))          
            }
            
            $RedfishTasks = Get-AsyncTaskResults $tasks
            $Logger.Info("Import the CRL of a remote HTTPS server task: " + $RedfishTasks)
            return Wait-RedfishTasks $pool $Session $RedfishTasks -ShowProgress
        }
        finally {
            Close-Pool $pool
        }
    }

    end {
    }
}