# Copyright (C) 2020 xFusion Digital Technologies Co., Ltd. All rights reserved.	
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the MIT License		

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# MIT License for more detail

<# NOTE: A PowerShell Constants implementation. #>

$global:BMC = @{

  'V52V3Mapping' = @{
    'HardDiskDrive'='HDD';
    'DVDROMDrive'='Cd';
    'PXE'='Pxe';
    'Others'='Others';
  };

  'V32V5Mapping' = @{
    'HDD'='HardDiskDrive';
    'Cd'='DVDROMDrive';
    'Pxe'='PXE';
    'Others'='Others';
  };

  Severity = @{
    OK='OK';
  };

  LinkStatus = @{
    NoLink='NoLink';
    LinkUp='LinkUp';
    LinkDown='LinkDown';
  };

  TaskState = @{
    Completed='Completed';
    Exception='Exception';
  };

  State = @{
    Absent='Absent';
    Enabled='Enabled';
  }

  FRUOperationSystem = 0;

  OutBandFirmwares = @(
    "ActiveBMC",
    "BackupBMC",
    "Bios"
  );

  InBandFirmwares = @(
    "PCIeCards"
  );

  OutBandImageFileSupportSchema = @(
    "https",
    "scp",
    "sftp",
    "cifs",
    "tftp",
    "nfs",
    "file"
  );

  InBandImageFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  SPImageFileSupportSchema = @(
    "nfs",
    "cifs"
  );

  SignalFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  BIOSConfigFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  NTPKeyFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  CollectFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  LicenseFileSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  OdataProperties = @(
    "@odata.context",
    "@odata.id",
    "@odata.type",
    "Links",
    "Actions"
  );

  LDAPCertSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  );

  LDAPCertRemoteImportSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp"
  );

  HttpsCertSupportSchema = @(
    "https",
    "sftp",
    "nfs",
    "cifs",
    "scp",
    "file"
  )

}
