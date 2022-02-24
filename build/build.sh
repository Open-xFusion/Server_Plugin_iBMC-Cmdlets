#!/bin/bash

current_path=`pwd`
cmdlets_path=$(dirname "$PWD")

cd "${cmdlets_path}/open_source/log4net"
unzip apache-log4net*.zip
cp net45/log4net.dll ${cmdlets_path}/code/common/

cd "${cmdlets_path}"
mkdir xFusion-iBMC-Cmdlets
cd ${cmdlets_path}/xFusion-iBMC-Cmdlets
cp -R ${cmdlets_path}/code/common .
cp -R ${cmdlets_path}/docs .
cp -R ${cmdlets_path}/code/scripts .
cp ${cmdlets_path}/code/xFusion-iBMC-Cmdlets.psd1 .
cp ${cmdlets_path}/code/xFusion-iBMC-Cmdlets.psm1 .
cp ${cmdlets_path}/README.md .
cd ..
zip -r "xFusion-iBMC-Cmdlets v${BmcCmdlets_Version}".zip xFusion-iBMC-Cmdlets
rm -rf ${cmdlets_path}/xFusion-iBMC-Cmdlets
exit 0
