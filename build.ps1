# KPMG deployment automation script
# Author Ajay Jha (badcoder)

Function UrlReWriteRule {
    param(
        [parameter(Mandatory=$true)]
        [String] $buildPath,
        [parameter(Mandatory=$true)]
        [String] $targetPath,
        [parameter(Mandatory=$true)]
        [String] $siteName,
        [parameter(Mandatory=$true)]
        [String] $hostName
    )
    Add-WebConfigurationProperty -pspath "iis:\sites\$siteName"  -filter "system.webServer/rewrite/rules" -name "." -value @{name='Redirect www.website.com' ;patternSyntax='Wildcard';stopProcessing='True'}
}

Function CreateUiBuild {
    param(
        [parameter(Mandatory=$true)]
        [String] $buildPath,
        [parameter(Mandatory=$true)]
        [String] $targetPath,
        [parameter(Mandatory=$true)]
        [String] $deployPath,
        [parameter(Mandatory=$true)]
        [String] $name,
        [parameter(Mandatory=$true)]
        [String] $backPath,
        [parameter(Mandatory=$true)]
        [String] $appPoolName,
        [parameter(Mandatory=$true)]
        [String] $appPoolDotNetVersion,
        [parameter(Mandatory=$true)]
        [String] $appName,
        [parameter(Mandatory=$true)]
        [String] $directoryPhysicalPath,
        [parameter(Mandatory=$true)]
        [String] $protocol,
        [parameter(Mandatory=$true)]
        [String] $port,
        [parameter(Mandatory=$true)]
        [String] $userId,
        [parameter(Mandatory=$true)]
        [String] $password,
        [parameter(Mandatory=$true)]
        [String] $windowAuthenticationEnabled,
        [parameter(Mandatory=$true)]
        [String] $tempSiteName,
        [parameter(Mandatory=$true)]
        [String] $tempSitePhysicalPath
    )
    Write-Host "Getting information for UI b"
    Write-Host "trget paath is $targetPath"
    Write-Host "build path is $buildPath"
    Write-Host "deploy path is $deployPath"
    Write-Host "name is $name"
    cd $buildPath;
    ng build --prod
    Start-Sleep -s 10
    if(!(Test-Path -Path $targetPath )){
        New-Item -Path "$targetPath" -ItemType directory -ErrorAction SilentlyContinue
    }else{
        Remove-Item $targetPath -Force  -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -s 5
        New-Item -Path "$targetPath" -ItemType directory -ErrorAction SilentlyContinue
    }
                
    Write-Host "target folder created successfully";
    Write-Host "copying build file";
    [string]$sourceDirectory  = "$buildPath\dist\*"
    [string]$destinationDirectory = "$targetPath";
    $deplyPath_temp="$deployPath\$name";
    [string]$destinationDirectoryDeploy = "$deplyPath_temp"
    Start-Sleep -s 5

    Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectory -ErrorAction SilentlyContinue

    cd $backPath
    
    Write-Host "Ui project $name bundled successfully";
    

    <#if(!(Test-Path -Path $deplyPath_temp )){
        New-Item -Path "$deplyPath_temp" -ItemType directory -ErrorAction SilentlyContinue
    }else{
        Remove-Item $deplyPath_temp -Force  -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -s 5
        New-Item -Path "$deplyPath_temp" -ItemType directory -ErrorAction SilentlyContinue
    }
    Start-Sleep -s 5
    Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectoryDeploy -ErrorAction SilentlyContinue
    Write-Host "Ui project $name deployed successfully";#>





    Import-Module WebAdministration
    $globalComputerName=(get-childitem -path env:computername).Value;
    $iisAppPoolName = $appPoolName;
    $iisAppPoolDotNetVersion = $appPoolDotNetVersion
    $iisAppName = $appName
    $directoryPath = $directoryPhysicalPath

    #navigate to the app pools root
    cd IIS:\AppPools\

    #check if the app pool exists
    if (!(Test-Path $iisAppPoolName -pathType container))
    {
        #create the app pool
        $appPool = New-Item $iisAppPoolName
        $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion 
        $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
        $appPool | Set-ItemProperty -name processModel.userName -Value $userId
        $appPool | Set-ItemProperty -name processModel.password -Value $password
        #$appPool | Set-ItemProperty -Name processModel -value @{userName="$userId";password="$password";identitytype=3}
    }else{
        $tempSite=Get-ChildItem IIS:\apppools | Where-Object {$_.Name -eq $iisAppPoolName}
        if($tempSite.Applications -ne $null){
            Write-Host "Application found inside $iisAppPoolName Apppool preparing clean -"
            RemoveAppIIS $tempSite.Applications
            Start-Sleep -s 5
            Write-Host "cleaning Apppool $iisAppPoolName "
            RemoveAppPoolIIS $iisAppPoolName;
            Start-Sleep -s 5
            Write-Host "$iisAppPoolName cleaned from system"
            Write-Host "creating apppool $iisAppPoolName again";
            $appPool = New-Item $iisAppPoolName
            $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
            $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
            $appPool | Set-ItemProperty -name processModel.userName -Value $userId
            $appPool | Set-ItemProperty -name processModel.password -Value $password
            #$appPool | Set-ItemProperty -Name processModel -Value @{userName="$userId";password="$password";identitytype=3}
        }
    }


    $tempSt=Get-Website -Name "$tempSiteName"
    if($tempSt -eq $null){
        Write-Host "Website $tempSiteName is not available creating the same"
        New-WebSite -Name "$tempSiteName" -Port $port -HostHeader "localhost" -PhysicalPath "$tempSitePhysicalPath" -Force
        New-WebBinding -Name "$tempSiteName" -IPAddress "*" -Port $port -Protocol $protocol -Force
    }

    Start-Sleep -Seconds 2

    #navigate to the sites root
    cd IIS:\Sites\$tempSiteName

    #check if the site exists
    if (Test-Path $iisAppName -pathType container)
    {
        #return
        Remove-WebApplication -Name "$iisAppName" -Site "$tempSiteName"
    }
    $getWebSite=Get-Website -Name "$tempSiteName"
    if($getWebSite -eq $null){
        $iisApp = New-Item $tempSiteName -bindings @{protocol=$protocol;bindingInformation="*`:$port`:"+$globalComputerName} -physicalPath $directoryPath -Force
        $iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName 
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }else{
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }

    cd $backPath


}

Function DeployUiBuild {
    param(
        [parameter(Mandatory=$true)]
        [String] $targetPath,
        [parameter(Mandatory=$true)]
        [String] $deployPath,
        [parameter(Mandatory=$true)]
        [String] $name,
        [parameter(Mandatory=$true)]
        [String] $appPoolName,
        [parameter(Mandatory=$true)]
        [String] $appPoolDotNetVersion,
        [parameter(Mandatory=$true)]
        [String] $appName,
        [parameter(Mandatory=$true)]
        [String] $directoryPhysicalPath,
        [parameter(Mandatory=$true)]
        [String] $protocol,
        [parameter(Mandatory=$true)]
        [String] $port,
        [parameter(Mandatory=$true)]
        [String] $userId,
        [parameter(Mandatory=$true)]
        [String] $password,
        [parameter(Mandatory=$true)]
        [String] $windowAuthenticationEnabled,
        [parameter(Mandatory=$true)]
        [String] $tempSiteName,
        [parameter(Mandatory=$true)]
        [String] $tempSitePhysicalPath,
        [parameter(Mandatory=$true)]
        [String] $backPath,
        [parameter(Mandatory=$true)]
        [String] $hostName
    )

    Write-Host "Ui project $name is already bundled";

    <#[string]$sourceDirectory  = "$targetPath\*"
    [string]$destinationDirectoryDeploy = "$deployPath"

    if(!(Test-Path -Path $deployPath )){
        New-Item -Path "$deployPath" -ItemType directory -ErrorAction SilentlyContinue
    }else{
        Remove-Item $deployPath -Force  -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -s 5
        New-Item -Path "$deployPath" -ItemType directory -ErrorAction SilentlyContinue
    }
    Start-Sleep -s 5
    Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectoryDeploy -ErrorAction SilentlyContinue
    Write-Host "Ui project $name deployed successfully";#>




    Import-Module WebAdministration
    $globalComputerName=(get-childitem -path env:computername).Value;
    $iisAppPoolName = $appPoolName;
    $iisAppPoolDotNetVersion = $appPoolDotNetVersion
    $iisAppName = $appName
    $directoryPath = $directoryPhysicalPath



    #navigate to the app pools root
    cd IIS:\AppPools\

    #check if the app pool exists
    if (!(Test-Path $iisAppPoolName -pathType container))
    {
        #create the app pool
        $appPool = New-Item $iisAppPoolName
        $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion 
        $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
        $appPool | Set-ItemProperty -name processModel.userName -Value $userId
        $appPool | Set-ItemProperty -name processModel.password -Value $password
        #$appPool | Set-ItemProperty -Name processModel -value @{userName="$userId";password="$password";identitytype=3}
    }else{
        $tempSite=Get-ChildItem IIS:\apppools | Where-Object {$_.Name -eq $iisAppPoolName}
        if($tempSite.Applications -ne $null){
            Write-Host "Application found inside $iisAppPoolName Apppool preparing clean -"
            RemoveAppIIS $tempSite.Applications
            Start-Sleep -s 5
            Write-Host "cleaning Apppool $iisAppPoolName "
            RemoveAppPoolIIS $iisAppPoolName;
            Start-Sleep -s 5
            Write-Host "$iisAppPoolName cleaned from system"
            Write-Host "creating apppool $iisAppPoolName again";
            $appPool = New-Item $iisAppPoolName
            $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
            $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
            $appPool | Set-ItemProperty -name processModel.userName -Value $userId
            $appPool | Set-ItemProperty -name processModel.password -Value $password
            #$appPool | Set-ItemProperty -Name processModel -Value @{userName="$userId";password="$password";identitytype=3}
        }
    }


    $tempSt=Get-Website -Name "$tempSiteName"
    if($tempSt -eq $null){
        Write-Host "Website $tempSiteName is not available creating the same"
        New-WebSite -Name "$tempSiteName" -Port $port -Protocol $protocol -HostHeader "$hostName" -PhysicalPath "$tempSitePhysicalPath" -Force 
        New-WebBinding -Name "$tempSiteName" -IPAddress "*" -Port $port -Protocol $protocol -Force
    }

    Start-Sleep -Seconds 2

    #navigate to the sites root
    cd IIS:\Sites\$tempSiteName

    #check if the site exists
    if (Test-Path $iisAppName -pathType container)
    {
        #return
        Remove-WebApplication -Name "$iisAppName" -Site "$tempSiteName"
    }
    $getWebSite=Get-Website -Name "$tempSiteName"
    if($getWebSite -eq $null){
        $iisApp = New-Item $tempSiteName -bindings @{protocol=$protocol;bindingInformation="*`:$port`:"+$globalComputerName} -physicalPath $directoryPath -Force
        $iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName 
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }else{
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }


    cd $backPath;
}

Function UpdateAppSettings {
    param(
        [parameter(Mandatory=$true)]
        [String] $path,
        [parameter(Mandatory=$true)]
        [String] $buildConfigPath,
        [parameter(Mandatory=$true)]
        [String] $newWebConfigPath
    )
    $xml = [xml](Get-Content $buildConfigPath);
    $xml2=[xml](Get-Content $path);
    $xml.Config.ProjectCollection.projectSetting.replace | %{
        $newKey=$_.key;
        $newValue=$_.newValue;
        $xml2.configuration.appSettings.add | %{
            $tempKey=$_.key;
            if($tempKey -eq $newKey){
                $_.value=$newValue;
            }
        }
        
    }
    $xml.Config.ProjectCollection.projectSetting.connectionString | % {
    $tempConnectionString = $_.connectionString;
        if($tempConnectionString -ne $null){
            if($xml2.configuration.connectionStrings -ne $null){
                $xml2.configuration.connectionStrings.add.connectionString=$tempConnectionString;
            }
        }
    }
    if($xml2.configuration.loggingConfiguration -ne $null){
        $xml.Config.ProjectCollection.projectSetting.log | %{
            if($_ -ne $null){
                $tempLogPath=$_.fileName;
                if($xml2.configuration.loggingConfiguration -ne $null){
                    $xml2.configuration.loggingConfiguration.listeners.add.fileName=$tempLogPath;
                }
            }
        }
    }
    $xml2.Save($newWebConfigPath)
}


Function UpdateAppConfig {
    param(
        [parameter(Mandatory=$true)]
        [String] $path,
        [parameter(Mandatory=$true)]
        [String] $buildConfigPath
    )
    $xml = [xml](Get-Content $buildConfigPath);
    $xml2=[xml](Get-Content $path);
    $xml.Config.ProjectCollection.projectSetting.replace | %{
        $newKey=$_.key;
        $newValue=$_.newValue;
        $xml2.configuration.appSettings.add | %{
            $tempKey=$_.key;
            if($tempKey -eq $newKey){
                $_.value=$newValue;
            }
        }
        
    }
    $xml.Config.ProjectCollection.projectSetting.connectionString | % {
    $tempConnectionString = $_.connectionString;
        if($tempConnectionString -ne $null){
            if($xml2.configuration.connectionStrings -ne $null){
                $xml2.configuration.connectionStrings.add.connectionString=$tempConnectionString;
            }
        }
    }
    if($xml2.configuration.loggingConfiguration -ne $null){
        $xml.Config.ProjectCollection.projectSetting.log | %{
            if($_ -ne $null){
                $tempLogPath=$_.fileName;
                if($xml2.configuration.loggingConfiguration -ne $null){
                    $xml2.configuration.loggingConfiguration.listeners.add.fileName=$tempLogPath;
                }
            }
        }
    }
    $xml2.Save($path)
}


Function RemoveAppPoolIIS {
    param(
        [parameter(Mandatory=$true)]
        [String] $name
    )
    Remove-WebAppPool $name
}

Function RemoveAppIIS {
    param(
        [parameter(Mandatory=$true)]
        [String] $name
    )
    Remove-WebSite -Name $name
}

Function StartService {
    param(
        [parameter(Mandatory=$true)]
        [String] $name
    )
    $status=Start-Service -Name $name;
    if($status -ne $null){
        return $true;
    }
    return $false;
}

Function DeployService {
    param(
        [parameter(Mandatory=$true)]
        [String] $path,
        [parameter(Mandatory=$true)]
        [String] $name,
        [parameter(Mandatory=$true)]
        [String] $description,
        [parameter(Mandatory=$true)]
        [String] $userId,
        [parameter(Mandatory=$true)]
        [String] $password
    )
    #$service=New-Service -Name $name -BinaryPathName $path -DisplayName $name -StartupType Manual -Description $description
    $service=C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /username=$userId /password=$password /unattended $path
    if($service -ne $null){
        return $true;
    }else{
        return $false;
    }
}


Function UninstallService {
    param(
        [parameter(Mandatory=$true)]
        [String] $path,
        [parameter(Mandatory=$true)]
        [String] $name,
        [parameter(Mandatory=$true)]
        [String] $description,
        [parameter(Mandatory=$true)]
        [String] $userId,
        [parameter(Mandatory=$true)]
        [String] $password
    )
    #$service=New-Service -Name $name -BinaryPathName $path -DisplayName $name -StartupType Manual -Description $description
    $service=C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe -u /username=$userId /password=$password $path
    if($service -ne $null){
        return $true;
    }else{
        return $false;
    }
}


Function CreateAppPoolInIIS {
    param(
        [parameter(Mandatory=$true)]
        [String] $appPoolName,
        [parameter(Mandatory=$true)]
        [String] $appPoolDotNetVersion,
        [parameter(Mandatory=$true)]
        [String] $appName,
        [parameter(Mandatory=$true)]
        [String] $directoryPhysicalPath,
        [parameter(Mandatory=$true)]
        [String] $protocol,
        [parameter(Mandatory=$true)]
        [String] $port,
        [parameter(Mandatory=$true)]
        [String] $userId,
        [parameter(Mandatory=$true)]
        [String] $password,
        [parameter(Mandatory=$true)]
        [String] $windowAuthenticationEnabled,
        [parameter(Mandatory=$true)]
        [String] $tempSiteName,
        [parameter(Mandatory=$true)]
        [String] $tempSitePhysicalPath,
        [parameter(Mandatory=$true)]
        [String] $hostName
    )
    Import-Module WebAdministration
    $globalComputerName=(get-childitem -path env:computername).Value;
    $iisAppPoolName = $appPoolName;
    $iisAppPoolDotNetVersion = $appPoolDotNetVersion
    $iisAppName = $appName
    $directoryPath = $directoryPhysicalPath

    #navigate to the app pools root
    cd IIS:\AppPools\

    #check if the app pool exists
    if (!(Test-Path $iisAppPoolName -pathType container))
    {
        #create the app pool
        $appPool = New-Item $iisAppPoolName
        $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion 
        $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
        $appPool | Set-ItemProperty -name processModel.userName -Value $userId
        $appPool | Set-ItemProperty -name processModel.password -Value $password
        #$appPool | Set-ItemProperty -Name processModel -value @{userName="$userId";password="$password";identitytype=3}
    }else{
        $tempSite=Get-ChildItem IIS:\apppools | Where-Object {$_.Name -eq $iisAppPoolName}
        if($tempSite.Applications -ne $null){
            Write-Host "Application found inside $iisAppPoolName Apppool preparing clean -"
            RemoveAppIIS $tempSite.Applications
            Start-Sleep -s 5
            Write-Host "cleaning Apppool $iisAppPoolName "
            RemoveAppPoolIIS $iisAppPoolName;
            Start-Sleep -s 5
            Write-Host "$iisAppPoolName cleaned from system"
            Write-Host "creating apppool $iisAppPoolName again";
            $appPool = New-Item $iisAppPoolName
            $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
            $appPool | Set-ItemProperty -name processModel.identityType -Value SpecificUser 
            $appPool | Set-ItemProperty -name processModel.userName -Value $userId
            $appPool | Set-ItemProperty -name processModel.password -Value $password
            #$appPool | Set-ItemProperty -Name processModel -Value @{userName="$userId";password="$password";identitytype=3}
        }
    }

    $tempSt=Get-Website -Name "$tempSiteName"
    if($tempSt -eq $null){
        Write-Host "Website $tempSiteName is not available creating the same"
        New-WebSite -Name "$tempSiteName" -Port $port -HostHeader "$hostName" -PhysicalPath "$tempSitePhysicalPath" -Force 
        New-WebBinding -Name "$tempSiteName" -IPAddress "*" -Port $port -Protocol $protocol -Force
    }

    Start-Sleep -Seconds 2

    #navigate to the sites root
    cd IIS:\Sites\$tempSiteName

    #check if the site exists
    if (Test-Path $iisAppName -pathType container)
    {
        #return
        Remove-WebApplication -Name "$iisAppName" -Site "$tempSiteName"
    }
    $getWebSite=Get-Website -Name "$tempSiteName"
    if($getWebSite -eq $null){
        $iisApp = New-Item $tempSiteName -bindings @{protocol=$protocol;bindingInformation="*`:$port`:"+$globalComputerName} -physicalPath $directoryPath -Force
        $iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName 
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }else{
        New-WebApplication -Name "$iisAppName" -Site "$tempSiteName" -ApplicationPool "$iisAppPoolName" -PhysicalPath "$directoryPath" -Force
    }

    #create the site
    

    #$iisApp = New-Item IIS:\Sites\$tempSiteName\$iisAppName -bindings @{protocol=$protocol;bindingInformation="*`:$port`:"+$globalComputerName} -physicalPath $directoryPath -Force
    #$iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName 

    if($windowAuthenticationEnabled -eq "true"){

        Write-Host Disable anonymous authentication
        Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -Value False -PSPath IIS:\Sites\$tempSiteName -Location "$iisAppName"

        Write-Host Enable windows authentication
        Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name Enabled -Value True -PSPath IIS:\Sites\$tempSiteName -Location "$iisAppName"
    }
}

Function BuildUIComponent {
    param(
       [parameter(Mandatory=$true)]
        [String] $path
    )
}


Function ReadConfig {
    param(
        [parameter(Mandatory=$true)]
        [String] $path
    )
    [xml]$XmlDocument = Get-Content -Path $path
    return $XmlDocument;
}

Function Build {
    param(
        [parameter(Mandatory=$true)]
        [bool] $nuget = $true,
        
        [parameter(Mandatory=$true)]
        [bool] $clean = $true,

        [parameter(Mandatory=$true)]
        [string] $executionEnvironment = "DEV"
    )
    
    if($executionEnvironment -eq "DEV"){
        #$env:Path += ";C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x86\signtool.exe"
        #$msBuildExe = 'C:\Program Files (x86)\MSBuild\14.0\Bin\msbuild.exe';
        #$msBuildExe='C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe'
        $XmlDocument = ReadConfig "buildConfig.xml";
        $targetBuildPath=$XmlDocument.Config.target.path;
        $bom_msbuild=$XmlDocument.Config.bom.msbuild.installationPath;
        $bom_signTool=$XmlDocument.Config.bom.signtool.installationPath;
        $bom_ng=$XmlDocument.Config.bom.ng.installationPath;
        $website_port=$XmlDocument.Config.website.port;
        $website_protocol=$XmlDocument.Config.website.protocol;
        $website_name=$XmlDocument.Config.website.siteName;
        $website_physicalPath=$XmlDocument.Config.website.physicalPath;
        $website_hostName=$XmlDocument.Config.website.hostName;
        $env:Path += ";$bom_signTool";
        $msBuildExe="$bom_msbuild";
        $targetFolderBuildParent=$XmlDocument.Config.target.folder;
        $XmlDocument.Config.ProjectCollection | % {
            $name=$_.project.name;
            $path=$_.project.path;
            $binPath=$_.project.binPath;
            $type=$_.type;
            $userId=$_.project.userid;
            $password=$_.project.password;
            $serviceName=$_.project.serviceName;
            $port=$website_port;
            $ui_build_deploy=$_.project.deployPath;
            $windowAuthenticationEnabled=$_.project.windowAuthenticationApplied;
            $tempSiteName=$website_name;
            if($type -eq "Windows Service" -or $type -eq "Api"){
                if($path -ne $null){
                    if ($nuget) {
                    Write-Host "Restoring NuGet packages" -foregroundcolor green
                    #nuget restore "$($path)"
                    }

                    if ($clean) {
                        Write-Host "Cleaning $($name)" -foregroundcolor green
                        & "$($msBuildExe)" "$($path)" /t:Clean /m
                    }

                    Write-Host "Building $($name)" -foregroundcolor green
                    & "$($msBuildExe)" "$($path)" /p:DeployOnBuild=true /p:PublishProfile=FolderProfile 
                    Write-Host "Project $name is successfully build";
                    Write-Host "Preparing target folder to copy";
                    $tempPath="$targetBuildPath\$name";
                    Write-Host $tempPath;
                    if(!(Test-Path -Path $tempPath )){
                        New-Item -Path "$tempPath" -ItemType directory -ErrorAction SilentlyContinue
                    }else{
                        Remove-Item $tempPath -Force  -Recurse -ErrorAction SilentlyContinue
                        Start-Sleep -s 5
                        New-Item -Path "$tempPath" -ItemType directory -ErrorAction SilentlyContinue
                    }
                
                    Write-Host "target folder created successfully";
                    Write-Host "copying build file";
                    [string]$sourceDirectory  = "$binPath\*"
                    [string]$destinationDirectory = "$tempPath"
                    Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectory -ErrorAction SilentlyContinue
                    Write-Host "build completed successfully for project $name"
                }else{
                    Write-Host "Please provide all mandatory field in buildConfig.xml"
                }
                if($type -eq "Api"){
                    Write-Host "Creating Apppool and website for the api $name in iis";
                    $appPoolName=("{0}{1}" -f $name,"AppPool" );
                    $appPoolDotNetVer="v4.0";
                    $appName=$name;
                    $physicalPath="$tempPath";
                    $protocol=$_.project.protocol;
                    CreateAppPoolInIIS $appPoolName $appPoolDotNetVer $appName $physicalPath $website_protocol $website_port $userId $password $windowAuthenticationEnabled $tempSiteName $website_physicalPath $website_hostName
                    Write-Host "Api deployed successfully";
                    #cd "C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation";
                    cd $targetFolderBuildParent;
                    $appConfigPath="$tempPath\$name.dll.config";
                    $newWebConfigPath="$physicalPath\Web.config";
                    Write-Host "Updating config path";
                    UpdateAppSettings $newWebConfigPath "buildConfig.xml" $newWebConfigPath;
                    Write-Host "Config file updated successfully";
                }
                if($type -eq "Windows Service"){
                    $tempPathSer=("{0}{1}" -f $tempPath,"\WindowsService.exe" );
                    $nameSer=$name;
                    $decription="Diagnostic Workbench Service";
                    $tempService=Get-Service -Name $nameSer -ErrorAction SilentlyContinue
                    if($tempService -eq $null){
                        Write-Host "Deploying the service $name "
                        DeployService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 10
                    }else{
                        #Remove-Service -Name $nameSer
                        #get-ciminstance win32_service -filter "name=`'$nameSer`'" | remove-ciminstance
                        UninstallService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 5
                        DeployService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 10
                    }
                
                    Write-Host "Installing the service";

                    # update app config value

                    #cd $targetFolderBuildParent;
                    $appConfigPath_app="$tempPath\WindowsService.exe.config";
                    Write-Host "Updating config path";
                    UpdateAppConfig $appConfigPath_app "buildConfig.xml";
                    Write-Host "Config file updated successfully";

                    # end update app config value

                    StartService $serviceName
                    Write-Host "Starting the service"
                }
            }elseif($type -eq "Ui"){
                $ui_path="$targetBuildPath\$name";
                $ui_buildPath=$path;
                $ui_deploy_path=$ui_build_deploy;
                $ui_name=$name;

                $appPoolName=("{0}{1}" -f $name,"AppPool" );
                $appPoolDotNetVer="v4.0";
                $appName=$name;
                $physicalPath="$targetBuildPath\$name";
                $protocol=$website_protocol;

                #C:\Users\itsdevazrapp002_svc\AppData\Roaming\npm
                $env:path=$env:path+";$bom_ng"
                Write-Host "building ui component"
                Write-Host "bundling angular"
                CreateUiBuild $ui_buildPath $ui_path $ui_deploy_path $ui_name $targetFolderBuildParent $appPoolName $appPoolDotNetVer $appName $physicalPath $website_protocol $website_port $userId $password $windowAuthenticationEnabled $tempSiteName $website_physicalPath
            }
        }
        
    }elseif($executionEnvironment -eq "QA" -or $executionEnvironment -eq "STG" -or $executionEnvironment -eq "PRD"){
        $env:Path += ";C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x86\signtool.exe"
        #$msBuildExe = 'C:\Program Files (x86)\MSBuild\14.0\Bin\msbuild.exe';
        $msBuildExe='C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe'
        $XmlDocument = ReadConfig "buildConfig.xml";
        $website_port=$XmlDocument.Config.website.port;
        $website_protocol=$XmlDocument.Config.website.protocol;
        $website_name=$XmlDocument.Config.website.siteName;
        $website_physicalPath=$XmlDocument.Config.website.physicalPath;
        $website_hostName=$XmlDocument.Config.website.hostName;
        $targetBuildPath=$XmlDocument.Config.target.path;
        $targetFolderBuildParent=$XmlDocument.Config.target.folder;
        $XmlDocument.Config.ProjectCollection | % {
            $name=$_.project.name;
            $path=$_.project.path;
            $binPath=$_.project.binPath;
            $type=$_.type;
            $userId=$_.project.userid;
            $password=$_.project.password;
            $serviceName=$_.project.serviceName;
            $port=$website_port;
            $windowAuthenticationEnabled=$_.project.windowAuthenticationApplied;
            $tempSiteName=$website_name;
            if($type -eq "Windows Service" -or $type -eq "Api"){
                if($path -ne $null){
                    $tempPath="$targetBuildPath\$name";
                    <# if ($nuget) {
                    Write-Host "Restoring NuGet packages" -foregroundcolor green
                    #nuget restore "$($path)"
                    }

                    if ($clean) {
                        Write-Host "Cleaning $($name)" -foregroundcolor green
                        & "$($msBuildExe)" "$($path)" /t:Clean /m
                    }

                    Write-Host "Building $($name)" -foregroundcolor green
                    & "$($msBuildExe)" "$($path)" /t:Build /m /p:Configuration=Release  /p:Platform="Any CPU" #>
                    Write-Host "Project $name is already builded";
                   <# Write-Host "Preparing target folder to copy";
                    $tempPath="$targetBuildPath\$name";
                    Write-Host $tempPath;
                    if(!(Test-Path -Path $tempPath )){
                        New-Item -Path "$tempPath" -ItemType directory -ErrorAction SilentlyContinue
                    }else{
                        Remove-Item $tempPath -Force  -Recurse -ErrorAction SilentlyContinue
                        Start-Sleep -s 5
                        New-Item -Path "$tempPath" -ItemType directory -ErrorAction SilentlyContinue
                    }
                
                    Write-Host "target folder created successfully";
                    Write-Host "copying build file";
                    [string]$sourceDirectory  = "$binPath\*"
                    [string]$destinationDirectory = "$tempPath"
                    Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectory -ErrorAction SilentlyContinue
                    Write-Host "build completed successfully for project $name" #>
                }else{
                    Write-Host "Please provide all mandatory field in buildConfig.xml"
                }
                if($type -eq "Api"){
                    <#Write-Host "Creating Apppool and website for the api $name in iis";
                    $appPoolName=("{0}{1}" -f $name,"AppPool" );
                    $appPoolDotNetVer="v4.0";
                    $appName=$name;
                    $physicalPath=$tempPath;
                    $protocol=$_.project.protocol;
                    CreateAppPoolInIIS $appPoolName $appPoolDotNetVer $appName $physicalPath $protocol $port $userId $password
                    Write-Host "Api deployed successfully";
                    #cd "C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation";
                    cd $targetFolderBuildParent;
                    $appConfigPath="$tempPath\$name.dll.config";
                    $newWebConfigPath="$tempPath\Web.config";
                    Write-Host "Updating config path";
                    UpdateAppSettings $appConfigPath "buildConfig.xml" $newWebConfigPath
                    Write-Host "Config file updated successfully";#>


                    Write-Host "Creating Apppool and website for the api $name in iis";
                    $appPoolName=("{0}{1}" -f $name,"AppPool" );
                    $appPoolDotNetVer="v4.0";
                    $appName=$name;
                    $physicalPath="$tempPath";
                    $protocol=$_.project.protocol;

                    

                    CreateAppPoolInIIS $appPoolName $appPoolDotNetVer $appName $physicalPath $website_protocol $website_port $userId $password $windowAuthenticationEnabled $website_name $website_physicalPath $website_hostName
                    Write-Host "Api deployed successfully";
                    #cd "C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation";
                    cd $targetFolderBuildParent;
                    $appConfigPath="$tempPath\$name.dll.config";
                    $newWebConfigPath="$physicalPath\Web.config";
                    Write-Host "Updating config path";
                    UpdateAppSettings $newWebConfigPath "buildConfig.xml" $newWebConfigPath;
                    Write-Host "Config file updated successfully";
                }
                if($type -eq "Windows Service"){
                    $tempPathSer=("{0}{1}" -f $tempPath,"\WindowsService.exe" );
                    $nameSer=$name;
                    $decription="Diagnostic Workbench Service";
                    $tempService=Get-Service -Name $nameSer -ErrorAction SilentlyContinue
                    if($tempService -eq $null){
                        Write-Host "Deploying the service $name "
                        DeployService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 10
                    }else{
                        #Remove-Service -Name $nameSer
                        #get-ciminstance win32_service -filter "name=`'$nameSer`'" | remove-ciminstance
                        UninstallService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 5
                        DeployService $tempPathSer $nameSer $decription $userId $password
                        Start-Sleep -s 10
                    }
                
                    Write-Host "Installing the service";

                    $appConfigPath_app="$tempPath\WindowsService.exe.config";
                    Write-Host "Updating config path";
                    UpdateAppConfig $appConfigPath_app "buildConfig.xml";
                    Write-Host "Config file updated successfully";

                    StartService $serviceName
                    Write-Host "Starting the service"
                }
            }elseif($type -eq "Ui"){
                $ui_path="$targetBuildPath\$name";
                $ui_buildPath=$path;
                $ui_deploy_path="$ui_build_deploy\$name";
                $ui_name=$name;
                $env:path=$env:path+";$bom_ng"

                $appPoolName=("{0}{1}" -f $name,"AppPool" );
                $appPoolDotNetVer="v4.0";
                $appName=$name;
                $physicalPath="$targetBuildPath\$name";
                $protocol=$website_protocol;

                #$env:path=$env:path+";C:\Users\itsdevazrapp002_svc\AppData\Roaming\npm"
                Write-Host "building ui component"
                Write-Host "bundling angular"
                DeployUiBuild $ui_path $ui_deploy_path $ui_name $appPoolName $appPoolDotNetVer $appName $physicalPath $website_protocol $website_port $userId $password $windowAuthenticationEnabled $tempSiteName $website_physicalPath $targetFolderBuildParent $website_hostName
            }
        }
    }else{
        Write-Error "unknown input for 'executionEnvironment' parameter supported value is 'DEV' and 'QA' "
    }
}


Function BuildInvoker {
    Write-Host "Please provide the ExecutionEnvironment name .!!";
    Write-Host "Accepted Values are 'DEV','QA','STG' and 'PRD'";
    Write-Host "Please provide the ExecutionEnvironment name .!!";
    Write-Host "Please Note that value is case sensitive so ensure capital case while providing the input"
    $executionEnvironment=Read-Host 'Please provide the ExecutionEnvironment name.'
    if($executionEnvironment -ne $null){
        if($executionEnvironment -eq "DEV" -or $executionEnvironment -eq "QA" -or $executionEnvironment -eq "STG" -or $executionEnvironment -eq "PRD"){
            Build $true $true $executionEnvironment
        }else{
            Write-Error "wrong input for executionEnvironment ";
        }
    }else{
        Write-Error "executionEnvironment value cannot be null";
    }
}

BuildInvoker

#for dev to qa movement please provide third parameter as 'DEV'
#Build $true $true "DEV"


#for qa to production movement please provide third parameter as 'QA'
#Build $true $true "PRD"