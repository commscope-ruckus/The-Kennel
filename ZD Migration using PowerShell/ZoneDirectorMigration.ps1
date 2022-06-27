class MaskCalculator
{
    [String]getMask([int]$Num)
    {
        if($Num -gt 8)
        {
                if($Num -gt 16)
                {
                    if($Num -gt 24)
                    {
                            $Bits = $Num - 24
                            $Bits = 8 - $Bits    
                            $Mask = [Math]::Pow(2,$Bits)
                            $Mask = 256 - $Mask
                            $Mask = "255.255.255.$($Mask)"
                    }
                    else
                    {
                        if($Num -eq 24)
                        {
                            $Mask = "255.255.255.0"
                        }
                        else
                        {
                            $Bits = $Num - 16
                            $Bits = 8 - $Bits    
                            $Mask = [Math]::Pow(2,$Bits)
                            $Mask = 256 - $Mask
                            $Mask = "255.255.$($Mask).0"
                        }
                    }
                }
                else
                {
                    if($Num -eq 16)
                    {
                        $Mask = "255.255.0.0"
                    }
                    else
                    {
                        $Bits = $Num - 8
                        $Bits = 8 - $Bits    
                        $Mask = [Math]::Pow(2,$Bits)
                        $Mask = 256 - $Mask
                        $Mask = "255.$($Mask).0.0"
                    }
                
                }
        }
        else
        {
            if($Num -eq 8)
            {
                $Mask = "255.0.0.0"
            }
            else
            {
                $Bits = 8 - $Num    
                $Mask = [Math]::Pow(2,$Bits)
                $Mask = 256 - $Mask
                $Mask = "$($Mask).0.0.0"
            }    
        }

        return $Mask
    }
}

class CloudUpload_21_01_11
{
    [PSCustomObject]$ZDParsedObjects
    [PSCustomObject]$ZDCreds
    [String]$ZDIP
    [PSCustomObject]$AuthToken
    [Array]$L2ACLs
    [Array]$L3ACLs
    [Array]$VLANPools
    [Array]$CloudpathServers
    [Array]$MigrationVenue
    [Array]$CloudWLANs
    [Array]$DPSKs
    [PSCustomObject]$JSON
    [String]$URLString


    
    deleteAll()
    {
        Write-Host "Removing all Cloud Controller Configurations because of error"
        Start-Sleep 5
        
        if($this.CloudWLANs.Count -gt 0)
        {
            Write-Host "`t WLANs"
            foreach($WLAN in $this.CloudWLANs)
            {
                $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/network/$($WLAN.id)"
                $Headers = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "Authorization" = "$($this.AuthToken.'API-KEY')"
                }
                Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                Start-Sleep 10
            }
        }        

        if($this.CloudpathServers.count -gt 0)
        {
            Write-Host "`t Cloudpath Servers"
            foreach($Servers in $this.CloudpathServers)
            {
                $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/cloudpath/$($Servers.id)"
                $Headers = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "Authorization" = "$($this.AuthToken.'API-KEY')"
                }
                Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                Start-Sleep 5
            }
        }
        
        if($this.L2ACLs.Count -gt 0 -or $this.L3ACLs.Count -gt 0)
        {
            if($this.L2ACLs.Count -gt 0)
            {
                Write-Host "`t L2 ACLs"
                foreach($L2s in $this.L2ACLs)
                {
                    $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/l2-acl-policy/$($L2s.id)"
                    $Headers = @{
                    "Accept" = "application/json"
                    "Content-Type" = "application/json"
                    "Authorization" = "$($this.AuthToken.'API-KEY')"
                    }
                    Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                    Start-Sleep 5
                }
            }

            if($this.L3ACLs.Count -gt 0)
            {
                Write-Host "`t L3 ACLs"
                foreach($L3s in $this.L3ACLs)
                {
                    $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/l3-acl-policy/$($L3s.id)"
                    $Headers = @{
                    "Accept" = "application/json"
                    "Content-Type" = "application/json"
                    "Authorization" = "$($this.AuthToken.'API-KEY')"
                    }
                    Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                    Start-Sleep 5
                }
            }
        }

        if($this.VLANPools.count -gt 0)
        {
            Write-Host "`t VLANPools"
            foreach($VLANPool in $this.VLANPools)
            {
                $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/vlan-pool/$($VLANPool.id)"
                $Headers = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "Authorization" = "$($this.AuthToken.'API-KEY')"
                }
                Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                Start-Sleep 5
            }
        }

        if($this.MigrationVenue.count -gt 0)
        {
            Write-Host "`t Migration Venues"
            foreach($Venue in $this.MigrationVenue)
            {
                                        
                $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/venue/$($Venue.id)"
                $Headers = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "Authorization" = "$($this.AuthToken.'API-KEY')"
                }
                Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers | Out-Null
                Start-Sleep 5
            }
        }
    }

    [boolean]setVenue()
    {
        try
        {
            $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/venue"
            $Headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"
            "Authorization" = "$($this.AuthToken.'API-KEY')"
            }
            $Body = Get-Content .\CloudJSON\21_01_11\BaseVenue.json
            $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
            $this.MigrationVenue += $response.response
            Start-Sleep 5

            return $true
        }
        catch
        {
            Write-Host "ERROR: setVenue"
            Write-Host $_
            return $false
        }
    }

    [boolean]setCloudpathServers()
    {
        if($this.ZDParsedObjects.AAAs.Count -gt 0)
        {
    
            for($Count = 0; $Count -lt $this.ZDParsedObjects.AAAs.Count; $Count++)
            {
                try
                {
                    $AAA = $this.ZDParsedObjects.AAAs[$Count]
                    if($AAA.Type -imatch "RADIUS server")
                    {
                        $CloudpathJSON = Get-Content .\CloudJSON\21_01_11\BaseCloudpath.json
                        $CloudpathJSON = $CloudpathJSON | ConvertFrom-Json
                        
                        if($AAA.PrimaryRADIUS.RadiusType -imatch "Cloud")
                        {
                            $CloudpathJSON.PSObject.Properties.Remove("deployedInVenueId")
                            $CloudpathJSON.PSObject.Properties.Remove("deployedInVenueName")

                            $CloudpathJSON.name = $AAA.Name
                            $CloudpathJSON.deploymentType = "Cloud"
                            $CloudpathJSON.authRadius.primary.ip = $AAA.PrimaryRADIUS.IPAddress
                            $CloudpathJSON.authRadius.primary.port = $AAA.PrimaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAA.PrimaryRADIUS.Secret,"Something")
                            $CloudpathJSON.authRadius.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            if($AAA.encryptionTLS -inotmatch "Disabled" -and $AAA.encryptionTLS.Length -ne 0)
                            {
                                $CloudpathJSON.authRadius.tlsEnabled = $true
                            }

                            $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/cloudpath"
                            $Headers = @{
                                "Accept" = "application/json"
                                "Content-Type" = "application/json"
                                "Authorization" = "$($this.AuthToken.'API-KEY')"
                            }
                            $Body = $CloudpathJSON | ConvertTo-Json
            
                            $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                            $this.CloudpathServers += $response.response
                            Start-Sleep 6
                        }
                        elseif($AAA.PrimaryRADIUS.RadiusType -imatch "Onprem")
                        {
                            $CloudpathJSON.deployedInVenueId = ($this.MigrationVenue | Where-Object -Property Name -EQ "ZD Migration").id
                            $CloudpathJSON.deployedInVenueName = "ZD Migration"
                            $CloudpathJSON.name = $AAA.Name
                            $CloudpathJSON.deploymentType = "OnPremise"
                            $CloudpathJSON.authRadius.primary.ip = $AAA.PrimaryRADIUS.IPAddress
                            $CloudpathJSON.authRadius.primary.port = $AAA.PrimaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAA.PrimaryRADIUS.Secret,"Something")
                            $CloudpathJSON.authRadius.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            if($AAA.encryptionTLS -inotmatch "Disabled" -and $AAA.encryptionTLS.Length -ne 0)
                            {
                                $CloudpathJSON.authRadius.tlsEnabled = $true
                            }
                        
                            $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/cloudpath"
                            $Headers = @{
                            "Accept" = "application/json"
                            "Content-Type" = "application/json"
                            "Authorization" = "$($this.AuthToken.'API-KEY')"
                            }
                            $Body = $CloudpathJSON | ConvertTo-Json
            
                            $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                            $this.CloudpathServers += $response.response
                            Start-Sleep 6
                        }

                        $CloudpathJSON = Get-Content .\CloudJSON\21_01_11\BaseCloudpath.json
                        $CloudpathJSON = $CloudpathJSON | ConvertFrom-Json

                        if($AAA.SecondaryRADIUS.RadiusType -imatch "Cloud")
                        {
                            $CloudpathJSON.PSObject.Properties.Remove("deployedInVenueId")
                            $CloudpathJSON.PSObject.Properties.Remove("deployedInVenueName")

                            $CloudpathJSON.name = $AAA.Name
                            $CloudpathJSON.deploymentType = "Cloud"
                            $CloudpathJSON.authRadius.primary.ip = $AAA.SecondaryRADIUS.IPAddress
                            $CloudpathJSON.authRadius.primary.port = $AAA.SecondaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAA.SecondaryRADIUS.Secret,"Something")
                            $CloudpathJSON.authRadius.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            if($AAA.encryptionTLS -inotmatch "Disabled" -and $AAA.encryptionTLS.Length -ne 0)
                            {
                                $CloudpathJSON.authRadius.tlsEnabled = $true
                            }

                            $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/cloudpath"
                            $Headers = @{
                                "Accept" = "application/json"
                                "Content-Type" = "application/json"
                                "Authorization" = "$($this.AuthToken.'API-KEY')"
                            }
                            $Body = $CloudpathJSON | ConvertTo-Json
            
                            $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                            $this.CloudpathServers += $response.response
                            Start-Sleep 6

                        }
                        elseif($AAA.SecondaryRADIUS.RadiusType -imatch "Onprem")
                        {
                            $CloudpathJSON.deployedInVenueId = ($this.MigrationVenue | Where-Object -Property Name -EQ "ZD Migration").id
                            $CloudpathJSON.deployedInVenueName = "ZD Migration"
                            $CloudpathJSON.name = $AAA.Name
                            $CloudpathJSON.deploymentType = "OnPremise"
                            $CloudpathJSON.authRadius.primary.ip = $AAA.SecondaryRADIUS.IPAddress
                            $CloudpathJSON.authRadius.primary.port = $AAA.SecondaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAA.SecondaryRADIUS.Secret,"Something")
                            $CloudpathJSON.authRadius.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            if($AAA.encryptionTLS -inotmatch "Disabled" -and $AAA.encryptionTLS.Length -ne 0)
                            {
                                $CloudpathJSON.authRadius.tlsEnabled = $true
                            }
                    
                            $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/cloudpath"
                            $Headers = @{
                            "Accept" = "application/json"
                            "Content-Type" = "application/json"
                            "Authorization" = "$($this.AuthToken.'API-KEY')"
                            }
                            $Body = $CloudpathJSON | ConvertTo-Json
            
                            $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                            $this.CloudpathServers += $response.response
                            Start-Sleep 6
                        }
                    }
                    
                }
                catch
                {
                    Write-Host "ERROR: setCloudpathServers"
                    Write-Host $_
                    return $false
                }
            }
            return $true
        }
        else
        {
            return $true
        }
    }
    
    [boolean]setVLANPools()
    {
        if($this.ZDParsedObjects.VLANPools.Count -gt 0)
        {
            try
            {
                $VLANPoolCount = ($this.ZDParsedObjects.VLANPools.Count)
                for($count = 0;$count -lt $VLANPoolCount;$count++)
                {
                    $VLANPoolJSON = Get-Content .\CloudJSON\21_01_11\BaseVLANPool.json
                    $VLANPoolJSON = $VLANPoolJSON | ConvertFrom-Json
                    $command = "`$this.ZDParsedObjects.VLANPools[$count]"
                    $VLANPool = Invoke-Expression $command
                    $VLANPoolJSON.name = $VLANPool.Name
                    $VLANPoolJSON.description = $VLANPool.Description
                    $VLANMembers = @()
                    $VLANs = $VLANPool.VLANSET -split ","
                    foreach($Vlan in $VLANs)
                    {
                        if($VLAN -ne "1")
                        {
                            $VLANMembers += $VLAN
                        }
                        
                        
                    }
                    $VLANPoolJSON.vlanMembers = $VLANMembers

                    $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/vlan-pool"
                    $Headers = @{
                        "Accept" = "application/json"
                        "Content-Type" = "application/json"
                        "Authorization" = "$($this.AuthToken.'API-KEY')"
                    }
                    $Body = $VLANPoolJSON | ConvertTo-Json
        
                    $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                    $this.VLANPools += $response.response
                    Start-Sleep 5
                }
                
                return $true
            }
            catch
            {
                Write-Host "ERROR: setVLANPools"
                Write-Host $_
                return $false
            }
        }
        else
        {
            return $true
        }
    }

    [boolean]setACLs()
    {
        try
        {
            if($this.ZDParsedObjects.ACLs.L2.Count -gt 0)
            {
                $ACLCount = $this.ZDParsedObjects.ACLs.L2.Count
                for($count = 0;$count -lt $ACLCount;$count++)
                {
                    $L2JSON = Get-Content .\CloudJSON\21_01_11\BaseL2ACL.json
                    $L2JSON = $L2JSON | ConvertFrom-Json

                    $command = "`$this.ZDParsedObjects.ACLs.L2[$count]"
                    $ACL = Invoke-Expression $command 
                    if($ACL.Stations.Count -gt 0)
                    {
                        $L2JSON.name = $ACL.Name
                        $L2JSON.description = $ACL.Description
                        if($ACL.Restriction -imatch "(.*)Allow(.*)")
                        {
                            $L2JSON.access = "ALLOW"
                        }
                        else
                        {
                            $L2JSON.access = "BLOCK"
                        }
                        $L2JSON.macAddresses = $ACL.Stations
                                        
                        $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/l2-acl-policy"
                        $Headers = @{
                        "Accept" = "application/json"
                        "Content-Type" = "application/json"
                        "Authorization" = "$($this.AuthToken.'API-KEY')"
                        }

                        $Body = $L2JSON | ConvertTo-Json
                        $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                        $this.L2ACLs += $response.response
                        Start-Sleep 5
                    }
                }
            }

            if($this.ZDParsedObjects.ACLs.L3.Count -gt 0)
            {
                $ACLCount = $this.ZDParsedObjects.ACLs.L3.Count
                for($OutCount = 0;$OutCount -lt $ACLCount;$OutCount++)
                {
                    $L3JSON = Get-Content .\CloudJSON\21_01_11\BaseL3ACL.json | Out-String | Convertfrom-Json

                    $command = "`$this.ZDParsedObjects.ACLs.L3[$OutCount]"
                    $ACL = Invoke-Expression $command
                    if($ACL.Rules.Count -gt 0)
                    {
                        $L3JSON.name = $ACL.Name
                        $L3JSON.description = $ACL.Description
                        if($ACL.DefaultAction -imatch "(.*)Allow(.*)")
                        {
                            $L3JSON.defaultAccess = "ALLOW"
                        }
                        else
                        {
                            $L3JSON.defaultAccess = "BLOCK"
                        }
    
                        
                        $L3JSON.l3Rules = @()
                        for($InCount = 0; $InCount -lt $ACL.Rules.Count; $InCount++ )
                        {
                            $L3JSONRulesHolder = Get-Content .\CloudJSON\21_01_11\BaseL3ACL.json
                            $L3JSONRulesHolder = $L3JSONRulesHolder | ConvertFrom-Json
                            $L3JSONRulesHolder = $L3JSONRulesHolder.l3Rules[0]
                            
                            $ACLRule = $ACL.Rules[$InCount]
                            $L3JSONRulesHolder.priority = ($InCount + 1)
                            $L3JSONRulesHolder.description = $ACLRule.Description
                            if($ACLRule.Type -imatch "(.*)Allow(.*)")
                            {
                                $L3JSONRulesHolder.access = "ALLOW"
                            }
                            else
                            {
                                $L3JSONRulesHolder.access = "BLOCK"
                            }
    
                            if($ACLRule.Protocol -imatch "(.*)Any(.*)")
                            {
                                $L3JSONRulesHolder.PSObject.Properties.Remove("protocol")
                                $L3JSONRulesHolder.PSObject.Properties.Remove("customProtocol")
                            }
                            else
                            {
                                $L3JSONRulesHolder.protocol = "L3ProtocolEnum_CUSTOM"
                                $L3JSONRulesHolder.customProtocol = $ACLRule.Protocol
                            }
    
                            $NetworkMask = $ACLRule.SourceAddress -split "/"
                            if([int]$NetworkMask[1] -lt 32 -and [int]$NetworkMask[1] -gt 0)
                            {
                                $Mask = $NetworkMask[1]
                                $Mask = [MaskCalculator]::new().getMask($Mask)
                                $L3JSONRulesHolder.source.enableIpSubnet = $true
                                $L3JSONRulesHolder.source.ip = $NetworkMask[0]
                                $L3JSONRulesHolder.source.ipMask = $Mask
                                
                            }
                            elseif([int]$NetworkMask[1] -eq 32)
                            {
                                $L3JSONRulesHolder.source.PSObject.Properties.Remove("ipMask")
                                $L3JSONRulesHolder.source.ip = $NetworkMask[0]
                                if($ACLRule.SourcePort -gt 0)
                                {
                                $L3JSONRulesHolder.source.port = $ACLRule.SourcePort
                            }
                                else
                                {
                                $L3JSONRulesHolder.source.PSObject.Properties.Remove("port")
                            }
                            }
                            else
                            {
                                $L3JSONRulesHolder.source.PSObject.Properties.Remove("ipMask")
                                $L3JSONRulesHolder.source.PSObject.Properties.Remove("ip")
                            }
                            
                            if($ACLRule.SourcePort -imatch "(.*)Any(.*)")
                            {
                                $L3JSONRulesHolder.source.PSObject.Properties.Remove("port")
                            }
                            else
                            {
                                $L3JSONRulesHolder.source.port = $ACLRule.SourcePort
                            }
    
                            $NetworkMask = $ACLRule.DestinationAddress -split "/"
                            if([int]$NetworkMask[1] -lt 32 -and [int]$NetworkMask[1] -gt 0)
                            {
                                $Mask = $NetworkMask[1]
                                $Mask = [MaskCalculator]::new().getMask($Mask)
                                $L3JSONRulesHolder.destination.enableIpSubnet = $true
                                $L3JSONRulesHolder.destination.ip = $NetworkMask[0]
                                $L3JSONRulesHolder.destination.ipMask = $Mask
                            }
                            elseif([int]$NetworkMask[1] -eq 32)
                            {
                                $L3JSONRulesHolder.destination.PSObject.Properties.Remove("ipMask")
                                $L3JSONRulesHolder.destination.ip = $NetworkMask[0]
                            }
                            else
                            {
                                $L3JSONRulesHolder.destination.PSObject.Properties.Remove("ipMask")
                                $L3JSONRulesHolder.destination.PSObject.Properties.Remove("ip")
                            }
    
                            if($ACLRule.DestinationPort -imatch "(.*)Any(.*)")
                            {
                                $L3JSONRulesHolder.destination.PSObject.Properties.Remove("port")
                            }
                            else
                            {
                                $L3JSONRulesHolder.destination.port = $ACLRule.DestinationPort
                            }
                           
                            $L3JSON.l3Rules += $L3JSONRulesHolder 
                        }
    
                        #KEEP: Need this becasue ConvertTo-Json commandlet doesn't work correctly with nested arrays (source and destination in l3Rules)
                        $L3JSONConvert = $L3JSON | ConvertTo-Json -Compress
                        $L3JSONConvert = $L3JSONConvert -replace "\[.*\]", ($L3JSON.l3Rules | ConvertTo-Json -Compress)
                        
    
                        $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/l3-acl-policy"
                        $Headers = @{
                        "Accept" = "application/json"
                        "Content-Type" = "application/json"
                        "Authorization" = "$($this.AuthToken.'API-KEY')"
                        }
                        $Body = $L3JSONConvert
                        $response = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop
                        $this.L3ACLs += $response.response
                        #Need this because the current APIs take time to upload
                        Start-Sleep 5
                    }
                }
            }

            return $true
        }
        catch
        {
            Write-Host "ERROR: setACLs"
            Write-Host $_
            return $false
        }
    }
    
    setWLANGeneralAdvancedSettings([PSCustomObject]$WLAN,[int]$Count)
    {
         $RemovedVLANPool = $false
        
        #Encryption and Passphrase
        $HolderVar = $WLAN.Encryption
        if($HolderVar -imatch "wpa23-mixed")
        {
            $this.JSON.wlan.wlanSecurity = "WPA23Mixed"
            $this.JSON.wlan.passphrase = $WLAN.PSKPassphrase
            $this.JSON.wlan.saePassphrase = $WLAN.SAEPassphrase
            $this.JSON.wlan.PSObject.Properties.Remove("wepHexKey")
    
            if($WLAN.PMF11w -inotmatch "Disabled")
            {
                if($WLAN.PMF11w -imatch "Optional")
                {
                    $this.JSON.wlan.managementFrameProtection = "Optional"
                }
                elseif($WLAN.PMF11w -imatch "Required")
                {
                    $this.JSON.wlan.managementFrameProtection = "Required"
                }
            }
        }
        elseif($HolderVar -imatch "wpa2")
        {
            $this.JSON.wlan.wlanSecurity = "WPA2Personal"
            $this.JSON.wlan.passphrase = $WLAN.Passphrase
            $this.JSON.wlan.PSObject.Properties.Remove("saePassphrase")
            $this.JSON.wlan.PSObject.Properties.Remove("wepHexKey")
            if($WLAN.PMF11w -inotmatch "Disabled")
            {
                if($WLAN.PMF11w -imatch "Optional")
                {
                    $this.JSON.wlan.managementFrameProtection = "Optional"
                }
                elseif($WLAN.PMF11w -imatch "Required")
                {
                    $this.JSON.wlan.managementFrameProtection = "Required"
                }
            }
        }
        elseif($HolderVar -imatch "wpa3")
        {
            $this.JSON.wlan.wlanSecurity = "WPA3"
            $this.JSON.wlan.saePassphrase = $WLAN.Passphrase
            $this.JSON.wlan.PSObject.Properties.Remove("passphrase")
            $this.JSON.wlan.PSObject.Properties.Remove("wepHexKey")
    
            if($WLAN.PMF11w -inotmatch "Disabled")
            {
                if($WLAN.PMF11w -imatch "Optional")
                {
                    $this.JSON.wlan.managementFrameProtection = "Optional"
                }
                elseif($WLAN.PMF11w -imatch "Required")
                {
                    $this.JSON.wlan.managementFrameProtection = "Required"
                }
            }
        }
        elseif($HolderVar -imatch "wep128")
        {
            $this.JSON.wlan.wlanSecurity = "WEP"
            $this.JSON.wlan.wepHexKey = $WLAN.WEPKey
            $this.JSON.wlan.PSObject.Properties.Remove("managementFrameProtection")
            $this.JSON.wlan.PSObject.Properties.Remove("passphrase")
            $this.JSON.wlan.PSObject.Properties.Remove("saePassphrase")
        }
        elseif($HolderVar -imatch "wpa-mixed")
        {
            $this.JSON.wlan.wlanSecurity = "WPAPersonal"
            $this.JSON.wlan.passphrase = $WLAN.Passphrase
            $this.JSON.wlan.PSObject.Properties.Remove("managementFrameProtection")
            $this.JSON.wlan.PSObject.Properties.Remove("saePassphrase")
            $this.JSON.wlan.PSObject.Properties.Remove("wepHexKey")
        }
        elseif($HolderVar -imatch "none")
        {
            $this.JSON.wlan.PSObject.Properties.Remove("wlanSecurity")
            $this.JSON.wlan.PSObject.Properties.Remove("managementFrameProtection")
            $this.JSON.wlan.PSObject.Properties.Remove("saePassphrase")
            $this.JSON.wlan.PSObject.Properties.Remove("wepHexKey")
            $this.JSON.wlan.PSObject.Properties.Remove("passphrase")
        }

        #WLAN Name
        $this.JSON.name = $WLAN.Name

        $this.JSON.description = $WLAN.Description

        #SSID Name
        $HolderVar = $WLAN.SSID              
        if($HolderVar.Length -ne 0)
        {
            $this.JSON.wlan.ssid = $HolderVar
        }
        else
        {
            $this.JSON.wlan.ssid = "UnnamedSSID$Count"
        }

        #L2ACL
        if($WLAN.L2MAC -inotmatch "No ACLS" -and $WLAN.L2MAC -gt 0)
        {
            $L2Policy = ($this.L2ACLs | Where-Object -Property name -eq $WLAN.L2MAC).id
            $this.JSON.wlan.advancedCustomization.l2AclEnable = $true
            $this.JSON.wlan.advancedCustomization.l2AclPolicyId = $L2Policy
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("l2AclEnable")
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("l2AclPolicyId")
        }

        #L3ACL
        if($WLAN.L3L4IPAddress -inotmatch "No ACLS" -and $WLAN.L3L4IPAddress -gt 0)
        {
            
            $L3Policy = ($this.L3ACLs | Where-Object -Property name -eq $WLAN.L3L4IPAddress).id
            $this.JSON.wlan.advancedCustomization.l3AclEnable = $true
            $this.JSON.wlan.advancedCustomization.l3AclPolicyId = $L3Policy
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("l3AclEnable")
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("l3AclPolicyId")
        }

        #User Uplink Rate Limitng
        $HolderVar = $WLAN.RateLimitingUplink
        if($HolderVar -inotmatch "Disabled" -and $HolderVar.Length -ne 1)
        {
            $HolderVar = ($HolderVar -split "Mbps")[0]
            $HolderVar = [int]$HolderVar
            if($HolderVar -gt 200)
            {
                $HolderVar = 200
            }
            $this.JSON.wlan.advancedCustomization.userUplinkRateLimiting = $HolderVar 
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("userUplinkRateLimiting")
        }
        

        #User Downlink Rate Limitng
        $HolderVar = $WLAN.RateLimitingDownlink
        if($HolderVar -inotmatch "Disabled" -and $HolderVar.Length -ne 1)
        {
            $HolderVar = ($HolderVar -split "Mbps")[0]
            $HolderVar = [int]$HolderVar
            if($HolderVar -gt 200)
            {
                $HolderVar = 200
            }
            $this.JSON.wlan.advancedCustomization.userDownlinkRateLimiting = $HolderVar
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("userDownlinkRateLimiting")
        }

        #WLAN Uplink Rate Limiting
        $HolderVar = $WLAN.PerSSIDRateLimitingUplink
         if($HolderVar -inotmatch "Disabled" -and $HolderVar.Length -ne 1)
        {
            $HolderVar = [int]$HolderVar
            if($HolderVar -gt 200)
            {
                $HolderVar = 200
            }
            $this.JSON.wlan.advancedCustomization.totalUplinkRateLimiting = $HolderVar
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("userUplinkRateLimiting")
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("totalUplinkRateLimiting")
        }

        #WLAN Uplink Rate Limiting
        $HolderVar = $WLAN.PerSSIDRateLimitingDownlink
        if($HolderVar -inotmatch "Disabled" -and $HolderVar.Length -ne 1)
        {
            $HolderVar = [int]$HolderVar
            if($HolderVar -gt 200)
            {
                $HolderVar = 200
            }
            $this.JSON.wlan.advancedCustomization.totalDownlinkRateLimiting = $HolderVar
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("userDownlinkRateLimiting")
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("totalDownlinkRateLimiting")
        }


        #Max Clinets
        $HolderVar = $WLAN.MaxClients
        $HolderVar = [int]$HolderVar
        if($HolderVar -gt 512)
        {
            $HolderVar = 512
        }
        $this.JSON.wlan.advancedCustomization.maxClientsOnWlanPerRadio = $HolderVar


        #Band Balancing
        $HolderVar = $WLAN.BandBalancing
        if($HolderVar -imatch "Disabled" -or $HolderVar.Length -eq 0) 
        {
            $this.JSON.wlan.advancedCustomization.enableBandBalancing = $false
        }

        #Client Isolation Per AP and Client Isolation Across AP
        $IsolatePerAP = $WLAN.IsolationPerAP
        $IsolateAcrossAp = $WLAN.IsolationAcrossAP
        if($IsolatePerAP -inotmatch "Disabled" -or $IsolateAcrossAp -inotmatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.clientIsolation = $true
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("clientIsolationOptions")
        }
        

        #Hide SSID
        $HolderVar = $WLAN.ClosedSystem
        if($HolderVar -inotmatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.hideSsid = $true
        }


        #Force DHCP
        $HolderVar = $WLAN.ForceDHCPState
        if($HolderVar -inotmatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.forceMobileDeviceDhcp = $true
        }

        #Load Balancing
        $HolderVar = $WLAN.LoadBalancing
        if($HolderVar -imatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.clientLoadBalancingEnable = $false
        }

        #Directed MC/BC Threshold
        $HolderVar = $WLAN.DirectedMCBCThreshold
        if($HolderVar -inotmatch "Disabled")
        {
            $HolderVar = [int]$HolderVar
            If($HolderVar -gt 128)
            {
                $HolderVar = 128
            }
            $this.JSON.wlan.advancedCustomization.directedThreshold = $HolderVar
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("directedThreshold")
        }
        
        #802.11k Neightbor Report
        $HolderVar = $WLAN.NeighborReport11K
        if($HolderVar -imatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.enableNeighborReport = $false
        }

        #Fast Roaming
        $HolderVar = $WLAN.FTRoaming
        if($HolderVar -inotmatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.enableFastRoaming = $true
        }

        #rfBandUsage and Venue allAPGroupsRadio
        $Radio24 = $false
        $Radio5 = $false
        $WLANGroupDeployed = @()
        $WLANGroupDeployed += $this.ZDParsedObjects.APs.RadioAN.WLANGroupName
        $WLANGroupDeployed += $this.ZDParsedObjects.APs.RadioBGN.WLANGroupName
        $WLANGroups = $this.ZDParsedObjects.WLANGroups
        $APGroupNames = $this.ZDParsedObjects.APs.GroupName

        foreach($WLANGroup in $WLANGroups)
        {
            $test = $WLANGroup.WLANServices.Name -contains $WLAN.Name
            if($test)
            {
                $test = $WLANGroupDeployed -contains $WLANGroup.Name

                if($test)
                {
                    
                    foreach($APGroup in $this.ZDParsedObjects.APGroups)
                    {
                        
                        $test = $APGroup.Radio11BGN.WLANGroup -eq $WLANGroup.Name
                        if($test)
                        {
                            $test = $APGroupNames -contains $APGroup.Name
                            if($test)
                            {
                                $Radio24 = $true
                            }
                        }

                        
                        $test = $APGroup.Radio11ANAC.WLANGroup -eq $WLANGroup.Name
                        if($test)
                        {
                            $test = $APGroupNames -contains $APGroup.Name
                            if($test)
                            {
                                $Radio5 = $true
                            }
                        }
                    }
                }
            }
        }
        
        if($Radio24 -and $Radio5)
        {
            $this.JSON.wlan.advancedCustomization.radioCustomization.rfBandUsage = "BOTH"
            $this.JSON.venues[0].allapgroupsradio = "Both"
        }
        elseif($Radio24)
        {
            $this.JSON.wlan.advancedCustomization.radioCustomization.rfBandUsage = "2.4GHZ"
            $this.JSON.venues[0].allapgroupsradio = "2.4-GHz"
        }
        elseif($Radio5)
        {
            $this.JSON.wlan.advancedCustomization.radioCustomization.rfBandUsage = "5.0GHZ"
            $this.JSON.venues[0].allapgroupsradio = "5-GHz"
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.radioCustomization.PSObject.Properties.Remove("rfBandUsage")
            $this.JSON.PSObject.Properties.Remove("venues")
        }

        #OFDM 
        $HolderVar = $WLAN.OFDMOnlyState
        if($HolderVar -imatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.radioCustomization.phyTypeConstraint = "NONE"
            $this.JSON.wlan.advancedCustomization.radioCustomization.managementFrameMinimumPhyRate = "2"
        }
        

        #BSS Minrate
        $HolderVar = $WLAN.BSSMinrate
        if($HolderVar -inotmatch "Disabled")
        {
            $HolderVar = $HolderVar -split ("Mbps")
            $HolderVar = $HolderVar[0]
            $HolderVar = $HolderVar.Trim()
            if($HolderVar -eq "1.0" -or $HolderVar -eq "2.0" -or $HolderVar -eq "12.0" -or $HolderVar -eq "24.0")
            {
                $HolderVar = [int]$HolderVar
                $HolderVar = [string]$HolderVar
            }

            $this.JSON.wlan.advancedCustomization.radioCustomization.bssMinimumPhyRate = $HolderVar
            $this.JSON.wlan.advancedCustomization.radioCustomization.managementFrameMinimumPhyRate = $HolderVar
        }
        
        
        
        #Management Tx Rate
        if($WLAN.OFDMOnlyState -imatch "Disabled" -and $WLAN.BSSMinrate -imatch "Disabled")
        {
            $ManRate24 = $WLAN.TxRateManagementFrame24
            $ManRate24 = $ManRate24 -split ("Mbps")
            $ManRate24 = $ManRate24[0]
            $ManRate24 = $ManRate24.Trim()
            $ManRate5 = $WLAN.TxRateManagementFrame5
            $ManRate5 = $ManRate5 -split ("Mbps")
            $ManRate5 = $ManRate5[0]
            $ManRate5 = $ManRate5.Trim()
            if($ManRate24 -gt $ManRate5)
            {
                $HolderVar = $ManRate24
            }
            else
            {
                $HolderVar = $ManRate5
            }

            if($HolderVar -eq "1.0" -or $HolderVar -eq "2.0" -or $HolderVar -eq "6.0" -or $HolderVar -eq "9.0" -or $HolderVar -eq "11.0" -or $HolderVar -eq "12.0" -or $HolderVar -eq "18.0" -or $HolderVar -eq "24.0")
            {
                $HolderVar = [int]$HolderVar
                $HolderVar = [string]$HolderVar
            
            }
            elseif($HolderVar -eq "36.0" -or $HolderVar -eq "48.0" -or $HolderVar -eq "54.0")
            {
                $HolderVar = "24"
            }
            $this.JSON.wlan.advancedCustomization.radioCustomization.managementFrameMinimumPhyRate = $HolderVar
        }   

        #Client Inactivity Timeout
        $HolderVar = $WLAN.InactivityTimeout.Status
        if($HolderVar -inotmatch "Disabled")
        {
           $HolderVar = $WLAN.InactivityTimeout.Timeout
           $HolderVar = ($HolderVar -split "Minutes")[0].Trim()
           $HolderVar = [int]$HolderVar
           $HolderVar = $HolderVar * 60
           if($HolderVar -le 60)
           {
               $HolderVar = 60
           }
           elseif($HolderVar -gt 86400)
           {
               $HolderVar = 86400
           }
    
           $this.JSON.wlan.advancedCustomization.clientInactivityTimeout = $HolderVar
        }
        
        #VLAN Pool
        $HolderVar = $WLAN.VlanPool
        if($HolderVar -inotmatch "No Pools" -and $HolderVar.Length -gt 0)
        {
            $HolderVar = $this.VLANPools | Where-Object -Property Name -EQ $HolderVar
            $this.JSON.wlan.advancedCustomization.vlanPool.name = $HolderVar.name
            $this.JSON.wlan.advancedCustomization.vlanPool.description = $HolderVar.description
            $this.JSON.wlan.advancedCustomization.vlanPool.vlanMembers = $HolderVar.vlanMembers
            $this.JSON.wlan.advancedCustomization.vlanPool.id = $HolderVar.id
        }
        else
        {
            $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("vlanPool")
            $RemovedVLANPool = $true
        }

        #Proxy ARP
        $HolderVar = $WLAN.ProxyARP
        if($HolderVar -inotmatch "Disabled")
        {
           $this.JSON.wlan.advancedCustomization.proxyARP = $true
        }

        #Transient Client Management 
        $HolderVar = $WLAN.TransientClientManagement
        if($HolderVar -inotmatch "Disabled")
        {
            $this.JSON.wlan.advancedCustomization.enableTransientClientManagement = $true
            $this.JSON.wlan.advancedCustomization.enableJoinRSSIThreshold = $true
            $this.JSON.wlan.advancedCustomization.joinWaitTime = [int]$WLAN.TransientClientManagement.JoinWaitTime
            $this.JSON.wlan.advancedCustomization.joinExpireTime = [int]$WLAN.TransientClientManagement.JoinExpireTime
            $this.JSON.wlan.advancedCustomization.joinWaitThreshold = [int]$WLAN.TransientClientManagement.JoinWaitThreshold
            $this.JSON.wlan.advancedCustomization.joinRSSIThreshold = [int]$WLAN.TransientClientManagement.MinimumClientRSSIThreshold
        }
        
        $HolderVar = [int]$WLAN.VLANID
        if($HolderVar -ne 1)
        {
            $this.JSON.wlan.vlanId = $HolderVar
        }

        $Compress = $this.JSON | ConvertTo-Json -Compress
        $Compress = $Compress -replace "`"clientIsolationOptions`":(.*)hideSsid`"", "`"clientIsolationOptions`": $($this.JSON.wlan.advancedCustomization.clientIsolationOptions |ConvertTo-Json -Compress),`"hideSsid`""
        $Compress = $Compress -replace "`"radioCustomization`":(.*)clientInactivityTimeout`"", "`"radioCustomization`": $($this.JSON.wlan.advancedCustomization.radioCustomization |ConvertTo-Json -Compress),`"clientInactivityTimeout`""
        
        if($RemovedVLANPool -eq $false)
        {
            $Compress = $Compress -replace "`"vlanPool`":(.*)proxyARP`"", "`"vlanPool`": $($this.JSON.wlan.advancedCustomization.vlanPool |ConvertTo-Json -Compress),`"proxyARP`""
            $this.JSON = $Compress
        }
        else
        {
            $this.JSON = $Compress
        }

           
    }
    
    [boolean]setWLAN()
    {
        $WLANs = $this.ZDParsedObjects.WLANs
       
       try
       {
            if($WLANs.Count -gt 0)
            {
                for($count = 0; $count -lt $WLANs.Count; $count++)
                {
                    $command = "`$WLANs[$count]"
                    $WLANTest = $false
                    $WLAN = Invoke-Expression $command
                    Write-Host "`t`t $($WLAN.Name)"

                    if($WLAN.Type -imatch "Standard Usage" -and $WLAN.Authentication -imatch "open" -and $WLAN.DynamicPSK -imatch "Disabled" -and ($WLAN.Encryption -imatch "wpa" -or $WLAN.Encryption -imatch "wep"))
                    {
                        $PSKJSON = Get-Content .\CloudJSON\21_01_11\Base.json
                        $this.JSON = $PSKJSON | ConvertFrom-Json
                        $this.JSON.type = "psk"
                        $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                        $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("enableAaaVlanOverride")
                        $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                        $WLANTest = $true
                    }
                    elseif($WLAN.Type -imatch "Standard Usage" -and $WLAN.Authentication -imatch "open" -and $WLAN.Encryption -imatch "none")
                    {
                        $OpenJSON = Get-Content .\CloudJSON\21_01_11\Base.json
                        $this.JSON = $OpenJSON | ConvertFrom-Json

                        $this.JSON.type = "open"
                        $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                        
                        $this.JSON.wlan.advancedCustomization.PSObject.Properties.Remove("enableAaaVlanOverride")
                        $this.JSON.wlan.PSObject.Properties.Remove("macAddressAuthentication")
                        $this.JSON.wlan.PSObject.Properties.Remove("macAuthMacFormat")
                        
                        $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                        $WLANTest = $true
                    }
                    elseif($WLAN.Type -imatch "Standard Usage" -and $WLAN.Authentication -imatch "open" -and ($WLAN.DynamicPSK -imatch "Enabled" -or $WLAN.DynamicPSK -imatch "External"))
                    {
                        if($WLAN.DynamicPSK -imatch "Enabled")
                        {
                            $DPSKJSON = Get-Content .\CloudJSON\21_01_11\BaseDPSK.json
                            $DPSKJSON = $DPSKJSON | ConvertFrom-Json
                            $DPSKJSONFull = Get-Content .\CloudJSON\21_01_11\Base.json
                            $this.JSON = $DPSKJSONFull | ConvertFrom-Json
                            $this.JSON.type = "dpsk"
                            $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                            $this.JSON.wlan.advancedCustomization.enableAaaVlanOverride = $true
                            $this.JSON.wlan.PSObject.Properties.Remove("macAddressAuthentication")
                            $this.JSON.wlan.PSObject.Properties.Remove("macAuthMacFormat")
                            $DPSKJSON.dpskPassphraseGeneration.length = $WLAN.DynamicPSKPassphraseLength
                            if($WLAN.DynamicPSKType -imatch "secure")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.format = "MOST_SECURED"
                            }
                            elseif($WLAN.DynamicPSKType -imatch "friendly")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.format = "KEYBOARD_FRIENDLY"
                            }
                            
                            if($WLAN.DynamicPSKExpireTime -imatch "unlimited")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "UNLIMITED"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "one-day")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "ONE_DAY"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "one-week")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "ONE_WEEK"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "one-months")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "ONE_MONTH"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "half-a-year" -or $WLAN.DynamicPSKExpireTime -imatch "two-months" -or $WLAN.DynamicPSKExpireTime -imatch "three-months") #Need this two-months first becasue of the match of two-month for weeks (below)
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "SIX_MONTHS"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "two-month")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "TWO_WEEKS"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "one-year")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "ONE_YEAR"
                            }
                            elseif($WLAN.DynamicPSKExpireTime -imatch "two-years")
                            {
                                $DPSKJSON.dpskPassphraseGeneration.expiration = "TWO_YEARS"
                            }
                            $this.JSON | Add-Member -MemberType NoteProperty -Name "dpskPassphraseGeneration" -Value $DPSKJSON.dpskPassphraseGeneration

                            $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                            $WLANTest = $true
                        }
                        elseif($WLAN.DynamicPSK -imatch "External")
                        {
                            $CloudpathServer = $this.CloudpathServers | Where-Object -Property Name -EQ $WLAN.ExternalDynamicPSKAuthenticationServer
                            
                            if($CloudpathServer.deploymentType -imatch "Cloud")
                            {
                                $DPSKJSON = Get-Content .\CloudJSON\21_01_11\BaseDPSK.json
                                $DPSKJSON = $DPSKJSON | ConvertFrom-Json
                                $DPSKJSONFull = Get-Content .\CloudJSON\21_01_11\Base.json
                                $this.JSON = $DPSKJSONFull | ConvertFrom-Json
                                $this.JSON.type = "dpsk"
                                $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                                $this.JSON.wlan.advancedCustomization.enableAaaVlanOverride = $true
                                $this.JSON.wlan.PSObject.Properties.Remove("macAddressAuthentication")
                                $this.JSON.wlan.PSObject.Properties.Remove("macAuthMacFormat")
                                $this.JSON | Add-Member -MemberType NoteProperty -Name "cloudpathServerId" -Value $CloudpathServer.id
                                $this.JSON | Add-Member -MemberType NoteProperty -Name "dpskPassphraseGeneration" -Value $DPSKJSON.dpskPassphraseGeneration

                                $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                                $WLANTest = $true
                            }
                            elseif($CloudpathServer.deploymentType -imatch "OnPremise" -or $CloudpathServer -eq $null) #need null check because other radius servers arent supported either
                            {
                                Write-Host "`t`t Cannot make WLAN $($WLAN.Name) becasue Cloud Controller currently ONLY uses Cloudpath cloud hosted servers for external DPSK"
                            }
                        }
                    }
                    elseif($WLAN.Type -imatch "Standard Usage" -and $WLAN.Authentication -imatch "802.1x-eap")
                    {
                        $RadiusJSON = Get-Content .\CloudJSON\21_01_11\BaseRADIUS.json
                        $RadiusJSON = $RadiusJSON | ConvertFrom-Json
                        $AAAJSON = Get-Content .\CloudJSON\21_01_11\Base.json
                        $this.JSON = $AAAJSON | ConvertFrom-Json
                        $this.JSON.type = "aaa"
                        $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                        $this.JSON.wlan.advancedCustomization.enableAaaVlanOverride = $true
                        $this.JSON.wlan.PSObject.Properties.Remove("macAddressAuthentication")
                        $this.JSON.wlan.PSObject.Properties.Remove("macAuthMacFormat")

                        $AAAServer = $this.ZDParsedObjects.AAAs | Where-Object -Property Name -EQ $WLAN.AuthenticationServer
                        
                        if($AAAServer.Type -imatch "RADIUS server")
                        {
                            if($AAAServer.PrimaryRADIUS.RadiusType -imatch "Cloud" -or $AAAServer.SecondaryRADIUS.RadiusType -imatch "Cloud" -or $AAAServer.PrimaryRADIUS.RadiusType -imatch "Onprem" -or $AAAServer.SecondaryRADIUS.RadiusType -imatch "Onprem")
                            {
                                $CloudpathServer = $this.CloudpathServers | Where-Object -Property Name -EQ $WLAN.AuthenticationServer
                                $this.JSON | Add-Member -MemberType NoteProperty -Name "cloudpathServerId" -Value $CloudpathServer.id
                            }
                            elseif($AAAServer.PrimaryRADIUS.RadiusType -imatch "Other" -or $AAAServer.SecondaryRADIUS.RadiusType -imatch "Other")
                            {
                                if($AAAServer.SecondaryRADIUS.Status -imatch "Enabled")
                                {
                                    $RadiusJSON.primary.ip = $AAAServer.PrimaryRADIUS.IPAddress
                                    $RadiusJSON.primary.port = $AAAServer.PrimaryRADIUS.Port
                                    $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.PrimaryRADIUS.Secret,"Something")
                                    $RadiusJSON.primary.sharedSecret = $HolderVar.Password
                                    $HolderVar = ""
                                    
                                    $RadiusJSON.secondary.ip = $AAAServer.SecondaryRADIUS.IPAddress
                                    $RadiusJSON.secondary.port = $AAAServer.SecondaryRADIUS.Port
                                    $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.SecondaryRADIUS.Secret,"Something")
                                    $RadiusJSON.secondary.sharedSecret = $HolderVar.Password
                                    $HolderVar = ""
                                    
                                    if($AAAServer.encryptionTLS -inotmatch "Disabled" -and $AAAServer.encryptionTLS.Length -gt 0)
                                    {
                                        $RadiusJSON.tlsEnabled = $true
                                    }

                                    $this.JSON | Add-Member -MemberType NoteProperty -Name "authRadius" -Value $RadiusJSON

                                }
                                else
                                {
                                    $RadiusJSON.PSObject.Properties.Remove("secondary")
                                    $RadiusJSON.primary.ip = $AAAServer.PrimaryRADIUS.IPAddress
                                    $RadiusJSON.primary.port = $AAAServer.PrimaryRADIUS.Port
                                    $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.PrimaryRADIUS.Secret,"Something")
                                    $RadiusJSON.primary.sharedSecret = $HolderVar.Password
                                    $HolderVar = ""
                                    if($AAAServer.encryptionTLS -inotmatch "Disabled" -and $AAAServer.encryptionTLS.Length -gt 0)
                                    {
                                        $RadiusJSON.tlsEnabled = $true
                                    }

                                    $this.JSON | Add-Member -MemberType NoteProperty -Name "authRadius" -Value $RadiusJSON
                                }
                            }
                        }

                        $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                        $WLANTest = $true
                        
                    }
                    elseif($WLAN.Type -imatch "Standard Usage" -and $WLAN.Authentication -imatch "mac-auth" -and $WLAN.DynamicPSK -imatch "Disabled")
                    {
                        $RadiusJSON = Get-Content .\CloudJSON\21_01_11\BaseRADIUS.json
                        $RadiusJSON = $RadiusJSON | ConvertFrom-Json
                        $MACJSON = Get-Content .\CloudJSON\21_01_11\Base.json
                        $this.JSON = $MACJSON | ConvertFrom-Json
                        $this.JSON.type = "psk"
                        $this.JSON.venues[0].venueId = $this.MigrationVenue.id
                        $this.JSON.wlan.advancedCustomization.enableAaaVlanOverride = $true
                        $this.JSON.wlan.macAddressAuthentication = $true
                        if($WLAN.MACAddressFormat -eq "aabbccddeeff")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "Lower"
                        }
                        elseif($WLAN.MACAddressFormat -eq "aa-bb-cc-dd-ee-ff")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "LowerDash"
                        }
                        elseif($WLAN.MACAddressFormat -eq "aa:bb:cc:dd:ee:ff")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "LowerColon"
                        }
                        elseif($WLAN.MACAddressFormat -eq "AABBCCDDEEFF")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "Upper"
                        }
                        elseif($WLAN.MACAddressFormat -eq "AA-BB-CC-DD-EE-FF")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "UpperDash"
                        }
                        elseif($WLAN.MACAddressFormat -eq "AA:BB:CC:DD:EE:FF")
                        {
                            $this.JSON.wlan.macAuthMacFormat = "UpperColon"
                        }
                        
                        $AAAServer = $this.ZDParsedObjects.AAAs | Where-Object -Property Name -EQ $WLAN.AuthenticationServer
                        if($AAAServer.SecondaryRADIUS.Status -imatch "Enabled")
                        {
                            $RadiusJSON.primary.ip = $AAAServer.PrimaryRADIUS.IPAddress
                            $RadiusJSON.primary.port = $AAAServer.PrimaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.PrimaryRADIUS.Secret,"Something")
                            $RadiusJSON.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            
                            $RadiusJSON.secondary.ip = $AAAServer.SecondaryRADIUS.IPAddress
                            $RadiusJSON.secondary.port = $AAAServer.SecondaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.SecondaryRADIUS.Secret,"Something")
                            $RadiusJSON.secondary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            
                            if($AAAServer.encryptionTLS -inotmatch "Disabled" -and $AAAServer.encryptionTLS.Length -gt 0)
                            {
                                $RadiusJSON.tlsEnabled = $true
                            }

                            $this.JSON | Add-Member -MemberType NoteProperty -Name "authRadius" -Value $RadiusJSON
                        }
                        else
                        {
                            $RadiusJSON.PSObject.Properties.Remove("secondary")
                            $RadiusJSON.primary.ip = $AAAServer.PrimaryRADIUS.IPAddress
                            $RadiusJSON.primary.port = $AAAServer.PrimaryRADIUS.Port
                            $HolderVar = New-Object System.Net.NetworkCredential("Something", $AAAServer.PrimaryRADIUS.Secret,"Something")
                            $RadiusJSON.primary.sharedSecret = $HolderVar.Password
                            $HolderVar = ""
                            if($AAAServer.encryptionTLS -inotmatch "Disabled" -and $AAAServer.encryptionTLS.Length -gt 0)
                            {
                                $RadiusJSON.tlsEnabled = $true
                            }

                            $this.JSON | Add-Member -MemberType NoteProperty -Name "authRadius" -Value $RadiusJSON
                        }
                        
                        $this.setWLANGeneralAdvancedSettings($WLAN,$count)
                        $WLANTest = $true
                    }
                    
                    if($WLANTest)
                    {
                        $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/network/deep"
                        $Headers = @{
                            "Accept" = "application/json"
                            "Content-Type" = "application/json"
                            "Authorization" = "$($this.AuthToken.'API-KEY')"
                        }
                        $Body = $this.JSON
                        $Response = Invoke-RestMethod -Method Post -Headers $Headers -Uri $URL -Body $Body -ErrorAction Stop
                        $this.CloudWLANs += $Response.response
                        Start-Sleep 10
                    }
                }
            }

            return $true

       }
       catch
       {
            Write-Host "ERROR: setWLAN"
            Write-Host $_
            return $false
       }
    }
    
    [boolean]setDPSKs()
    {
        try
        {
            $DPSKWLANs = $this.ZDParsedObjects.WLANs | Where-Object -Property DynamicPSK -EQ "Enabled"
            $DPSKCSV = Import-Csv .\DPSKs\*

            foreach($DPSK in $DPSKCSV)
            {
                Write-Host "`t`t $($DPSK.'User Name')"
                $DPSKJSON = Get-Content .\CloudJSON\21_01_11\BaseDPSKPasswords.json
                $DPSKJSON = $DPSKJSON | ConvertFrom-Json
                $WLAN = $DPSKWLANs | Where-Object -Property Name -EQ $DPSK.WLAN 

                if($WLAN.LimitDynamicPSK -inotmatch "Disabled")
                {
                    $DPSKJSON.numberOfPassphrases = [int]$WLAN.LimitDynamicPSKNumber
                }
                
                if($WLAN.SharedDynamicPSK -inotmatch "Disabled")
                {
                    $DeviceCount = [int]$WLAN.SharedDynamicPSKNumber
                    if($DeviceCount -gt 50)
                    {
                        $DPSKJSON.numberOfDevicesType = "UNLIMITED"
                        $DPSKJSON.PSObject.Properties.Remove("numberOfDevices")
                    }
                    else
                    {
                        $DPSKJSON.numberOfDevicesType = "LIMITED"
                        $DPSKJSON.numberOfDevices = $DeviceCount
                    }
                    
                }

                if($DPSK.'Mac Address' -ne "00:00:00:00:00:00")
                {
                    $DPSKJSON.mac = $DPSK.'Mac Address'
                }
                else
                {
                        $DPSKJSON.PSObject.Properties.Remove("mac")
                }

                if([int]$DPSK.'Configured Vlan ID' -ne 0)
                {
                    $DPSKJSON.vlanId = [int]$DPSK.'Configured Vlan ID'
                }
                
                $DPSKJSON.username = $DPSK.'User Name'
                $DPSKJSON.passphrase = $DPSK.Passphrase
                $DPSKJSON.networkId = ($this.CloudWLANs | Where-Object -Property name -EQ $DPSK.WLAN).id
                
                $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/dpsk-passphrase"
                $Headers = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "Authorization" = "$($this.AuthToken.'API-KEY')"
            }
                $Body = $DPSKJSON | ConvertTo-Json
                $Response = Invoke-RestMethod -Method Post -Headers $Headers -Uri $URL -Body $Body -ErrorAction Stop | Out-Null
                $this.DPSKs += $Response.response
                Start-Sleep 5
            }

            return $true
        }
        catch
        {
            $ErrorVar = $_

            if($ErrorVar.FullyQualifiedErrorId -imatch "ImportCsvCommand")
            {
                return $true
            }
            else
            {
                Write-Host "ERROR: setWLAN"
                Write-Host $_
                return $false
            }
        }
    }

    migrateAPs()
    {
        Write-Host "Adding APs"
        $Creds = $this.ZDCreds

        for($Count = 0; $Count -lt $this.ZDParsedObjects.APs.Count; $Count++)
        {
            $APFailUpload = $true

            while($APFailUpload)
            {    
                try
                {
                    $APJSON = Get-Content .\CloudJSON\21_01_11\BaseAP.json
                    $APJSON = $APJSON | ConvertFrom-Json
                    $AP = $this.ZDParsedObjects.APs[$Count]
                    $IP = $AP.NetworkSetting.IPAddress
                    $MAC = $AP.MACAddress
                    Write-Host "`t $($AP.DeviceName) ($IP)"

                    if(Test-Connection -ComputerName $IP -Quiet)
                    {
                        $APInfo = ""
                        $Serial = ""
                        $sessionAP = New-SSHSession -ComputerName $IP -Credential $Creds -AcceptKey -Force -ErrorAction Stop 
                        $streamAP = $sessionAP.Session.CreateShellStream("test",4294967295,4294967295,4294967295,4294967295,2147483647)
                        Invoke-SSHStreamShellCommand -ShellStream $streamAP -Command  "`n" | Out-Null
                        Invoke-SSHStreamShellCommand -ShellStream $streamAP -Command  "$($Creds.UserName)" | Out-Null
                        Invoke-SSHStreamShellCommand -ShellStream $streamAP -Command  "$($Creds.GetNetworkCredential().Password)" | Out-Null
                        Start-Sleep 1
                        $Count2=0
                        While($Serial.Length -eq 0)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $streamAP -Command "get boarddata" -OutVariable APInfo | Out-Null
                            foreach($Line in $APInfo)
                            {
                                if($Line -imatch "^Serial")
                                {
                                   $Serial = ($Line -split "(.*):")[2].Trim()
                                   break
                                }
                            }
                        
                            if($Serial.Length -gt 0)
                            {
                                
                            }
                            elseif($Serial.Length -eq 0 -and $Count2 -lt 6)
                            {
                                $Count2++
                                Start-Sleep 3
                            }
                            else
                            {
                                throw "Cannot Get Serial Number: $($AP.DeviceName) ($($AP.NetworkSetting.IPAddress))"
                            }
                            
                            
                        }
                        
                        $APJSON.serialNumber = $Serial
                        $HolderVar = $this.ZDParsedObjects.APs | Where-Object -Property DeviceName -EQ $AP.DeviceName
                        if($HolderVar.Count -gt 1)
                        {
                            $HolderVar = "$($AP.DeviceName)$Count"
                            $APJSON.name = $HolderVar
                        }
                        else
                        {
                            $APJSON.name = $AP.DeviceName
                        }
                        $APJSON.description = $AP.Description
                        $APJSON.venueId = $this.MigrationVenue.id
                        
                        $URL = "$($this.URLString)/api/tenant/$($this.AuthToken.tenantId)/wifi/ap"
                        $Headers = @{
                            "Accept" = "application/json"
                            "Content-Type" = "application/json"
                            "Authorization" = "$($this.AuthToken.'API-KEY')"
                        }
                        $Body = $APJSON | ConvertTo-Json -Compress
                        $Body = $Body -replace "(.*)", "[$Body]"
                        Invoke-RestMethod -Method Post -Headers $Headers -Uri $URL -Body $Body -ErrorAction stop | Out-Null
                        Start-Sleep 7
                        Remove-SSHSession -SessionId $sessionAP.SessionId
                        $APFailUpload = $false
                    }
                    else
                    {
                        Write-Host "`t Cannont PING AP"
                        $APFailUpload = $false
                    }
                }
                catch
                {
                   $ErrorVar = $_

                   if( $ErrorVar.FullyQualifiedErrorId -imatch "InvokeRestMethodCommand")
                   {
                        $APFailUpload = $true
                   }
                   elseif($ErrorVar.FullyQualifiedErrorId -imatch "SSH.NewSshSession")
                   {
                       Write-Host "`t Cannont Establish Connection"
                       $APFailUpload = $false
                   }
                   else
                   {
                       write-host $ErrorVar.FullyQualifiedErrorId
                       write-host $_
                       $APFailUpload = $false
                   }
                }
            }
        }
    }

    CloudUpload_21_01_11([PSCustomObject]$ZDP,[PSCustomObject]$AU, [PSCustomObject]$ZDCreds,[String]$ZDIP,[String]$URLString )
    {
        Write-Host "Adidng ZoneDirector Configuraitons to Cloud Contoller"
        $this.ZDParsedObjects = $ZDP
        $this.AuthToken = $AU
        $this.ZDCreds = $ZDCreds
        $this.ZDIP = $ZDIP
        $this.URLString = $URLString

        Write-Host "`t Migration Venue"
        $ErrorVar = $this.setVenue()
        if($ErrorVar)
        {
            Write-Host "`t Cloudpath Servers"
            $ErrorVar = $this.setCloudpathServers()
            if($ErrorVar)
            {
                Write-Host "`t VLANPools"
                $ErrorVar = $this.setVLANPools()
                if($ErrorVar)
                {
                    Write-Host "`t ACLs"
                    $ErrorVar = $this.setACLs()
                    if($ErrorVar)
                    {
                        Write-Host "`t WLANs"
                        $ErrorVar = $this.setWLAN()
                        if($ErrorVar)
                        {
                            if($this.CloudWLANs.type -contains "dpsk")
                            {
                                $ErrorVar = $this.setDPSKs()
                                if($ErrorVar)
                                {
                                    $this.migrateAPs()
                                }
                                else
                                {
                                    $this.deleteAll()
                                }
                            }
                            else
                            {
                                $this.migrateAPs()
                            }
                        }
                        else
                        {
                            $this.deleteAll()
                        }
                    }
                    else
                    {
                        $this.deleteAll()
                    }
                }
                else
                {
                    $this.deleteAll()
                }
            }
            else
            {
                $this.deleteAll()
            }
            
        }
        else
        {
            $this.deleteAll()
        }
        
        Write-Host "Completed"
        Read-Host
    }
}

class CloudController
{
    [PSCustomObject]$AuthToken
    [String]$URLString
    
    [String]getAPIToken([PSCredential]$Credentials)
    {
        Write-Host "`r`r"
        $this.URLString = $null
        $a = $null
        while($a -ne 1 -and $a -ne 2 -and $a -ne 3)
        {
            Write-Host "1: Americas"
            Write-Host "2: Europe"
            Write-Host "3: Asia"
            $a = Read-Host -Prompt "Select the region your Cloud Controller is in"
        }
        
        if($a -eq 1)
        {
            $this.URLString = "https://ruckus.cloud"
        }
        elseif($a -eq 2)
        {
            $this.URLString = "https://eu.ruckus.cloud"
        }
        elseif($a -eq 3)
        {
            $this.URLString = "https://asiaruckus.cloud"
        }

        try
        {
            $HTTP = [System.Net.WebRequest]::Create($this.URLString)   
            $HTTPResponse = $HTTP.GetResponse()
            $HTTPStatus = [int]$HTTPResponse.StatusCode
            if($HTTPStatus -ne 200)
            {
                throw "CannotReachCloudController"
            }
            $HTTPResponse.Close()
            
            $URL = "$($this.URLString)/token"
            $Headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"
            }
            $Body = @{
            username = $Credentials.UserName
            password = $Credentials.GetNetworkCredential().Password
            }
            $Body = $Body | ConvertTo-Json
            $this.AuthToken = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -Body $Body -ErrorAction Stop

            return "Success"
        }
        catch
        {
            $ErrorVar = $_

            if( $ErrorVar.FullyQualifiedErrorId -imatch "WebCmdletWebResponseException")
            {
                return "CloudCredentialsWrong"
            }
            else
            {
                return $_.FullyQualifiedErrorId
            }
        }
        
    }
    
    setConfiguraiton_21_01_11($ZDParsedObjects,$ZDCreds,$ZDIP)
    {
        [CloudUpload_21_01_11]$CU = [CloudUpload_21_01_11]::new($ZDParsedObjects,$this.AuthToken,$ZDCreds,$ZDIP,$this.URLString)
    }

}

class ZoneDirectorParse_10_4_1_0_257
{
    [PSCustomObject]$ZDParsedObjects

    [PSCustomObject]getACLs()
    {
        Write-Host "`t ACLs"
        $L2ACLConfig = Get-Content .\ZoneDirectorConfigs\L2ACLs.txt
        $L3ACLConfig = Get-Content .\ZoneDirectorConfigs\L3ACLs.txt
        $startpoint = $false
        $ACLs = New-Object -TypeName PSObject
        $L2ACLs = @()
        $L3ACLs = @()

        $startpoint = $false
        $StartionsStart = $false
        $ACLCount = 0
        foreach($L2Line in $L2ACLConfig)
        {
            if($L2Line -imatch "Stations:")
            {
                $StartionsStart = $true
            }
            
            if(($L2line -imatch "^\d:" -or $L2line -imatch "^\d\d:") -and $StartionsStart -eq $false -and $startpoint -eq $false)
            {
                $ACLCount++
                $startpoint = $true
                New-Variable -Name "ACLL2$($ACLCount)"
                $command = "`$ACLL2$($ACLCount) = New-Object -TypeName PSObject"
                Invoke-Expression $command
            }

            if($StartionsStart)
            {
                if($L2Line.length -ne 0)
                {
                    if($L2Line -imatch "Stations:")
                    {
                        $L2Stations = @()
                    }
                    else
                    {
                       $Station = $L2Line -split "MAC Address(.*)=(.*)"
                       $Station = ($Station[2]).Trim()
                       $L2Stations += $Station
                    }
                }
                else
                {
                    $StartionsStart = $false
                    $startpoint = $false
                    $command = "`$ACLL2$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Stations`" -Value `$L2Stations"
                    Invoke-Expression $command
                    $command = "`$L2ACLs += `$ACLL2$($ACLCount)"
                    Invoke-Expression $command
                }
            }
            else
            {
                if($L2line -inotmatch "(.*)^\d:" -or $L2line -inotmatch "(.*)^\d\d:")
                {
                    if($L2line -imatch "Name(.*)=(.*)")
                    {
                        $name = $L2Line -split "Name(.*)=(.*)"
                        $name = ($name[2]).Trim()
                        $command = "`$ACLL2$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `$name"
                        Invoke-Expression $command
                    }
                    elseif($L2line -imatch "Description(.*)=(.*)")
                    {
                        $Description = $L2Line -split "Description(.*)=(.*)"
                        $Description = ($Description[2]).Trim()
                        $command = "`$ACLL2$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `$Description"
                        Invoke-Expression $command
                    }
                    elseif($L2line -imatch "Restriction(.*)=(.*)")
                    {
                        $Restriction = $L2Line -split "Restriction(.*)=(.*)"
                        $Restriction = ($Restriction[2]).Trim()
                        $command = "`$ACLL2$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Restriction`" -Value `$Restriction"
                        Invoke-Expression $command
                    }
                }
            }
        }


        $startpoint = $false
        $RulesStart = $false
        $RuleCount = 0
        $ACLCount = 0
        foreach($L3Line in $L3ACLConfig)
        {
            if($L3Line -imatch "Rules:")
            {
                $RulesStart = $true
            }

            if(($L3line -imatch "^\d:" -or $L3line -imatch "^\d\d:") -and $RulesStart -eq $false -and $startpoint -eq $false)
            {
                $ACLCount++
                $startpoint = $true
                New-Variable -Name "ACLL3$($ACLCount)"
                $command = "`$ACLL3$($ACLCount) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$ACLL3$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                Invoke-Expression $command
                $command = "`$ACLL3$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$ACLL3$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"DefaultAction`" -Value `"`""
                Invoke-Expression $command
                $command = "`$ACLL3$($ACLCount) | Add-Member -MemberType NoteProperty -Name `"Rules`" -Value `"`""
                Invoke-Expression $command
            }

            if($RulesStart)
            {
                if($L3Line.length -ne 0)
                {
                    if($L3Line -imatch "Rules:")
                    {
                        
                    }
                    elseif($L3line -imatch "^\d:" -or $L3line -imatch "^\d\d:")
                    {
                        $RuleCount++
                        New-Variable -Name "Rule$($RuleCount)"
                        $command = "`$Rule$($RuleCount) = New-Object -TypeName PSObject"
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"Type`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"SourceAddress`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"DestinationAddress`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"SourcePort`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"DestinationPort`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$Rule$($RuleCount) | Add-Member -MemberType NoteProperty -Name `"Protocol`" -Value `"`""
                        Invoke-Expression $command
                    }
                    else
                    {
                        switch -Regex($L3line)
                        {
                            "Description(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Description(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).Description = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Type(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Type(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).Type = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Source Address(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Source Address(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).SourceAddress = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Destination Address(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Destination Address(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).DestinationAddress = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Source Port(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Source Port(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).SourcePort = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Destination Port(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Destination Port(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).DestinationPort = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                            "Protocol(.*)=(.*)"
                            {
                                $HolderVar = $L3Line -split "Protocol(.*)=(.*)"
                                $HolderVar = ($HolderVar[2]).Trim()
                                $command = "`$Rule$($RuleCount).Protocol = `$HolderVar"
                                Invoke-Expression $command
                                break
                            }
                        }
                    }
                }
                else
                {
                    $L3Rules = @()
                    for($count = 1;$count -le $RuleCount;$count++)
                    {
                        $command = "`$L3Rules += `$Rule$($count)"
                        Invoke-Expression $command
                        $command = "Remove-Variable -Name `Rule$($count)"
                        Invoke-Expression $command
                    }

                    $command = "`$ACLL3$($ACLCount).Rules = `$L3Rules"
                    Invoke-Expression $command
                    $command = "`$L3ACLs += `$ACLL3$($ACLCount)"
                    Invoke-Expression $command
                    $RuleCount = 0
                    $RulesStart = $false
                    $startpoint = $false
                }
            }
            else
            {
                if($L3line -inotmatch "^\d:" -or $L3line -inotmatch "^\d\d:")
                {
                    if($L3line -imatch "Name(.*)=(.*)")
                    {
                        $Name = $L3Line -split "Name(.*)=(.*)"
                        $Name = ($Name[2]).Trim()
                        $command = "`$ACLL3$($ACLCount).Name = `$name"
                        Invoke-Expression $command
                    }
                    elseif($L3line -imatch "Description(.*)=(.*)")
                    {
                        $Description = $L3Line -split "Description(.*)=(.*)"
                        $Description = ($Description[2]).Trim()
                        $command = "`$ACLL3$($ACLCount).Description = `$Description"
                        Invoke-Expression $command
                    }
                    elseif($L3line -imatch "Default Action if no rule is matched(.*)=(.*)")
                    {
                        $DefaultAction = $L3Line -split "Default Action if no rule is matched(.*)=(.*)"
                        $DefaultAction = ($DefaultAction[2]).Trim()
                        $command = "`$ACLL3$($ACLCount).DefaultAction = `$DefaultAction"
                        Invoke-Expression $command
                    }
                }
            }
        }

        $ACLs | Add-Member -MemberType NoteProperty -Name "L2" -Value $L2ACLs
        $ACLs | Add-Member -MemberType NoteProperty -Name "L3" -Value $L3ACLs

        return $ACLs

    }

    [Array]getWLANs()
    {
        Write-Host "`t WLANs"
        $WLANConfig = Get-Content .\ZoneDirectorConfigs\WLANs.txt
        $WLANs = @()
        
        $startpoint = $false
        $startInactivityTimeout = $false
        $startDHCPOption = $false
        $startTransientClientManagement = $false
        $TransientClientManagementObject = New-Object -TypeName PSObject
        $DHCPOptionObject = New-Object -TypeName PSObject
        $InactivityTimeoutObject = New-Object -TypeName PSObject
        $count = 0

        foreach($Line in $WLANConfig)
        {
            if($Line -match "^\d:" -or $Line -match "^\d\d:")
            {
                if($count -gt 0)
                {
                    $command = "`$WLANs += `$WLAN$($count)"
                    Invoke-Expression $command
                }
                
                $count++
                $startpoint = $true
                $startInactivityTimeout = $false
                $startDHCPOption = $false
                $startTransientClientManagement = $false
                $command = "`$WLAN$($count) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"TxRateManagementFrame24`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"TxRateManagementFrame5`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"BeaconInterval`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SSID`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Type`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Authentication`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Encryption`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Algorithm`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Passphrase`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PSKPassphrase`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SAEPassphrase`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"WEPKey`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"FTRoaming`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"NeighborReport11K`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"WebAuthentication`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"AuthenticationServer`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"AccountingServer`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"MACAddressFormat`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"CalledStationIdType`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"TunnelMode`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DHCPRelay`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"MaxClients`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"IsolationPerAP`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"IsolationAcrossAP`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ZeroITActivation`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"LoadBalancing`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"BandBalancing`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicPSK`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ExternalDynamicPSKAuthenticationServer`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicPSKPassphraseLength`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicPSKType`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicPSKExpireTime`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicPSKValidityPeriod`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"LimitDynamicPSK`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"LimitDynamicPSKNumber`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SharedDynamicPSK`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SharedDynamicPSKNumber`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"RateLimitingUplink`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PerSSIDRateLimitingUplink`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"RateLimitingDownlink`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PerSSIDRateLimitingDownlink`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"AutoProxyConfiguration`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"InactivityTimeout`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"VLANID`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DynamicVLAN`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ClosedSystem`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"HttpsRedirection`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"OFDMOnlyState`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"MulticastFilterState`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DirectedMulticast`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"State11d`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ForceDHCPState`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ForceDHCPTimeout`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DHCPOption82`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"IgnoreUnauthorizedClientStatistic`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"STAInfoExtractionState`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"BSSMinrate`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DTIMPeriod`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DirectedMCBCThreshold`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"CallAdmissionControlState`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PMKCacheTimeout`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PMKCacheReconnect`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"NASIDType`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"RoamingAcctInterimUpdate`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PAPMessageAuthenticator`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SendEAPFailure`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"L2MAC`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"L3L4IPAddress`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"L3L4IPv6Address`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"Precedence`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ProxyARP`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"DevicePolicy`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"VlanPool`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"RoleBasedAccessControlPolicy`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"SmartRoam`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"RoamFactor`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"WhiteList`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"URLFiltering`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ApplicationRecognitionControl`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ClientFlowDataLogging`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"WlanBind`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"ClientConnectionData`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"TransientClientManagement`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLAN$($count) | Add-Member -MemberType NoteProperty -Name `"PMF11w`" -Value `"`""
                Invoke-Expression $command

            }
    
            if($startpoint)
            {
                if($startInactivityTimeout)
                {
                    switch -Regex ($Line)
                    {
                        "^Status(.*)"
                        {
                            $Status = ($Line -split "(.*)=")[2].Trim()
                            $InactivityTimeoutObject.Status = $Status
                            if($Status -eq "Disabled")
                            {
                                $startInactivityTimeout = $false
                                $command = "`$WLAN$($count).InactivityTimeout` = `$InactivityTimeoutObject"
                                Invoke-Expression $command
                            }
                            break
                        }
                        "^Timeout(.*)"
                        {
                            $Timeout = ($Line -split "(.*)=")[2].Trim()
                            $InactivityTimeoutObject.Timeout = $Timeout

                            $startInactivityTimeout = $false
                            break
                        }
                    }

                    $command = "`$WLAN$($count).InactivityTimeout` = `$InactivityTimeoutObject"
                    Invoke-Expression $command
                }
                elseif($startDHCPOption)
                {
                    switch -Regex ($Line)
                    {
                        "^Status"
                        {
                            $Status = ($Line -split "(.*)=")[2].Trim()
                            $DHCPOptionObject.Status = $Status
                            break
                        }
                        "^Option82 sub-Option150"
                        {
                            $Option150 = ($Line -split "(.*)=")[2].Trim()
                            $DHCPOptionObject.Option150 = $Option150
                            break
                        }
                        "^Option82 sub-Option151"
                        {
                            $Option151 = ($Line -split "(.*)=")[2].Trim()
                            $DHCPOptionObject.Option151 = $Option151

                            $startDHCPOption = $false
                            break
                        }
                        "^Option82 sub-Option1"
                        {
                            $Option1 = ($Line -split "(.*)=")[2].Trim()
                            $DHCPOptionObject.Option1 = $Option1
                            break
                        }
                        "^Option82 sub-Option2"
                        {
                            $Option2 = ($Line -split "(.*)=")[2].Trim()
                            $DHCPOptionObject.Option2 = $Option2
                            break
                        }
                    }

                    $command = "`$WLAN$($count).DHCPOption82` = `$DHCPOptionObject"
                    Invoke-Expression $command
                
                }
                elseif($startTransientClientManagement)
                {
                    switch -Regex ($Line)
                    {
                        "^Join Wait Time(.*)(seconds)(.*)"
                        {
                            $JoinWaitTime = ($Line -split "(.*)=")[2].Trim()
                            $TransientClientManagementObject.JoinWaitTime = $JoinWaitTime
                            break
                        }
                        "^Join Expire Time(.*)(seconds)(.*)"
                        {
                            $JoinExpireTime = ($Line -split "(.*)=")[2].Trim()
                            $TransientClientManagementObject.JoinExpireTime = $JoinExpireTime
                            break
                        }
                        "^Join Wait Threshold(.*)(times)(.*)"
                        {
                            $JoinWaitThreshold = ($Line -split "(.*)=")[2].Trim()
                            $TransientClientManagementObject.JoinWaitThreshold = $JoinWaitThreshold
                            break
                        }
                        "^Minimum Client RSSI Threshold(.*)(dBm)(.*)"
                        {
                            $MinimumClientRSSIThreshold = ($Line -split "(.*)=")[2].Trim()
                            $TransientClientManagementObject.MinimumClientRSSIThreshold = $MinimumClientRSSIThreshold

                            $startTransientClientManagement = $false
                            break
                        }
                    }

                    $command = "`$WLAN$($count).TransientClientManagement = `$TransientClientManagementObject"
                    Invoke-Expression $command

                }
                else
                {
                    switch -Regex ($Line)
                    {
                        "^NAME(.*)="
                        {
                            $Name = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Name = `$Name"
                            Invoke-Expression $command
                            break
                        }
                        "^Tx. Rate of Management Frame\(2.4GHz\)(.*)="
                        {
                            $ManRate = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).TxRateManagementFrame24 = `$ManRate"
                            Invoke-Expression $command
                            break   
                        }
                        "^Tx. Rate of Management Frame\(5GHz\)(.*)="
                        {
                            $ManRate = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).TxRateManagementFrame5 = `$ManRate"
                            Invoke-Expression $command
                            break   
                        }
                        "^Beacon Interval(.*)="
                        {
                            $Beacon = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).BeaconInterval = `$Beacon"
                            Invoke-Expression $command
                            break
                        }
                        "^SSID(.*)="
                        {
                            $SSID = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SSID = `$SSID"
                            Invoke-Expression $command
                            break
                        }
                        "^Description(.*)="
                        {
                            $Description = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Description = `$Description"
                            Invoke-Expression $command
                            break
                        }    
                        "^Type(.*)="
                        {
                            $Type = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Type = `$Type"
                            Invoke-Expression $command
                            break
                        }    
                        "^Authentication ="
                        {
                            $Authentication = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Authentication = `$Authentication"
                            Invoke-Expression $command
                            break
                        }   
                        "^Encryption(.*)="
                        {
                            $Encryption = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Encryption = `$Encryption"
                            Invoke-Expression $command
                            break
                        }    
                        "^Algorithm(.*)="
                        {
                            $Algorithm = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Algorithm = `$Algorithm"
                            Invoke-Expression $command
                            break
                        }    
                        "^Passphrase(.*)="
                        {
                            $Passphrase = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Passphrase = `$Passphrase"
                            Invoke-Expression $command
                            break
                        }
                        "^PSK Passphrase(.*)="
                        {
                            $PSKPassphrase = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PSKPassphrase = `$PSKPassphrase"
                            Invoke-Expression $command
                            break
                        }
                        "^SAE Passphrase(.*)="
                        {
                            $SAEPassphrase = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SAEPassphrase = `$SAEPassphrase"
                            Invoke-Expression $command
                            break
                        }
                        "^WEP Key(.*)="
                        {
                            $WEPKey  = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).WEPKey = `$WEPKey"
                            Invoke-Expression $command
                            break
                        }
                        "^FT Roaming(.*)="
                        {
                            $FTRoaming = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).FTRoaming = `$FTRoaming"
                            Invoke-Expression $command
                            break
                        }    
                        "^802.11k Neighbor report(.*)="
                        {
                            $NeighborReport11K = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).NeighborReport11K = `$NeighborReport11K"
                            Invoke-Expression $command
                            break
                        } 
                        "^Web Authentication(.*)="
                        {
                            $WebAuthentication = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).WebAuthentication = `$WebAuthentication"
                            Invoke-Expression $command
                            break
                        } 
                        "^Authentication Server(.*)="
                        {
                            $AuthenticationServer = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).AuthenticationServer = `$AuthenticationServer"
                            Invoke-Expression $command
                            break
                        } 
                        "^Accounting Server(.*)="
                        {
                            $AccountingServer = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).AccountingServer = `$AccountingServer"
                            Invoke-Expression $command
                            break
                        }
                        "^MAC Address format(.*)="
                        {
                            $MACAddressFormat = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).MACAddressFormat = `$MACAddressFormat"
                            Invoke-Expression $command
                            break
                        } 
                        "^Called-Station-Id type(.*)="
                        {
                            $CalledStationIdType = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).CalledStationIdType = `$CalledStationIdType"
                            Invoke-Expression $command
                            break
                        } 
                        "^Tunnel Mode(.*)="
                        {
                            $TunnelMode = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).TunnelMode = `$TunnelMode"
                            Invoke-Expression $command
                            break
                        } 
                        "^DHCP relay(.*)="
                        {
                            $DHCPRelay = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DHCPRelay = `$DHCPRelay"
                            Invoke-Expression $command
                            break
                        } 
                        "^Max. Clients(.*)="
                        {
                            $MaxClients = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).MaxClients = `$MaxClients"
                            Invoke-Expression $command
                            break
                        } 
                        "^Isolation per AP(.*)="
                        {
                            $IsolationPerAP = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).IsolationPerAP = `$IsolationPerAP"
                            Invoke-Expression $command
                            break
                        } 
                        "^Isolation across AP(.*)="
                        {
                            $IsolationAcrossAP = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).IsolationAcrossAP = `$IsolationAcrossAP"
                            Invoke-Expression $command
                            break
                        } 
                        "^Zero-IT Activation(.*)="
                        {
                            $ZeroITActivation = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ZeroITActivation = `$ZeroITActivation"
                            Invoke-Expression $command
                            break
                        } 
                        "^Load Balancing(.*)="
                        {
                            $LoadBalancing = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).LoadBalancing = `$LoadBalancing"
                            Invoke-Expression $command
                            break
                        } 
                        "^Band Balancing(.*)="
                        {
                            $BandBalancing = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).BandBalancing = `$BandBalancing"
                            Invoke-Expression $command
                            break
                        } 
                        "^Dynamic PSK ="
                        {
                            $DynamicPSK = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicPSK = `$DynamicPSK"
                            Invoke-Expression $command
                            break
                        } 
                        "^External Dynamic PSK Authentication Server(.*)="
                        {
                            $ExternalDynamicPSKAuthenticationServer = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ExternalDynamicPSKAuthenticationServer = `$ExternalDynamicPSKAuthenticationServer"
                            Invoke-Expression $command
                            break
                        }
                        "^Dynamic PSK Passphrase Length(.*)="
                        {
                            $DynamicPSKPassphraseLength = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicPSKPassphraseLength = `$DynamicPSKPassphraseLength"
                            Invoke-Expression $command
                            break
                        } 
                        "^Dynamic PSK Type(.*)="
                        {
                            $DynamicPSKType = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicPSKType = `$DynamicPSKType"
                            Invoke-Expression $command
                            break
                        } 
                        "^Dynamic PSK Expire Time(.*)="
                        {
                            $DynamicPSKExpireTime = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicPSKExpireTime = `$DynamicPSKExpireTime"
                            Invoke-Expression $command
                            break
                        } 
                        "^Dynamic PSK Validity Period(.*)="
                        {
                            $DynamicPSKValidityPeriod = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicPSKValidityPeriod = `$DynamicPSKValidityPeriod"
                            Invoke-Expression $command
                            break
                        } 
                        "^Limit Dynamic PSK ="
                        {
                            $LimitDynamicPSK = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).LimitDynamicPSK = `$LimitDynamicPSK"
                            Invoke-Expression $command
                            break
                        } 
                        "^Limit Dynamic PSK Number(.*)="
                        {
                            $LimitDynamicPSKNumber = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).LimitDynamicPSKNumber = `$LimitDynamicPSKNumber"
                            Invoke-Expression $command
                            break
                        } 
                        "^Shared Dynamic PSK ="
                        {
                            $SharedDynamicPSK = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SharedDynamicPSK = `$SharedDynamicPSK"
                            Invoke-Expression $command
                            break
                        } 
                        "^Shared Dynamic PSK Number(.*)="
                        {
                            $SharedDynamicPSKNumber = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SharedDynamicPSKNumber = `$SharedDynamicPSKNumber"
                            Invoke-Expression $command
                            break
                        } 
                        "^Rate Limiting Uplink(.*)="
                        {
                            $RateLimitingUplink = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).RateLimitingUplink = `$RateLimitingUplink"
                            Invoke-Expression $command
                            break
                        } 
                        "^PerSSID Rate Limiting Uplink(.*)="
                        {
                            $PerSSIDRateLimitingUplink = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PerSSIDRateLimitingUplink = `$PerSSIDRateLimitingUplink"
                            Invoke-Expression $command
                            break
                        } 
                        "^Rate Limiting Downlink(.*)="
                        {
                            $RateLimitingDownlink = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).RateLimitingDownlink = `$RateLimitingDownlink"
                            Invoke-Expression $command
                            break
                        } 
                        "^PerSSID Rate Limiting Downlink(.*)="
                        {
                            $PerSSIDRateLimitingDownlink = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PerSSIDRateLimitingDownlink = `$PerSSIDRateLimitingDownlink"
                            Invoke-Expression $command
                            break
                        } 
                        "^Auto-Proxy configuration:"
                        {
                            break
                        } 
                        "^Inactivity Timeout:"
                        {
                            $startInactivityTimeout = $true 
                            $InactivityTimeoutObject = New-Object -TypeName PSObject
                            $InactivityTimeoutObject | Add-Member -MemberType NoteProperty -Name "Status" -Value ""
                            $InactivityTimeoutObject | Add-Member -MemberType NoteProperty -Name "Timeout" -Value ""
                            break
                        } 
                        "^VLAN-ID(.*)="
                        {
                            $VLANID = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).VLANID = `$VLANID"
                            Invoke-Expression $command
                            break
                        } 
                        "^Dynamic VLAN(.*)="
                        {
                            $DynamicVLAN = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DynamicVLAN = `$DynamicVLAN"
                            Invoke-Expression $command
                            break
                        } 
                        "^Closed System(.*)="
                        {
                            $ClosedSystem = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ClosedSystem = `$ClosedSystem"
                            Invoke-Expression $command
                            break
                        } 
                        "^Https Redirection(.*)="
                        {
                            $HttpsRedirection = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).HttpsRedirection = `$HttpsRedirection"
                            Invoke-Expression $command
                            break
                        } 
                        "^OFDM-Only State(.*)="
                        {
                            $OFDMOnlyState = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).OFDMOnlyState = `$OFDMOnlyState"
                            Invoke-Expression $command
                            break
                        } 
                        "^Multicast Filter State(.*)="
                        {
                            $MulticastFilterState = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).MulticastFilterState = `$MulticastFilterState"
                            Invoke-Expression $command
                            break
                        } 
                        "^Directed Multicast(.*)="
                        {
                            $DirectedMulticast = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DirectedMulticast = `$DirectedMulticast"
                            Invoke-Expression $command
                            break
                        } 
                        "^802.11d State(.*)="
                        {
                            $State11d = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).State11d = `$State11d"
                            Invoke-Expression $command
                        } 
                        "^Force DHCP State(.*)="
                        {
                            $ForceDHCPState = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ForceDHCPState = `$ForceDHCPState"
                            Invoke-Expression $command
                            break
                        } 
                        "^Force DHCP Timeout(.*)="
                        {
                            $ForceDHCPTimeout = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ForceDHCPTimeout = `$ForceDHCPTimeout"
                            Invoke-Expression $command
                            break
                        } 
                        "^DHCP Option82:"
                        {
                            $startDHCPOption = $true
                            $DHCPOptionObject = New-Object -TypeName PSObject
                            $DHCPOptionObject | Add-Member -MemberType NoteProperty -Name "Status" -Value ""
                            $DHCPOptionObject | Add-Member -MemberType NoteProperty -Name "Option1" -Value ""
                            $DHCPOptionObject | Add-Member -MemberType NoteProperty -Name "Option2" -Value ""
                            $DHCPOptionObject | Add-Member -MemberType NoteProperty -Name "Option150" -Value ""
                            $DHCPOptionObject | Add-Member -MemberType NoteProperty -Name "Option151" -Value ""
                            break
                        } 
                        "^Ignore unauthorized client statistic(.*)="
                        {
                            $IgnoreUnauthorizedClientStatistic = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).IgnoreUnauthorizedClientStatistic = `$IgnoreUnauthorizedClientStatistic"
                            Invoke-Expression $command
                            break
                        } 
                        "^STA Info Extraction State(.*)="
                        {
                            $STAInfoExtractionState = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).STAInfoExtractionState = `$STAInfoExtractionState"
                            Invoke-Expression $command
                            break
                        } 
                        "^BSS Minrate(.*)="
                        {
                            $BSSMinrate = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).BSSMinrate = `$BSSMinrate"
                            Invoke-Expression $command
                            break
                        } 
                        "^DTIM period(.*)="
                        {
                            $DTIMPeriod = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DTIMPeriod = `$DTIMPeriod"
                            Invoke-Expression $command
                            break
                        } 
                        "^Directed MC/BC Threshold(.*)="
                        {
                            $DirectedMCBCThreshold  = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DirectedMCBCThreshold  = `$DirectedMCBCThreshold "
                            Invoke-Expression $command
                            break
                        } 
                        "^Call Admission Control State(.*)="
                        {
                            $CallAdmissionControlState = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).CallAdmissionControlState = `$CallAdmissionControlState"
                            Invoke-Expression $command
                            break
                        } 
                        "^PMK Cache Timeout(.*)="
                        {
                            $PMKCacheTimeout = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PMKCacheTimeout = `$PMKCacheTimeout"
                            Invoke-Expression $command
                            break
                        } 
                        "^PMK Cache for Reconnect(.*)="
                        {
                            $PMKCacheReconnect = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PMKCacheReconnect = `$PMKCacheReconnect"
                            Invoke-Expression $command
                            break
                        } 
                        "^NAS-ID Type(.*)="
                        {
                            $NASIDType = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).NASIDType = `$NASIDType"
                            Invoke-Expression $command
                            break
                        } 
                        "^Roaming Acct-Interim-Update(.*)="
                        {
                            $RoamingAcctInterimUpdate = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).RoamingAcctInterimUpdate = `$RoamingAcctInterimUpdate"
                            Invoke-Expression $command
                            break
                        } 
                        "^PAP Message Authenticator(.*)="
                        {
                            $PAPMessageAuthenticator = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PAPMessageAuthenticator = `$PAPMessageAuthenticator"
                            Invoke-Expression $command
                            break
                        } 
                        "^Send EAP-Failure(.*)="
                        {
                            $SendEAPFailure = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SendEAPFailure = `$SendEAPFailure"
                            Invoke-Expression $command
                            break
                        } 
                        "^L2/MAC(.*)="
                        {
                            $L2MAC = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).L2MAC = `$L2MAC"
                            Invoke-Expression $command
                            break
                        } 
                        "^L3/L4/IP Address(.*)="
                        {
                            $L3L4IPAddress = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).L3L4IPAddress = `$L3L4IPAddress"
                            Invoke-Expression $command
                            break
                        } 
                        "^L3/L4/IPv6 Address(.*)="
                        {
                            $L3L4IPv6Address = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).L3L4IPv6Address = `$L3L4IPv6Address"
                            Invoke-Expression $command
                            break
                        } 
                        "^Precedence(.*)="
                        {
                            $Precedence = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).Precedence = `$Precedence"
                            Invoke-Expression $command
                            break
                        } 
                        "^Proxy ARP(.*)="
                        {
                            $ProxyARP = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ProxyARP = `$ProxyARP"
                            Invoke-Expression $command
                            break
                        } 
                        "^Device Policy(.*)="
                        {
                            $DevicePolicy = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).DevicePolicy = `$DevicePolicy"
                            Invoke-Expression $command
                            break
                        } 
                        "^Vlan Pool(.*)="
                        {
                            $VlanPool = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).VlanPool = `$VlanPool"
                            Invoke-Expression $command
                            break
                        } 
                        "^Role based Access Control Policy(.*)="
                        {
                            $RoleBasedAccessControlPolicy = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).RoleBasedAccessControlPolicy = `$RoleBasedAccessControlPolicy"
                            Invoke-Expression $command
                            break
                        } 
                        "^SmartRoam(.*)="
                        {
                            $SmartRoam = ($Line -split "\s\s")
                            $Status = ($SmartRoam[0] -split "(.*)=")[2].Trim()
                            $RoamFactor = ($SmartRoam[1] -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).SmartRoam = `$Status"
                            Invoke-Expression $command
                            $command = "`$WLAN$($count).RoamFactor = `$RoamFactor"
                            Invoke-Expression $command
                            break
                        } 
                        "^White List(.*)="
                        {
                            $WhiteList = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).WhiteList = `$WhiteList"
                            Invoke-Expression $command
                            break
                        } 
                        "^URL Filtering(.*)="
                        {
                            $URLFiltering = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).URLFiltering = `$URLFiltering"
                            Invoke-Expression $command
                            break
                        } 
                        "^Application Recognition & Control(.*)="
                        {
                            $ApplicationRecognitionControl = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ApplicationRecognitionControl = `$ApplicationRecognitionControl"
                            Invoke-Expression $command
                            break
                        } 
                        "^Client Flow Data Logging(.*)="
                        {
                            $ClientFlowDataLogging = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ClientFlowDataLogging = `$ClientFlowDataLogging"
                            Invoke-Expression $command
                            break
                        } 
                        "^Wlan Bind(.*)="
                        {
                            $WlanBind = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).WlanBind = `$WlanBind"
                            Invoke-Expression $command
                            break
                        } 
                        "^Client Connection Data(.*)="
                        {
                            $ClientConnectionData = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).ClientConnectionData = `$ClientConnectionData"
                            Invoke-Expression $command
                            break
                        } 
                        "^Transient Client Management(.*)="
                        {
                            $TransientClientManagement = ($Line -split "(.*)=")[2].Trim()
                            if($TransientClientManagement -ine "Disabled")
                            {
                                $startTransientClientManagement = $true
                                $TransientClientManagementObject = New-Object -TypeName PSObject
                                $TransientClientManagementObject | Add-Member -MemberType NoteProperty -Name "JoinWaitTime" -Value ""
                                $TransientClientManagementObject | Add-Member -MemberType NoteProperty -Name "JoinExpireTime" -Value ""
                                $TransientClientManagementObject | Add-Member -MemberType NoteProperty -Name "JoinWaitThreshold" -Value ""
                                $TransientClientManagementObject | Add-Member -MemberType NoteProperty -Name "MinimumClientRSSIThreshold" -Value ""
                                break
                            }
                            else
                            {
                                $command = "`$WLAN$($count).TransientClientManagement = `$TransientClientManagement"
                                Invoke-Expression $command
                                break
                            }
                        } 
                        "^80211w-pmf(.*)="
                        {
                            $PMF11w = ($Line -split "(.*)=")[2].Trim()
                            $command = "`$WLAN$($count).PMF11w = `$PMF11w"
                            Invoke-Expression $command
                            break
                        } 
                    }
                }
            }
        }

        $command = "`$WLANs += `$WLAN$($count)"
        Invoke-Expression $command
        return $WLANs
    }

    [Array]getAPs()
    {
        Write-Host "`t APs"
        $APConfig = get-content .\ZoneDirectorConfigs\APs.txt
        $APs = @()

        $ChannelRangeObject = New-Object -TypeName PSObject
        $RadioANObject = New-Object -TypeName PSObject
        $RadioBGNObject = New-Object -TypeName PSObject
        $NetworkSettingsObject = New-Object -TypeName PSObject
        $MeshObject = New-Object -TypeName PSObject
        $LLDPObject = New-Object -TypeName PSObject
        $startpoint = $false
        $startChannelRange = $false
        $startRadioAN = $false
        $startRadioBGN = $false
        $startNetworkSetting = $false
        $startMesh = $false
        $startLLDP = $false
        $startLANPort = $false
        $count = 0


        foreach($Line in $APConfig)
        {
            if(($Line -match "^\d:(.*)" -or $Line -match "^\d\d:(.*)") -and $startLANPort -eq $false)
            {            

                if($count -gt 0)
                {
                    $startpoint = $false
                    $startChannelRange = $false
                    $startRadioAN = $false
                    $startRadioBGN = $false
                    $startNetworkSetting = $false
                    $startMesh = $false
                    $startLLDP = $false
                    $command = "`$APs += `$AP$($count)"
                    Invoke-Expression $command
                }
                
                $startpoint = $true
                $count++
                $command = "`$AP$($count) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"MACAddress`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"Model`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"Approved`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"DeviceName`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"Location`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"GPS`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"CERT`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"BonjourPolicy`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"BonjourFencing`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"GroupName`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"ChannelRange`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"RadioAN`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"RadioBGN`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"OverrideGlobalPortConfig`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"NetworkSetting`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"Mesh`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"LLDP`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"PoEMode`" -Value `"`""
                Invoke-Expression $command
                $command = "`$AP$($count) | Add-Member -MemberType NoteProperty -Name `"LACPState`" -Value `"`""
                Invoke-Expression $command

            }

            if($startpoint)
            {
                if($startChannelRange -and $Line -imatch "^Override global ap-model port configuration(.*)")
                {
                    $startChannelRange = $false
                }
                elseif($startRadioAN -and ($Line -imatch "^Radio b/g/n:(.*)" -or $Line -imatch "^Override global ap-model port configuration(.*)"))
                {
                    $startRadioAN = $false
                }
                elseif($startRadioBGN -and $Line -imatch "^Override global ap-model port configuration(.*)")
                {
                    $startRadioBGN = $false
                }
                elseif($startNetworkSetting -and $Line -imatch "^Mesh:(.*)")
                {
                    $startNetworkSetting = $false
                }
                elseif($startMesh -and $Line -imatch "^LLDP:(.*)")
                {
                    $startMesh = $false
                }
                elseif($startLLDP -and $Line -imatch "^PoE Mode(.*)=(.*)")
                {
                    $startLLDP = $false
                }

                if($startChannelRange)
                {
                    if($Line -imatch "A/N(.*)=(.*)")
                    {
                        $ANObject = New-Object -TypeName PSObject
                        $ANObject | Add-Member -MemberType NoteProperty -Name "Allowed" -Value ""
                        $ANObject | Add-Member -MemberType NoteProperty -Name "Disallowed" -Value ""

                        $AN = $Line -split "A/N=(.*)"
                        $AN = $AN[1] -split "\(Disallowed=(.*)\)"
                        $ANAllowed = $AN[0].Trim()
                        $ANDisallowed = $AN[1].Trim()
                        $ANObject.Allowed = $ANAllowed
                        $ANObject.Disallowed = $ANDisallowed
                        $ChannelRangeObject.AN = $ANObject

                    }
                    elseif($Line -imatch "B/G/N(.*)=(.*)")
                    {
                        $BGNObject = New-Object -TypeName PSObject
                        $BGNObject | Add-Member -MemberType NoteProperty -Name "Allowed" -Value ""
                        $BGNObject | Add-Member -MemberType NoteProperty -Name "Disallowed" -Value ""

                        $BGN = $Line -split "B/G/N="
                        $BGN = $BGN[1] -split "\(Disallowed=(.*)\)"
                        $BGNAllowed = $BGN[0].Trim()
                        $BGNDisallowed = $BGN[1].Trim()
                        $BGNObject.Allowed = $BGNAllowed
                        $BGNObject.Disallowed = $BGNDisallowed
                        $ChannelRangeObject.BGN = $BGNObject

                        $command = "`$AP$($count).ChannelRange = `$ChannelRangeObject"
                        Invoke-Expression $command

                        $startChannelRange = $false

                    }
                }
                elseif($startRadioAN)
                {
                    switch -Regex ($Line)
                    {
                        "^Channelization(.*)=(.*)"
                        {
                            $Channelization = $Line -split "Channelization(.*)=(.*)"
                            $Channelization = $Channelization[2].Trim()
                            $RadioANObject.Channelization = $Channelization
                            
                            break
                        }
                        "^Channel(.*)=(.*)"
                        {
                            $Channel = $Line -split "Channel(.*)=(.*)"
                            $Channel = $Channel[2].Trim()
                            $RadioANObject.Channel = $Channel
                            break
                        }
                        "^WLAN Services enabled(.*)=(.*)"
                        {
                            $WLANServicesEnabled = $Line -split "WLAN Services enabled(.*)=(.*)"
                            $WLANServicesEnabled = $WLANServicesEnabled[2].Trim()
                            $RadioANObject.WLANServicesEnabled = $WLANServicesEnabled
                            break
                        }
                        "^Tx. Power(.*)=(.*)"
                        {
                            $TxPower = $Line -split "Tx. Power(.*)=(.*)"
                            $TxPower = $TxPower[2].Trim()
                            $RadioANObject.TxPower = $TxPower
                            break
                        }
                        "^WLAN Group Name(.*)=(.*)"
                        {
                            $WLANGroupName = $Line -split "WLAN Group Name(.*)=(.*)"
                            $WLANGroupName = $WLANGroupName[2].Trim()
                            $RadioANObject.WLANGroupName = $WLANGroupName
                            break
                        }
                        "^Call Admission Control(.*)=(.*)"
                        {
                            $CallAdmissions = $Line -split "Call Admission Control(.*)=(.*)"
                            $CallAdmissions = $CallAdmissions[2].Trim()
                            $RadioANObject.CallAdmissionControl = $CallAdmissions
                            break
                        }
                        "^Protection Mode(.*)=(.*)"
                        {
                            $ProtectionMode = $Line -split "Protection Mode(.*)=(.*)"
                            $ProtectionMode = $ProtectionMode[2].Trim()
                            $RadioANObject.ProtectionMode = $ProtectionMode
                            
                            $command = "`$AP$($count).RadioAN = `$RadioANObject"
                            Invoke-Expression $command

                            $startRadioAN = $false
                            break
                        }
                    }
                }
                elseif($startRadioBGN)
                {
                    switch -Regex ($Line)
                    {
                        "^Channelization(.*)=(.*)"
                        {
                            $Channelization = $Line -split "Channelization(.*)=(.*)"
                            $Channelization = $Channelization[2].Trim()
                            $RadioBGNObject.Channelization = $Channelization
                            break
                        }
                        "^Channel(.*)=(.*)"
                        {
                            $Channel = $Line -split "Channel(.*)=(.*)"
                            $Channel = $Channel[2].Trim()
                            $RadioBGNObject.Channel = $Channel
                            break
                        }
                        "^WLAN Services enabled(.*)=(.*)"
                        {
                            $WLANServicesEnabled = $Line -split "WLAN Services enabled(.*)=(.*)"
                            $WLANServicesEnabled = $WLANServicesEnabled[2].Trim()
                            $RadioBGNObject.WLANServicesEnabled = $WLANServicesEnabled
                            break
                        }
                        "^Tx. Power(.*)=(.*)"
                        {
                            $TxPower = $Line -split "Tx. Power(.*)=(.*)"
                            $TxPower = $TxPower[2].Trim()
                            $RadioBGNObject.TxPower = $TxPower
                            break
                        }
                        "^WLAN Group Name(.*)=(.*)"
                        {
                            $WLANGroupName = $Line -split "WLAN Group Name(.*)=(.*)"
                            $WLANGroupName = $WLANGroupName[2].Trim()
                            $RadioBGNObject.WLANGroupName = $WLANGroupName
                            break
                        }
                        "^Call Admission Control(.*)=(.*)"
                        {
                            $CallAdmissions = $Line -split "Call Admission Control(.*)=(.*)"
                            $CallAdmissions = $CallAdmissions[2].Trim()
                            $RadioBGNObject.CallAdmissionControl = $CallAdmissions
                            break
                        }
                        "^Protection Mode(.*)=(.*)"
                        {
                            $ProtectionMode = $Line -split "Protection Mode(.*)=(.*)"
                            $ProtectionMode = $ProtectionMode[2].Trim()
                            $RadioBGNObject.ProtectionMode = $ProtectionMode

                            $command = "`$AP$($count).RadioBGN = `$RadioBGNObject"
                            Invoke-Expression $command

                            $startRadioBGN = $false

                            break
                        }
                    }
                }
                elseif($startNetworkSetting)
                {
                    switch -Regex ($Line)
                    {
                        "^Protocol mode(.*)=(.*)"
                        {
                            $ProtocolMode = $Line -split "Protocol mode(.*)="
                            $ProtocolMode = $ProtocolMode[2].Trim()
                            $NetworkSettingsObject.ProtocolMode = $ProtocolMode
                            break
                        }
                        "^Device IP Settings(.*)=(.*)"
                        {
                            $DeviceIPSettings = $Line -split "Device IP Settings(.*)="
                            $DeviceIPSettings = $DeviceIPSettings[2].Trim()
                            $NetworkSettingsObject.DeviceIPSettings = $DeviceIPSettings
                            break
                        }
                        "^IP Type(.*)=(.*)"
                        {
                            $IPType = $Line -split "IP Type(.*)="
                            $IPType = $IPType[2].Trim()
                            $NetworkSettingsObject.IPType = $IPType
                            break
                        }
                        "^IP Address(.*)=(.*)"
                        {
                            $IPAddress = $Line -split "IP Address(.*)="
                            $IPAddress = $IPAddress[2].Trim()
                            $NetworkSettingsObject.IPAddress = $IPAddress
                            break
                        }
                        "^Netmask(.*)=(.*)"
                        {
                            $Netmask = $Line -split "Netmask(.*)="
                            $Netmask = $Netmask[2].Trim()
                            $NetworkSettingsObject.Netmask = $Netmask
                            break
                        }
                        "^Gateway(.*)=(.*)"
                        {
                            $Gateway = $Line -split "Gateway(.*)="
                            $Gateway = $Gateway[2].Trim()
                            $NetworkSettingsObject.Gateway = $Gateway
                            break
                        }
                        "^Primary DNS Server(.*)=(.*)"
                        {
                            $PrimaryDNSServer = $Line -split "Primary DNS Server(.*)="
                            $PrimaryDNSServer = $PrimaryDNSServer[2].Trim()
                            $NetworkSettingsObject.PrimaryDNSServer = $PrimaryDNSServer
                            break
                        }
                        "^Secondary DNS Server(.*)=(.*)"
                        {
                            $SecondaryDNSServer = $Line -split "Secondary DNS Server(.*)="
                            $SecondaryDNSServer = $SecondaryDNSServer[2].Trim()
                            $NetworkSettingsObject.SecondaryDNSServer = $SecondaryDNSServer
                            break
                        }
                        "^Device IPv6 Settings(.*)=(.*)"
                        {
                            $DeviceIPv6Settings = $Line -split "Device IPv6 Settings(.*)="
                            $DeviceIPv6Settings = $DeviceIPv6Settings[2].Trim()
                            $NetworkSettingsObject.DeviceIPv6Settings = $DeviceIPv6Settings
                            break
                        }
                        "^IPv6 Type(.*)=(.*)"
                        {
                            $IPv6Type = $Line -split "IPv6 Type(.*)="
                            $IPv6Type = $IPv6Type[2].Trim()
                            $NetworkSettingsObject.IPv6Type = $IPv6Type
                            break
                        }
                        "^IPv6 Address(.*)=(.*)"
                        {
                            $IPv6Address = $Line -split "IPv6 Address(.*)="
                            $IPv6Address = $IPv6Address[2].Trim()
                            $NetworkSettingsObject.IPv6Address = $IPv6Address
                            break
                        }
                        "^IPv6 Prefix Length(.*)=(.*)"
                        {
                            $IPv6PrefixLength = $Line -split "IPv6 Prefix Length(.*)="
                            $IPv6PrefixLength = $IPv6PrefixLength[2].Trim()
                            $NetworkSettingsObject.IPv6PrefixLength = $IPv6PrefixLength
                            break
                        }
                        "^IPv6 Gateway(.*)=(.*)"
                        {
                            $IPv6Gateway = $Line -split "IPv6 Gateway(.*)="
                            $IPv6Gateway = $IPv6Gateway[2].Trim()
                            $NetworkSettingsObject.IPv6Gateway = $IPv6Gateway
                            break
                        }
                        "^IPv6 Primary DNS Server(.*)=(.*)"
                        {
                            $IPv6PrimaryDNSServer = $Line -split "IPv6 Primary DNS Server(.*)="
                            $IPv6PrimaryDNSServer = $IPv6PrimaryDNSServer[2].Trim()
                            $NetworkSettingsObject.IPv6PrimaryDNSServer = $IPv6PrimaryDNSServer
                            break
                        }
                        "^IPv6 Secondary DNS Server(.*)=(.*)"
                        {
                            $IPv6SecondaryDNSServer = $Line -split "IPv6 Secondary DNS Server(.*)="
                            $IPv6SecondaryDNSServer = $IPv6SecondaryDNSServer[2].Trim()
                            $NetworkSettingsObject.IPv6SecondaryDNSServer = $IPv6SecondaryDNSServer

                            $command = "`$AP$($count).NetworkSetting = `$NetworkSettingsObject"
                            Invoke-Expression $command

                            $startNetworkSetting = $false
                            break
                        }
                    }
                }
                elseif($startMesh)
                {
                    switch -Regex ($Line)
                    {
                        "^Mode(.*)=(.*)"
                        {
                            $Mode = $Line -split "Mode(.*)="
                            $Mode = $Mode[2].Trim()
                            $MeshObject.Mode = $Mode
                            break
                        }
                        "^max hops(.*)=(.*)"
                        {
                            $MaxHops = $Line -split "max hops(.*)="
                            $MaxHops = $MaxHops[2].Trim()
                            $MeshObject.MaxHops = $MaxHops

                            $startMesh = $false
                            $command = "`$AP$($count).Mesh = `$MeshObject"
                            Invoke-Expression $command

                            break
                        }
                    }
                }
                elseif($startLLDP)
                {
                    $Status = $Line -split "Status(.*)= "
                    $Status = $Status[2].Trim()
                    $LLDPObject.Status = $Status

                    $startLLDP = $false
                    $command = "`$AP$($count).LLDP = `$LLDPObject"
                    Invoke-Expression $command

                }
                elseif($Line.Length -eq 0)
                {
                    $startLanPort = $false
                }
                else
                {
                    switch -Regex($Line)
                    {
                        "^MAC Address(.*)=(.*)"
                        {
                            $MAC = $Line -split "MAC Address(.*)="
                            $MAC = $MAC[2].Trim()
                            $command = "`$AP$($count).MACAddress = `$MAC"
                            Invoke-Expression $command
                            break
                        }
                        "^Model(.*)=(.*)"
                        {
                            $Model = $Line -split "Model(.*)="
                            $Model = $Model[2].Trim()
                            $command = "`$AP$($count).Model = `$Model"
                            Invoke-Expression $command
                            break
                        }
                        "^Approved(.*)=(.*)"
                        {
                            $Approved = $Line -split "Approved(.*)="
                            $Approved = $Approved[2].Trim()
                            $command = "`$AP$($count).Approved = `$Approved"
                            Invoke-Expression $command
                            break
                        }
                        "^Device Name(.*)=(.*)"
                        {
                            $DeviceName = $Line -split "Device Name(.*)="
                            $DeviceName = $DeviceName[2].Trim()
                            $command = "`$AP$($count).DeviceName = `$DeviceName"
                            Invoke-Expression $command
                            break
                        }
                        "^Description(.*)=(.*)"
                        {
                            $Description = $Line -split "Description(.*)="
                            $Description = $Description[2].Trim()
                            $command = "`$AP$($count).Description = `$Description"
                            Invoke-Expression $command
                            break
                        }
                        "^Location(.*)"
                        {
                            $Location = $Line -split "Location(.*)="
                            $Location = $Location[2].Trim()
                            $command = "`$AP$($count).Location = `$Location"
                            Invoke-Expression $command
                            break
                        }
                        "^GPS(.*)"
                        {
                            $GPS = $Line -split "GPS(.*)="
                            $GPS = $GPS[2].Trim()
                            $command = "`$AP$($count).GPS = `$GPS"
                            Invoke-Expression $command
                            break
                        }
                        "^CERT(.*)"
                        {
                            $CERT = $Line -split "CERT(.*)="
                            $CERT = $CERT[2].Trim()
                            $command = "`$AP$($count).CERT = `$CERT"
                            Invoke-Expression $command
                            break
                        }
                        "^Bonjour-policy(.*)"
                        {
                            $BonjourPolicy = $Line -split "Bonjour-policy(.*)="
                            $BonjourPolicy = $BonjourPolicy[2].Trim()
                            $command = "`$AP$($count).BonjourPolicy = `$BonjourPolicy"
                            Invoke-Expression $command
                            break
                        }
                        "^Bonjour-fencing(.*)"
                        {
                            $BonjourFencing = $Line -split "Bonjour-fencing(.*)="
                            $BonjourFencing = $BonjourFencing[2].Trim()
                            $command = "`$AP$($count).BonjourFencing = `$BonjourFencing"
                            Invoke-Expression $command
                            break
                        }
                        "^Group Name(.*)"
                        {
                            $GroupName = $Line -split "Group Name(.*)="
                            $GroupName = $GroupName[2].Trim()
                            $command = "`$AP$($count).GroupName = `$GroupName"
                            Invoke-Expression $command
                            break
                        }
                        "^Channel Range:(.*)"
                        {
                            $startChannelRange = $true
                            $ChannelRangeObject = New-Object -TypeName PSObject
                            $ChannelRangeObject | Add-Member -MemberType NoteProperty -Name "AN" -Value ""
                            $ChannelRangeObject | Add-Member -MemberType NoteProperty -Name "BGN" -Value ""
                            break
                        }
                        "^Radio a/n:(.*)"
                        {
                            $startRadioAN = $true
                            $RadioANObject = New-Object -TypeName PSObject
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "Channelization" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "Channel" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "WLANServicesEnabled" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "TxPower" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "WLANGroupName" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "CallAdmissionControl" -Value ""
                            $RadioANObject | Add-Member -MemberType NoteProperty -Name "ProtectionMode" -Value ""
                            break
                        }
                        "^Radio b/g/n:(.*)"
                        {
                            $startRadioBGN = $true
                            $RadioBGNObject = New-Object -TypeName PSObject
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "Channelization" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "Channel" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "WLANServicesEnabled" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "TxPower" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "WLANGroupName" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "CallAdmissionControl" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "ProtectionMode" -Value ""
                            break
                        }
                        "^Override global ap-model port configuration(.*)"
                        {
                            $OverrideGlobalPortConfig = $Line -split "Override global ap-model port configuration(.*)="
                            $OverrideGlobalPortConfig = $OverrideGlobalPortConfig[2].Trim()
                            $command = "`$AP$($count).OverrideGlobalPortConfig = `$OverrideGlobalPortConfig"
                            Invoke-Expression $command
                            break
                        }
                        "^Network Setting:(.*)"
                        {
                            $startNetworkSetting = $true
                            $NetworkSettingsObject = New-Object -TypeName PSObject
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "ProtocolMode" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "DeviceIPSettings" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPType" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "Netmask" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "Gateway" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "PrimaryDNSServer" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "SecondaryDNSServer" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "DeviceIPv6Settings" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6Type" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6Address" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6PrefixLength" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6Gateway" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6PrimaryDNSServer" -Value ""
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "IPv6SecondaryDNSServer" -Value ""
                            break
                        }
                        "^Mesh:(.*)"
                        {
                            $startMesh = $true
                            $MeshObject = New-Object -TypeName PSObject
                            $MeshObject | Add-Member -MemberType NoteProperty -Name "Mode" -Value ""
                            $MeshObject | Add-Member -MemberType NoteProperty -Name "MaxHops" -Value ""
                            break
                        }
                        "^LLDP:(.*)"
                        {
                            $startLLDP = $true
                            $LLDPObject = New-Object -TypeName PSObject
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "Status" -Value ""
                            break
                        }
                        "^PoE Mode(.*)"
                        {
                            $PoE = $Line -split "PoE Mode(.*)="
                            $PoE = $PoE[2].Trim()
                            $command = "`$AP$($count).PoEMode = `$PoE"
                            Invoke-Expression $command
                            break
                        }
                        "^LACP State(.*)"
                        {
                            $LACP = $Line -split "LACP State(.*)="
                            $LACP = $LACP[2].Trim()
                            $command = "`$AP$($count).LACPState = `$LACP"
                            Invoke-Expression $command
                            break
                        }
                        "^LAN Port(.*)"
                        {
                            $startLANPort = $true
                            break
                        }
                    }
                }
            }
        }

        $command = "`$APs += `$AP$($count)"
        Invoke-Expression $command

        return $APs
    }

    [Array]getAPGroups()
    {
        Write-Host "`t AP Groups"
        $APGroupConfig = get-content .\ZoneDirectorConfigs\APGroups.txt
        $APGroups = @()
        
        $LocationServicesObject = New-Object -TypeName PSObject
        $ChannelRangeObject = New-Object -TypeName PSObject
        $RadioANACObject = New-Object -TypeName PSObject
        $RadioBGNObject = New-Object -TypeName PSObject
        $NetworkSettingsObject = New-Object -TypeName PSObject
        $BonjourFencingObject = New-Object -TypeName PSObject
        $MeshObject = New-Object -TypeName PSObject
        $ChannflyObject = New-Object -TypeName PSObject
        $MembersObject = New-Object -TypeName PSObject
        $LLDPObject = New-Object -TypeName PSObject
        $startpoint = $false
        $startLocationServices = $false
        $startChannelRange = $false
        $startRadio11BGN = $false
        $startRadio11ANAC = $false
        $startNetworkSetting = $false
        $startBonjourFencing = $false
        $startMesh = $false
        $startChannflySetting = $false
        $startMembers = $false
        $startLLDP = $false

        $count = 0
        foreach($Line in $APGroupConfig)
        {
            if($Line -match "^\d:(.*)" -or $Line -match "^\d\d:(.*)")
            {            

                if($count -gt 0)
                {
                    $command = "`$APGroups += `$APGroup$($count)"
                    Invoke-Expression $command
                }
                
                $startpoint = $true
                $startLocationServices = $false
                $startChannelRange = $false
                $startRadio11BGN = $false
                $startRadio11ANAC = $false
                $startNetworkSetting = $false
                $startBonjourFencing = $false
                $startMesh = $false
                $startChannflySetting = $false
                $startMembers = $false
                $startLLDP = $false
                $count++

                $command = "`$APGroup$($count) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"MLDQueryv1`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"MLDQueryv2`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"IGMPQueryv2`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"IGMPQueryv3`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"LocationBaseService`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"ChannelRange`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Radio11BGN`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Radio11ANAC`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"NetworkSetting`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"BonjourFencing`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Mesh`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"ChannflySetting`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Members`" -Value `"`""
                Invoke-Expression $command
                $command = "`$APGroup$($count) | Add-Member -MemberType NoteProperty -Name `"LLDP`" -Value `"`""
                Invoke-Expression $command
            }

            if($startpoint)
            {
                if($startChannelRange -and $Line -imatch "^Override global ap-model port configuration(.*)")
                {
                    $startChannelRange = $false
                }
                elseif($startMembers -and $Line -imatch "^LLDP:")
                {
                    $startMembers = $false
                    
                }

                if($startLocationServices)
                {
                    switch -Regex ($Line)
                    {
                        "^State(.*)"
                        {
                            $LocationServices = $Line -split "State(.*)="
                            $LocationServices = $LocationServices[2].Trim()
                            $LocationServicesObject.State = $LocationServices
                            break
                        }
                        "^Location Server(.*)"
                        {
                            $LocationServer = $Line -split "Location Server(.*)="
                            $LocationServer = $LocationServer[2].Trim()
                            $LocationServicesObject.LocationServer = $LocationServer

                            $startLocationServices = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).LocationBaseService = `$LocationServicesObject"
                    Invoke-Expression $command
                }
                elseif($startChannelRange)
                {
                    switch -Regex ($Line)
                    {
                        "^B/G/N(.*)="
                        {
                            $BGNObject = New-Object -TypeName PSObject
                            $BGNObject | Add-Member -MemberType NoteProperty -Name "Allowed" -Value ""
                            $BGNObject | Add-Member -MemberType NoteProperty -Name "Disallowed" -Value ""

                            $BGN = $Line -split "B/G/N="
                            $BGN = $BGN[1] -split "\(Disallowed=(.*)\)"
                            $BGNAllowed = $BGN[0].Trim()
                            $BGNDisallowed = $BGN[1].Trim()
                            $BGNObject.Allowed = $BGNAllowed
                            $BGNObject.Disallowed = $BGNDisallowed
                            $ChannelRangeObject.BGN = $BGNObject
                        }
                        "^A/N Indoor(.*)="
                        {
                            $ANIndoorObject = New-Object -TypeName PSObject
                            $ANIndoorObject | Add-Member -MemberType NoteProperty -Name "Allowed" -Value ""
                            $ANIndoorObject | Add-Member -MemberType NoteProperty -Name "Disallowed" -Value ""

                            $ANIndoor = $Line -split "A/N Indoor="
                            $ANIndoor = $ANIndoor[1] -split "\(Disallowed=(.*)\)"
                            $ANIndoorAllowed = $ANIndoor[0].Trim()
                            $ANIndoorDisallowed = $ANIndoor[1].Trim()
                            $ANIndoorObject.Allowed = $ANIndoorAllowed
                            $ANIndoorObject.Disallowed = $ANIndoorDisallowed
                            $ChannelRangeObject.ANIndoor = $ANIndoorObject
                            break
                        }
                        "^A/N Outdoor(.*)="
                        {
                            $ANOutdoorObject = New-Object -TypeName PSObject
                            $ANOutdoorObject | Add-Member -MemberType NoteProperty -Name "Allowed" -Value ""
                            $ANOutdoorObject | Add-Member -MemberType NoteProperty -Name "Disallowed" -Value ""

                            $ANOutdoor = $Line -split "A/N Outdoor="
                            $ANOutdoor = $ANOutdoor[1] -split "\(Disallowed=(.*)\)"
                            $ANOutdoorAllowed = $ANOutdoor[0].Trim()
                            $ANOutdoorDisallowed = $ANOutdoor[1].Trim()
                            $ANOutdoorObject.Allowed = $ANOutdoorAllowed
                            $ANOutdoorObject.Disallowed = $ANOutdoorDisallowed
                            $ChannelRangeObject.ANOutdoor = $ANOutdoorObject

                            $startChannelRange = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).ChannelRange = `$ChannelRangeObject"
                    Invoke-Expression $command
                }
                elseif($startRadio11ANAC)
                {
                    switch -Regex ($Line)
                    {
                        "^Channelization(.*)="
                        {
                            $Channelization = $Line -split "Channelization(.*)="
                            $Channelization = $Channelization[2].Trim()
                            $RadioANACObject.Channelization = $Channelization
                            
                            break
                        }
                        "^Indoor Channel(.*)="
                        {
                            $IndoorChannel = $Line -split "Indoor Channel(.*)="
                            $IndoorChannel = $IndoorChannel[2].Trim()
                            $RadioANACObject.IndoorChannel = $IndoorChannel
                            break
                        }
                        "^Outdoor Channel(.*)="
                        {
                            $OutdoorChannel = $Line -split "Outdoor Channel(.*)="
                            $OutdoorChannel = $OutdoorChannel[2].Trim()
                            $RadioANACObject.OutdoorChannel = $OutdoorChannel
                            break
                        }
                        "^Tx. Power(.*)="
                        {
                            $TxPower = $Line -split "Tx. Power(.*)="
                            $TxPower = $TxPower[2].Trim()
                            $RadioANACObject.TxPower = $TxPower
                            break
                        }
                        "11N only Mode(.*)="
                        {
                            $Mode11n = $Line -split "11N only Mode(.*)="
                            $Mode11n = $Mode11n[2].Trim()
                            $RadioANACObject.Mode11N = $Mode11n
                            break
                        }
                        "^WLAN Group(.*)="
                        {
                            $WLANGroupName = $Line -split "WLAN Group(.*)="
                            $WLANGroupName = $WLANGroupName[2].Trim()
                            $RadioANACObject.WLANGroup = $WLANGroupName
                            break
                        }
                        "^Call Admission Control(.*)="
                        {
                            $CallAdmissions = $Line -split "Call Admission Control(.*)="
                            $CallAdmissions = $CallAdmissions[2].Trim()
                            $RadioANACObject.CallAdmissionControl = $CallAdmissions
                            break
                        }
                        "^Protection Mode(.*)="
                        {
                            $ProtectionMode = $Line -split "Protection Mode(.*)="
                            $ProtectionMode = $ProtectionMode[2].Trim()
                            $RadioANACObject.ProtectionMode = $ProtectionMode
                            break
                        }
                        "^Wlan Service(.*)="
                        {
                            $WLANServicesEnabled = $Line -split "Wlan Service(.*)="
                            $WLANServicesEnabled = $WLANServicesEnabled[2].Trim()
                            $RadioANACObject.WlanService = $WLANServicesEnabled
                            $startRadio11ANAC = $false
                            
                            break
                        }
                    }

                    $command = "`$APGroup$($count).Radio11ANAC = `$RadioANACObject"
                    Invoke-Expression $command
                }
                elseif($startRadio11BGN)
                {
                    switch -Regex ($Line)
                    {
                        "^Channelization(.*)="
                        {
                            $Channelization = $Line -split "Channelization(.*)="
                            $Channelization = $Channelization[2].Trim()
                            $RadioBGNObject.Channelization = $Channelization
                            
                            break
                        }
                        "^Channel(.*)="
                        {
                            $Channel = $Line -split "Channel(.*)="
                            $Channel = $Channel[2].Trim()
                            $RadioBGNObject.Channel = $Channel
                            break
                        }
                        "^Tx. Power(.*)="
                        {
                            $TxPower = $Line -split "Tx. Power(.*)="
                            $TxPower = $TxPower[2].Trim()
                            $RadioBGNObject.TxPower = $TxPower
                            break
                        }
                        "11N only Mode(.*)="
                        {
                            $Mode11n = $Line -split "11N only Mode(.*)="
                            $Mode11n = $Mode11n[2].Trim()
                            $RadioBGNObject.Mode11N = $Mode11n
                            break
                        }
                        "^WLAN Group(.*)="
                        {
                            $WLANGroupName = $Line -split "WLAN Group(.*)="
                            $WLANGroupName = $WLANGroupName[2].Trim()
                            $RadioBGNObject.WLANGroup = $WLANGroupName
                            break
                        }
                        "^Call Admission Control(.*)="
                        {
                            $CallAdmissions = $Line -split "Call Admission Control(.*)="
                            $CallAdmissions = $CallAdmissions[2].Trim()
                            $RadioBGNObject.CallAdmissionControl = $CallAdmissions
                            break
                        }
                        "^Protection Mode(.*)="
                        {
                            $ProtectionMode = $Line -split "Protection Mode(.*)="
                            $ProtectionMode = $ProtectionMode[2].Trim()
                            $RadioBGNObject.ProtectionMode = $ProtectionMode
                            break
                        }
                        "^Wlan Service(.*)="
                        {
                            $WLANServicesEnabled = $Line -split "Wlan Service(.*)="
                            $WLANServicesEnabled = $WLANServicesEnabled[2].Trim()
                            $RadioBGNObject.WlanService = $WLANServicesEnabled

                            $startRadio11BGN = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).Radio11BGN = `$RadioBGNObject"
                    Invoke-Expression $command
                }
                elseif($startNetworkSetting)
                {
                    switch -Regex ($Line)
                    {
                        "^Protocol mode(.*)=(.*)"
                        {
                            $ProtocolMode = $Line -split "Protocol mode(.*)="
                            $ProtocolMode = $ProtocolMode[2].Trim()
                            $NetworkSettingsObject.ProtocolMode = $ProtocolMode

                            $startNetworkSetting = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).NetworkSetting = `$NetworkSettingsObject"
                    Invoke-Expression $command
                }
                elseif($startBonjourFencing)
                {
                    switch -Regex ($Line)
                    {
                        "^Bonjour-fencing(.*)="
                        {
                            $BonjourFencing = $Line -split "Bonjour-fencing(.*)="
                            $BonjourFencing = $BonjourFencing[2].Trim()
                            $BonjourFencingObject.BonjourFencing = $BonjourFencing

                            $startBonjourFencing = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).BonjourFencing = `$BonjourFencingObject"
                    Invoke-Expression $command
                }
                elseif($startMesh)
                {
                    switch -Regex ($Line)
                    {
                        "^Mode(.*)="
                        {
                            $Mode = $Line -split "Mode(.*)="
                            $Mode = $Mode[2].Trim()
                            $MeshObject.Mode = $Mode

                            $startMesh = $false
                            break
                            
                        }
                        "^max hops(.*)="
                        {
                            $MaxHops = $Line -split "max hops(.*)="
                            $MaxHops = $MaxHops[2].Trim()
                            $MeshObject.MaxHops = $MaxHops
                            break
                        }
                    }

                    $command = "`$APGroup$($count).Mesh = `$MeshObject"
                    Invoke-Expression $command
                }
                elseif($startChannflySetting)
                {
                    switch -Regex ($Line)
                    {
                        "^state(.*)="
                        {
                            $ChannflyState = $Line -split "state(.*)="
                            $ChannflyState = $ChannflyState[2].Trim()
                            $ChannflyObject.State = $ChannflyState

                            $startChannflySetting = $false
                            break
                        }
                    }

                    $command = "`$APGroup$($count).ChannflySetting = `$ChannflyObject"
                    Invoke-Expression $command
                }
                elseif($startMembers)
                {
                    switch -Regex ($Line)
                    {
                        "^MAC(.*)="
                        {
                            $MACAdress = $Line -split "MAC(.*)="
                            $MACAdress = $MACAdress[2].Trim()
                            $MembersObject.Members += $MACAdress
                            break
                        }
                    }

                    $command = "`$APGroup$($count).Members = `$MembersObject "
                    Invoke-Expression $command
                }
                elseif($startLLDP)
                {
                    switch -Regex ($Line)
                    {
                        "^Status(.*)="
                        {
                            $Status = $Line -split "Status(.*)= "
                            $Status = $Status[2].Trim()
                            $LLDPObject.Status = $Status
                            break
                        }
                        "^Keep AP's Settings(.*)="
                        {
                            $KeepSettings = $Line -split "Keep AP's Settings(.*)="
                            $KeepSettings = $KeepSettings[2].Trim()
                            $LLDPObject.KeeAPSettings = $KeepSettings
                            break
                        }
                        "^Interval(.*)="
                        {
                            $Interval = $Line -split "Interval(.*)="
                            $Interval = $Interval[2].Trim()
                            $LLDPObject.Interval = $Interval
                            break
                        }
                        "HoldTime(.*)="
                        {
                            $HoldTime = $Line -split "HoldTime(.*)="
                            $HoldTime = $HoldTime[2].Trim()
                            $LLDPObject.HoldTime = $HoldTime
                            break
                        }
                        "Mgmt(.*)="
                        {
                            $MGMT = $Line -split "Mgmt(.*)="
                            $MGMT = $MGMT[2].Trim()
                            $LLDPObject.Mgmt = $MGMT
                            break
                        }
                        "eth\d"
                        {
                            $Port = $Line -split "Send out LLDP packet on"
                            $Port = $Port[1] -split "="
                            $ETH = $Port[0].Trim()
                            $PortStatus = $Port[1].Trim()

                            if($ETH -imatch "eth5")
                            {
                                $ETHObject = New-Object -TypeName PSObject
                                $ETHObject | Add-Member -MemberType NoteProperty -Name "ETHPort" -Value $ETH
                                $ETHObject | Add-Member -MemberType NoteProperty -Name "PortStatus" -Value $PortStatus
                                $LLDPObject.Ports += $ETHObject
                                $startLLDP = $false
                            }
                            else
                            {
                                $ETHObject = New-Object -TypeName PSObject
                                $ETHObject | Add-Member -MemberType NoteProperty -Name "ETHPort" -Value $ETH
                                $ETHObject | Add-Member -MemberType NoteProperty -Name "PortStatus" -Value $PortStatus
                                $LLDPObject.Ports += $ETHObject
                            }
                        }
                    }

                    $command = "`$APGroup$($count).LLDP = `$LLDPObject"
                    Invoke-Expression $command
                }
                else
                {
                    switch -Regex($Line)
                    {
                        "^Name"
                        {
                            $Name = $Line -split "Name(.*)="
                            $Name = $Name[2].Trim()
                            $command = "`$APGroup$($count).Name = `$Name"
                            Invoke-Expression $command
                            break
                        }
                        "^Description"
                        {
                            $Description = $Line -split "Description(.*)="
                            $Description = $Description[2].Trim()
                            $command = "`$APGroup$($count).Description = `$Description"
                            Invoke-Expression $command
                            break
                        }
                        "^MLD Query v1"
                        {
                            $MLDQueryv1 = $Line -split "MLD Query v1(.*)="
                            $MLDQueryv1 = $MLDQueryv1[2].Trim()
                            $command = "`$APGroup$($count).MLDQueryv1 = `$MLDQueryv1"
                            Invoke-Expression $command
                            break
                        }
                        "^MLD Query v2"
                        {
                            $MLDQueryv2 = $Line -split "MLD Query v2(.*)="
                            $MLDQueryv2 = $MLDQueryv2[2].Trim()
                            $command = "`$APGroup$($count).MLDQueryv2 = `$MLDQueryv2"
                            Invoke-Expression $command
                            break
                        }
                        "^IGMP Query v2"
                        {
                            $IGMPQueryv2 = $Line -split "IGMP Query v2(.*)="
                            $IGMPQueryv2 = $IGMPQueryv2[2].Trim()
                            $command = "`$APGroup$($count).IGMPQueryv2 = `$IGMPQueryv2"
                            Invoke-Expression $command
                            break
                        }
                        "^IGMP Query v3"
                        {
                            $IGMPQueryv3 = $Line -split "IGMP Query v3(.*)="
                            $IGMPQueryv3 = $IGMPQueryv3[2].Trim()
                            $command = "`$APGroup$($count).IGMPQueryv3 = `$IGMPQueryv3"
                            Invoke-Expression $command
                            break
                        }
                        "^Location Base Service"
                        {
                            $startLocationServices = $true
                            $LocationServicesObject = New-Object -TypeName PSObject
                            $LocationServicesObject | Add-Member -MemberType NoteProperty -Name "State" -Value ""
                            $LocationServicesObject | Add-Member -MemberType NoteProperty -Name "LocationServer" -Value ""
                            break
                        }
                        "^Channel Range:"
                        {
                            $startChannelRange = $true
                            $ChannelRangeObject = New-Object -TypeName PSObject
                            $ChannelRangeObject | Add-Member -MemberType NoteProperty -Name "BGN" -Value ""
                            $ChannelRangeObject | Add-Member -MemberType NoteProperty -Name "ANIndoor" -Value ""
                            $ChannelRangeObject | Add-Member -MemberType NoteProperty -Name "ANOutdoor" -Value ""
                            
                            break
                        }
                        "^Radio 11bgn:"
                        {
                            $startRadio11BGN = $true
                            $RadioBGNObject = New-Object -TypeName PSObject
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "Channelization" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "Channel" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "TxPower" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "Mode11N" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "WLANGroup" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "CallAdmissionControl" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "ProtectionMode" -Value ""
                            $RadioBGNObject | Add-Member -MemberType NoteProperty -Name "WlanService" -Value ""
                            break
                        }
                        "^Radio 11an/ac:"
                        {
                            $startRadio11ANAC = $true
                            $RadioANACObject = New-Object -TypeName PSObject
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "Channelization" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "IndoorChannel" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "OutdoorChannel" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "TxPower" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "Mode11N" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "WLANGroup" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "CallAdmissionControl" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "ProtectionMode" -Value ""
                            $RadioANACObject | Add-Member -MemberType NoteProperty -Name "WlanService" -Value ""
                            break
                        }
                        "^Network Setting:"
                        {
                            $startNetworkSetting = $true
                            $NetworkSettingsObject = New-Object -TypeName PSObject
                            $NetworkSettingsObject | Add-Member -MemberType NoteProperty -Name "ProtocolMode" -Value ""
                            break
                        }
                        "Bonjour Fencing:"
                        {
                            $startBonjourFencing = $true
                            $BonjourFencingObject = New-Object -TypeName PSObject
                            $BonjourFencingObject | Add-Member -MemberType NoteProperty -Name "BonjourFencing" -Value ""
                            break
                        }
                        "^Mesh:"
                        {
                            $startMesh = $true
                            $MeshObject = New-Object -TypeName PSObject
                            $MeshObject | Add-Member -MemberType NoteProperty -Name "Mode" -Value ""
                            $MeshObject | Add-Member -MemberType NoteProperty -Name "MaxHops" -Value ""
                            break
                        }
                        "Turn off channfly setting:"
                        {
                            $startChannflySetting = $true
                            $ChannflyObject = New-Object -TypeName PSObject
                            $ChannflyObject | Add-Member -MemberType NoteProperty -Name "State" -Value ""
                            break
                        }
                        "Members:"
                        {
                            $startMembers = $true
                            $MembersObject = New-Object -TypeName PSObject
                            $MembersObject | Add-Member -MemberType NoteProperty -Name "Members" -Value @()
                            break
                        }
                        "^LLDP:"
                        {
                            $startLLDP = $true
                            $LLDPObject = New-Object -TypeName PSObject
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "Status" -Value ""
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "KeeAPSettings" -Value ""
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "Interval" -Value ""
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "HoldTime" -Value ""
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "Mgmt" -Value ""
                            $LLDPObject | Add-Member -MemberType NoteProperty -Name "Ports" -Value @()
                            break
                        }
                    }
                }
            }
        }

        $command = "`$APGroups += `$APGroup$($count)"
        Invoke-Expression $command

        return $APGroups
    }

    [Array]getVLANPools()
    {
        Write-Host "`t VLAN Pools"
        $VLANPoolConfig = Get-Content .\ZoneDirectorConfigs\VLANPools.txt
        $startpoint = $false
        $VLANPools = @()
        $count = 0

        foreach($Line in $VLANPoolConfig)
        {
            if($Line -match "^\d:(.*)" -or $Line -match "^\d\d:(.*)")
            {
                $startpoint = $true
                $count++
                $command = "`$VLANPool$($count) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$VLANPool$($count) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                Invoke-Expression $command
                $command = "`$VLANPool$($count) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$VLANPool$($count) | Add-Member -MemberType NoteProperty -Name `"Option`" -Value `"`""
                Invoke-Expression $command
                $command = "`$VLANPool$($count) | Add-Member -MemberType NoteProperty -Name `"VLANSET`" -Value `"`""
                Invoke-Expression $command
            }

            if($startpoint)
            {
                if($Line.Length -ne 0)
                {
                    Switch -Regex($Line)
                    {
                      "Name(.*)=(.*)"
                      {
                           $Line = ($Line -split "(.*)Name(.*)=(.*)")[3].Trim()
                           $command = "`$VLANPool$($count).Name = `$Line"
                           Invoke-Expression $command
                           break
                      }
                      "Description(.*)=(.*)"
                      {
                            $Line = ($Line -split "(.*)Description(.*)=(.*)")[3].Trim()
                            $command = "`$VLANPool$($count).Description = `$Line"
                            Invoke-Expression $command
                            break
                      }
                      "Option(.*)=(.*)"
                      {
                            $Line = ($Line -split "(.*)Option(.*)=(.*)")[3].Trim()
                            $command = "`$VLANPool$($count).Option = `$Line"
                            Invoke-Expression $command
                            break
                      }
                      "VLANSET(.*)=(.*)"
                      {
                            $Line = ($Line -split "(.*)VLANSET(.*)=(.*)")[3].Trim()
                            $command = "`$VLANPool$($count).VLANSET = `$Line"
                            Invoke-Expression $command
                            break
                      }
                    }
                }
                else
                {
                    $startpoint = $false
                    $command = "`$VLANPools += `$VLANPool$($count)"
                    Invoke-Expression $command
                }
            }
        }

        return $VLANPools
    }
 
    [Array]getWLANGroups()
    {
        Write-Host "`t WLAN Groups"
        $WLANGroupConfig = Get-Content .\ZoneDirectorConfigs\WLANGroups.txt

        $count = 0
        $WLANCount = 0
        $startpoint = $false
        $WLANstartpoint = $false
        $WLANGroups = @()

        foreach($Line in $WLANGroupConfig)
        {
            if($Line -imatch "^\d:"-or $Line -imatch "^\d\d:")
            {
                $startpoint = $true
                $WLANstartpoint = $false
                $Count++
                $command = "`$WLANGroup$($count) = New-Object -TypeName PSObject"
                Invoke-Expression $command
                $command = "`$WLANGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLANGroup$($count) | Add-Member -MemberType NoteProperty -Name `"Description`" -Value `"`""
                Invoke-Expression $command
                $command = "`$WLANGroup$($count) | Add-Member -MemberType NoteProperty -Name `"WLANServices`" -Value @()"
                Invoke-Expression $command
            }

            if($startpoint)
            {
                if($Line -imatch "WLAN Service:(.*)")
                {
                    $WLANstartpoint = $true
                    $WLANCount = 0
                }

                if($WLANstartpoint)
                {
                    if($Line -imatch "^WLAN\d:" -or $Line -imatch "^WLAN\d\d:" )
                    {
                        $WLANCount++
                        $command = "`$WLAN$($WLANCount) = New-Object -TypeName PSObject"
                        Invoke-Expression $command
                        $command = "`$WLAN$($WLANCount) | Add-Member -MemberType NoteProperty -Name `"Name`" -Value `"`""
                        Invoke-Expression $command
                        $command = "`$WLAN$($WLANCount) | Add-Member -MemberType NoteProperty -Name `"VLAN`" -Value `"`""
                        Invoke-Expression $command
                    }
                    elseif($Line -match "NAME(.*)=(.*)")
                    {
                        $WLANName = $Line -split "Name(.*)="
                        $WLANName = $WLANName[2].Trim()
                        $command = "`$WLAN$($WLANCount).Name = `$WLANName"
                        Invoke-Expression $command
                    }
                    elseif($Line -match "VLAN(.*)=(.*)")
                    {
                        $WLANVLAN = $Line -split "VLAN(.*)="
                        $WLANVLAN = $WLANVLAN[2].Trim()
                        $command = "`$WLAN$($WLANCount).VLAN = `$WLANVLAN"
                        Invoke-Expression $command
                        $command = "`$WLANGroup$($count).WLANServices += `$WLAN$($WLANCount)"
                        Invoke-Expression $command
                    }
                    elseif($Line -notmatch "WLAN Service:(.*)")
                    {
                        $WLANCount = 0
                        $startpoint = $false
                        $WLANstartpoint = $false
                        $command = "`$WLANGroups += `$WLANGroup$($count)"
                        Invoke-Expression $command
                    }
                    
                }
                else
                {
                    if($Line -imatch "Name(.*)=(.*)")
                    {
                        $WLANGroupName = $Line -split "Name(.*)="
                        $WLANGroupName = $WLANGroupName[2].Trim()
                        $command = "`$WLANGroup$($count).Name = `"$($WLANGroupName)`""
                        Invoke-Expression $command
                    }
                    elseif($Line -imatch "Description(.*)=(.*)")
                    {
                        $WLANGroupDesc = $Line -split "Description(.*)="
                        $WLANGroupDesc = $WLANGroupDesc[2].Trim()
                        $command = "`$WLANGroup$($count).Description = `"$($WLANGroupDesc)`""
                        Invoke-Expression $command
                    }
                }
            }
        }

        return $WLANGroups
    }

    [Array]getDPSK()
    {
        Write-Host "`t DPSKs"
        $DPSKConfig = Get-Content .\ZoneDirectorConfigs\DPSKList.txt
        $DPSKs = @()
        $startPoint = $true
        $Count = 0
        foreach($Line in $DPSKConfig)
        {
           if($Count -gt 0)
           {}
           
           if($Line -imatch "DPSK:(.*)")
           {
               $Count++
               $DPSKObject =  New-Object -TypeName PSObject
               $DPSKObject | Add-Member -MemberType NoteProperty -Name "User" -Value ""
               $DPSKObject | Add-Member -MemberType NoteProperty -Name "Role" -Value ""
               $DPSKObject | Add-Member -MemberType NoteProperty -Name "MACAddress" -Value ""
               $DPSKObject | Add-Member -MemberType NoteProperty -Name "" -Value ""
               $DPSKObject | Add-Member -MemberType NoteProperty -Name "" -Value ""
           }
        
           If($startPoint)
           {}
        
        }

        return $DPSKs
    }

    [Array]getAAA()
    {
        Write-Host "`t AAA Services"
        $AAAConfig = Get-Content .\ZoneDirectorConfigs\AAAs.txt
        $AAAs = @()
        
        $AAA = New-Object -TypeName PSObject
        $PrimaryRADIUSObject =  New-Object -TypeName PSObject
        $SecondaryRADIUSObject =  New-Object -TypeName PSObject
        $RetryPolicyObject = New-Object -TypeName PSObject
        $startPoint = $false
        $StartPrimaryRADIUS = $false
        $StartSecondaryRADIUS = $false
        $StartRetryPolicy = $false
        $Count = 0

        foreach($Line in $AAAConfig)
        {
        
            if($Line -match "^\d:(.*)" -or $Line -match "^\d\d:(.*)")
            {
                if($Count -gt 0)
                {
                    $AAAs += $AAA
                }

                $startpoint = $true
                $StartPrimaryRADIUS = $false
                $StartSecondaryRADIUS = $false
                $StartRetryPolicy = $false
                $Count++
                $AAA = New-Object -TypeName PSObject
                $AAA | Add-Member -MemberType NoteProperty -Name "Name" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "Type" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "AuthMethod" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "PrimaryRADIUS" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "SecondaryRADIUS" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "Port" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "WindowsDomainName" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "AdminDN" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "DomainServerDeviceName" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "AdminPassword" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "encryptionTLS" -Value ""
                $AAA | Add-Member -MemberType NoteProperty -Name "RetryPolicy" -Value ""
            }
            
            if($startpoint)
            {
                if($StartPrimaryRADIUS)
                {
                    switch -Regex ($Line)
                    {
                        "^IP Address"
                        {
                            $IPAddress = ($Line -split "IP Address(.*)=")[2].Trim()
                            $PrimaryRADIUSObject.IPAddress = $IPAddress
                            $AAA.PrimaryRADIUS = $PrimaryRADIUSObject
                                                     

                            break
                        }
                        "^Port"
                        {
                            $Port = ($Line -split "Port(.*)=")[2].Trim()
                            $PrimaryRADIUSObject.Port = $Port
                            $AAA.PrimaryRADIUS = $PrimaryRADIUSObject
                            break
                        }
                        "^Secret"
                        {
                            Write-Host "`t`t Enter the Secrete/Password for Primary RADIUS($($PrimaryRADIUSObject.IPAddress)) server on $($AAA.NAME) AAA service"
                            $HolderVar = Read-Host -AsSecureString "Enter the Secrete/Password for Primary RADIUS($($PrimaryRADIUSObject.IPAddress)) server on $($AAA.NAME) AAA service"
                            $PrimaryRADIUSObject.Secret = $HolderVar
                            
                            $HolderVar = ""
                            while($HolderVar -ne "c" -and $HolderVar -ne "p" -and $HolderVar -ne "o")
                            {
                                Write-Host "`t`t c - Cloudpath SaaS server"
                                Write-Host "`t`t p - Cloudpath on-prem server"
                                Write-Host "`t`t o - Other AAA server"
                                $HolderVar = Read-Host -Prompt "`t`t Is $($AAA.NAME) ($($PrimaryRADIUSObject.IPAddress)) a cloud hosted Cloudpath server or on-prem Cloudpath server or other?"
                                $HolderVar = $HolderVar.ToLower()
                            }
                            if($HolderVar -imatch "c")
                            {
                                $PrimaryRADIUSObject.RadiusType = "Cloud"
                            }
                            elseif($HolderVar -imatch "p")
                            {
                                $PrimaryRADIUSObject.RadiusType = "Onprem"
                            }
                            else
                            {
                                $PrimaryRADIUSObject.RadiusType = "Other"
                            }

                            $AAA.PrimaryRADIUS = $PrimaryRADIUSObject
                            $StartPrimaryRADIUS = $false
                            break
                        }
                    }
                }
                elseif($StartSecondaryRADIUS)
                {
                    switch -Regex ($Line)
                    {
                        "^Status"
                        {
                            $Status = ($Line -split "Status(.*)=")[2].Trim()
                            $SecondaryRADIUSObject.Status = $Status
                            $AAA.SecondaryRADIUS = $SecondaryRADIUSObject
                            if($Status -imatch "Disabled")
                            {
                                $StartSecondaryRADIUS = $false
                            }
                            break
                        }
                        "^IP Address"
                        {
                            $IPAddress = ($Line -split "IP Address(.*)=")[2].Trim()
                            $SecondaryRADIUSObject.IPAddress = $IPAddress
                            $AAA.SecondaryRADIUS = $SecondaryRADIUSObject
                            break
                        }
                        "^Port"
                        {
                            $Port = ($Line -split "Port(.*)=")[2].Trim()
                            $SecondaryRADIUSObject.Port = $Port
                            $AAA.SecondaryRADIUS = $SecondaryRADIUSObject
                            break
                        }
                        "^Secret"
                        {
                            
                            Write-Host "`t`t Enter the Secrete/Password for Secondary RADIUS($($SecondaryRADIUSObject.IPAddress)) server on $($AAA.NAME) AAA service"
                            $HolderVar = Read-Host -AsSecureString "Enter the Secrete/Password for Secondary RADIUS($($SecondaryRADIUSObject.IPAddress)) server on $($AAA.NAME) AAA service"
                            $SecondaryRADIUSObject.Secret = $HolderVar
                            $HolderVar = ""
                            
                            while($HolderVar -ne "c" -and $HolderVar -ne "p" -and $HolderVar -ne "o")
                            {
                                Write-Host "`t`t c - Cloudpath Saas server"
                                Write-Host "`t`t p - Cloudpath on-prem server"
                                Write-Host "`t`t o - Other AAA server"
                                $HolderVar = Read-Host -Prompt "`t`t Is $($AAA.NAME) ($($SecondaryRADIUSObject.IPAddress)) a cloud hosted Cloudpath server or on-prem Cloudpath server or other?" 
                                $HolderVar = $HolderVar.ToLower()
                            }

                            
                            if($HolderVar -imatch "c")
                            {
                                $SecondaryRADIUSObject.RadiusType = "Cloud"
                            }
                            elseif($HolderVar -imatch "p")
                            {
                                $SecondaryRADIUSObject.RadiusType = "Onprem"
                            }
                            else
                            {
                                $SecondaryRADIUSObject.RadiusType = "Other"
                            }
                            
                            $AAA.SecondaryRADIUS = $SecondaryRADIUSObject
                            $StartSecondaryRADIUS = $false
                            break
                        }
                    }
                }
                elseif($StartRetryPolicy)
                {
                    switch -Regex ($Line)
                    {
                        "^Max\. Number of Retries"
                        {
                            $MaxNumberOfRetries = ($Line -split "Max\. Number of Retries(.*)=")[2].Trim()
                            $RetryPolicyObject.MaxNumberOfRetries = $MaxNumberOfRetries
                            $AAA.RetryPolicy = $RetryPolicyObject
                            break
                        }
                        "^Request Timeout"
                        {
                            $RequestTimeout = ($Line -split "Request Timeout(.*)=")[2].Trim()
                            $RetryPolicyObject.RequestTimeout = $RequestTimeout
                            $AAA.RetryPolicy = $RetryPolicyObject
                            break
                        }
                        "^Reconnect Primary"
                        {
                            $ReconnectPrimary = ($Line -split "Reconnect Primary(.*)=")[2].Trim()
                            $RetryPolicyObject.ReconnectPrimary = $ReconnectPrimary
                            $AAA.RetryPolicy = $RetryPolicyObject
                            break
                        }
                        "^Max\. Number of Consecutive Drop Packets"
                        {
                            $MaxNumberOfConsecutiveDropPackets = ($Line -split "Max\. Number of Consecutive Drop Packets(.*)=")[2].Trim()
                            $RetryPolicyObject.MaxNumberOfConsecutiveDropPackets = $MaxNumberOfConsecutiveDropPackets
                            $AAA.RetryPolicy = $RetryPolicyObject
                            break
                        }
                        ""
                        {
                            $StartRetryPolicy = $false
                        }
                    }
                }
                else
                {
                    switch -Regex ($Line)
                    {
                        "^Name"
                        {
                            $Name = ($Line -split "Name(.*)=")[2].Trim()
                            $AAA.Name = $Name
                            break
                        }
                        "^Type"
                        {
                            $Type = ($Line -split "Type(.*)=")[2].Trim()
                            $AAA.Type = $Type
                            if($Type -inotmatch "RADIUS server")
                            {
                                $startpoint = $false 
                            }

                            break
                        }
                        "^Auth Method"
                        {
                            $AuthMethod = ($Line -split "Auth Method(.*)=")[2].Trim()
                            $AAA.AuthMethod = $AuthMethod
                            break
                        }
                        "^IP Address"
                        {
                            $IPAddress = ($Line -split "IP Address(.*)=")[2].Trim()
                            $AAA.IPAddress = $IPAddress
                            break
                        }
                        "^Port"
                        {
                            $Port = ($Line -split "Port(.*)=")[2].Trim()
                            $AAA.Port = $Port
                            break
                        }
                        "^Windows Domain Name"
                        {
                            $WindowsDomainName = ($Line -split "Windows Domain Name(.*)=")[2].Trim()
                            $AAA.WindowsDomainName = $WindowsDomainName
                            break
                        }
                        "^Admin DN"
                        {
                            $AdminDN = ($Line -split "Admin DN(.*)=")[2].Trim()
                            $AAA.AdminDN = $AdminDN
                            break
                        }
                        "^DomainServer DeviceName"
                        {
                            $DomainServerDeviceName = ($Line -split "DomainServer DeviceName(.*)=")[2].Trim()
                            $AAA.DomainServerDeviceName = $DomainServerDeviceName
                            break
                        }
                        "^Admin Password"
                        {
                            $AdminPassword = ($Line -split "Admin Password(.*)=")[2].Trim()
                            $AAA.AdminPassword = $AdminPassword
                            break
                        }
                        "^encryption\-TLS"
                        {
                            $encryptionTLS = ($Line -split "encryption-TLS(.*)=")[2].Trim()
                            $AAA.encryptionTLS = $encryptionTLS
                            break
                        }
                        "^Primary RADIUS"
                        {
                            $StartPrimaryRADIUS = $true
                            $PrimaryRADIUSObject = New-Object -TypeName PSObject
                            $PrimaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value ""
                            $PrimaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "Port" -Value ""
                            $PrimaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "Secret" -Value ""
                            $PrimaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "RadiusType" -Value ""
                            break
                        }
                        "^Secondary RADIUS"
                        {
                            $StartSecondaryRADIUS = $true
                            $SecondaryRADIUSObject = New-Object -TypeName PSObject
                            $SecondaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "Status" -Value ""
                            $SecondaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value ""
                            $SecondaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "Port" -Value ""
                            $SecondaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "Secret" -Value ""
                            $SecondaryRADIUSObject | Add-Member -MemberType NoteProperty -Name "RadiusType" -Value ""
                            break
                        }
                        "^Retry Policy"
                        {
                            $StartRetryPolicy = $true
                            $RetryPolicyObject = New-Object -TypeName PSObject
                            $RetryPolicyObject | Add-Member -MemberType NoteProperty -Name "MaxNumberOfRetries" -Value ""
                            $RetryPolicyObject | Add-Member -MemberType NoteProperty -Name "RequestTimeout" -Value ""
                            $RetryPolicyObject | Add-Member -MemberType NoteProperty -Name "ReconnectPrimary" -Value ""
                            $RetryPolicyObject | Add-Member -MemberType NoteProperty -Name "MaxNumberOfConsecutiveDropPackets" -Value ""
                            break
                        }
                    }
                }
            }
        }

        $AAAs += $AAA
        return $AAAs
    }

    ZoneDirectorParse_10_4_1_0_257()
    {
        Write-Host "Parsing ZoneDirector Configuraitons"    
        $this.ZDParsedObjects = New-Object -TypeName PSObject

        $WLANGroups = $this.getWLANGroups()
        $WLANs = $this.getWLANs()
        $APGroups = $this.getAPGroups()
        $APs = $this.getAPs()
        $ACLs = $this.getACLs()
        $VLANPools = $this.getVLANPools()
        $AAAs = $this.getAAA()
        
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "WLANGroups" -Value $WLANGroups
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "WLANs" -Value $WLANs
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "APGroups" -Value $APGroups
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "APs" -Value $APs
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "ACLs" -Value $ACLs
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "VLANPools" -Value $VLANPools
        $this.ZDParsedObjects | Add-Member -MemberType NoteProperty -Name "AAAs" -Value $AAAs
        #Don't need DPSK list for 10.4 because of file upload to DPSK folder
    }
}

class ZoneDirector
{
    [PSCustomObject]getParse_10_4_1_0_257()
    {
        [ZoneDirectorParse_10_4_1_0_257]$parse = [ZoneDirectorParse_10_4_1_0_257]::new()
        return $parse.ZDParsedObjects
    }
    
    [String]getConfigFiles_10_4_1_0_257([String]$IP,[PSCredential]$Creds)
    {
        try
        {
           Import-Module .\Posh-SSH
        }
        catch 
        {
            $ErrorVar = $_

            if($ErrorVar.FullyQualifiedErrorId -match "ImportModuleCommand")
            {
                $path = "$(Get-Location)\Posh-SSH\3.0.0\Assembly\Newtonsoft.Json.dll"
                Unblock-File $path
                $path = "$(Get-Location)\Posh-SSH\3.0.0\Assembly\Renci.SshNet.dll"
                Unblock-File $path
                $path = "$(Get-Location)\Posh-SSH\3.0.0\Assembly\SshNet.Security.Cryptography.dll"
                Unblock-File $path
                Import-Module .\Posh-SSH
            }
            else
            {
                Write-Host $_
            }
        }

        Write-Host "Getting ZoneDirector Configuraitons"
        $WLANs = @()
        $AAAs = @()
        $L2ACLs = @()
        $L3ACLs = @()
        $APs = @()
        $APGroups = @()
        $VLANPools = @()
        $WLANGroups = @()
        $DPSKList = @()
        $SysInfo = @()
        
        try
        {
            If(Test-Connection -ComputerName $IP -Quiet)
            {
                $session = New-SSHSession -ComputerName $IP -Credential $Creds -AcceptKey -ErrorAction Stop
                $stream = $session.Session.CreateShellStream("test",4294967295,4294967295,4294967295,4294967295,2147483647)
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command "`n" | Out-Null
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "$($Creds.UserName)`n" | Out-Null
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "$($Creds.GetNetworkCredential().Password)" | Out-Null
                Start-Sleep 4
                $LoginStatus = $stream.read()
                $LoginStatus = ($LoginStatus -split "`n")[0].Trim()
                if($LoginStatus -imatch "Login incorrect")
                {
                    Remove-SSHSession -SessionId $session.SessionId | Out-Null
                    throw "WrongCredentials"
                }
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "en force `n" | Out-Null
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show sysinfo" -OutVariable SysInfo | Out-Null
                $SysInfoVersion = ($SysInfo[9] -split "(.*)=")[2].Trim()
                If($SysInfoVersion -imatch "10.4")
                {
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show wlan all `n" -OutVariable WLANs | Out-Null
                    While($WLANs[0] -inotmatch "WLAN Service:" -and $WLANs[-1] -inotmatch "ruckus#")
                    {
                    if($count -le 6)
                    {
                        Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show wlan all `n" -OutVariable WLANs | Out-Null
                        Start-Sleep $count
                        $count++
                    }
                    else
                    {
                        throw "WLAN"
                        break
                    }
                    }
                    
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show aaa all `n" -OutVariable AAAs | Out-Null
                    While($AAAs[0] -inotmatch "AAA:" -and $AAAs[-1] -inotmatch "ruckus#")
                    {
                    if($count -le 6)
                    {
                        Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show aaa all `n" -OutVariable AAAs | Out-Nulll
                        Start-Sleep $count
                        $count++
                    }
                    else
                    {
                        throw "AAA"
                        break
                    }
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show l2acl all" -OutVariable L2ACLs | Out-Null
                    While($L2ACLs[0] -inotmatch "L2/MAC ACL:")
                    {
                    if($count -le 6)
                    {
                        Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show l2acl all" -OutVariable L2ACLs | Out-Null
                        Start-Sleep $count
                        $count++
                    }
                    else
                    {
                        throw "L2ACL"
                        break
                    }
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show l3acl all" -OutVariable L3ACLs | Out-Null
                    #ZoneDirector Version 10.4.0.0.69 returns nothing when no l3acls are set so need the a answer check to catch if there is no L3 policies
                    $a = ""
                    While($L3ACLs[0] -inotmatch "L3/L4/IP ACL:" -and $a -ine "n")
                    {
                        
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show l3acl all" -OutVariable L3ACLs | Out-Null
                            Start-Sleep $count
                            $count++
                        }
                        else
                        {
                            throw "L3ACL"
                            break
                        }

                        if($L3ACLs[0] -inotmatch "L3/L4/IP ACL:")
                        {
                            $a = ""
                            while($a -ine "y" -and $a -ine "n")
                            {
                                $a = Read-Host "`t Is there L3 ACL policies that need migrated (y or n)"
                            }
                        }
                    }
                    

                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show ap all" | Out-Null
                    $APs = $stream.Read()
                    $APs  = $APs -split "`n"
                    While($APs[0] -inotmatch "AP:" -and $APs[-1] -inotmatch "ruckus#")
                    {
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show ap all" | Out-Null
                            Start-Sleep $count
                            $count++
                            $APs = $stream.Read()
                            $APs  = $APs -split "`n"
                        }
                        else
                        {
                            throw "AP"
                            break
                        }
                        
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show ap-group all" | Out-Null
                    $APGroups  = $stream.Read()
                    $APGroups  = $APGroups -split "`n"
                    While($APGroups[0] -inotmatch "APGROUP:" -and $APGroups[-1] -inotmatch "ruckus#")
                    {
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show ap-group all" | Out-Null
                            Start-Sleep $count
                            $count++
                            $APGroups  = $stream.Read()
                            $APGroups  = $APGroups -split "`n"
                        }
                        else
                        {
                            throw "APGroup"
                            break
                        }
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show vlan-pool all" -OutVariable VLANPools | Out-Null
                    While($VLANPools[0] -inotmatch "VLAN Pool:")
                    {
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show ap-group all" | Out-Null
                            Start-Sleep $count
                            $count++
                        }
                        else
                        {
                            throw "VLANPool"
                            break
                        }
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show wlan-group all" -OutVariable WLANGroups | Out-Null
                    While($WLANGroups[0] -inotmatch "WLAN Group:")
                    {
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show wlan-group all" -OutVariable WLANGroups | Out-Null
                            Start-Sleep $count
                            $count++
                        }
                        else
                        {
                            throw "WLANGroup"
                            break
                        }
                    }
        
                    $count = 2
                    Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show dynamic-psks" -OutVariable DPSKList | Out-Null
                    While($DPSKList[0] -inotmatch "Generated Dynamic PSKs:")
                    {
                        if($count -le 6)
                        {
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command  "show wlan-group all" -OutVariable WLANGroups | Out-Null
                            Start-Sleep $count
                            $count++
                        }
                        else
                        {
                            throw "DPSK"
                            break
                        }
                    }
        
        
                    New-Item -Path .\ZoneDirectorConfigs\WLANs.txt -ItemType file -Force | Out-Null
                    foreach($line in $WLANs)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\WLANs.txt -Value $line
                    }
                    
                    New-Item -Path .\ZoneDirectorConfigs\AAAs.txt -ItemType file -Force | Out-Null
                    foreach($line in $AAAs)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\AAAs.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\L2ACLs.txt -ItemType file -Force | Out-Null
                    foreach($line in $L2ACLs)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\L2ACLs.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\L3ACLs.txt -ItemType file -Force | Out-Null
                    foreach($line in $L3ACLs)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\L3ACLs.txt -Value $line
                    }
                    
                    New-Item -Path .\ZoneDirectorConfigs\APs.txt -ItemType file -Force | Out-Null
                    foreach($line in $APs)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\APs.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\APGroups.txt -ItemType file -Force | Out-Null
                    foreach($line in $APGroups)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\APGroups.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\VLANPools.txt -ItemType file -Force | Out-Null
                    foreach($line in $VLANPools)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\VLANPools.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\WLANGroups.txt -ItemType file -Force | Out-Null
                    foreach($line in $WLANGroups)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\WLANGroups.txt -Value $line
                    }
        
                    New-Item -Path .\ZoneDirectorConfigs\DPSKList.txt -ItemType file -Force | Out-Null
                    foreach($line in $DPSKList)
                    {
                        $line = $line.Trim()
                        Add-Content -Path .\ZoneDirectorConfigs\DPSKList.txt -Value $line
                    }
        
                    Remove-SSHSession -SessionId $session.SessionId | Out-Null
    
                    return "Success"
        
                }
                else
                {
                    Remove-SSHSession -SessionId $session.SessionId | Out-Null
                    throw "WrongVersion"
                }
            }
            else
            {
                throw "CannotPingZD"
            }
        }
        catch
        {
            $ErrorVar = $_

            if($ErrorVar.FullyQualifiedErrorId -imatch "SSH.NewSshSession")
            {
                return "WrongIP"
            }
            else
            {
                return $ErrorVar.FullyQualifiedErrorId
            }

        }
    }
}

class ZoneDirectorMigration
{
    [string]$ZDIP
    [PSCredential]$ZDCreds 
    [PSCustomObject]$ZDParsedObjects
    [Version]$Version = $PSVersionTable.PSVersion
    [Int32]$Width = $Host.UI.RawUI.WindowSize.Width
    [ZoneDirector]$ZD = [ZoneDirector]::new()
    

    ZoneDirectorMigration()
    {
            
        #Had to put blank file (BlankFile.txt) in DPSKs and ZoneDirectorConfigs folder because GitHub wouldn't upload a blank folder.
        #Below code removes file becasue script use no name specific content retrevial for DPSKs
        if(Get-ChildItem -Path .\DPSKs -Name "BlankFile.txt")
        {
            Remove-Item -Path .\DPSKs\BlankFile.txt
        }
        
        if(Get-ChildItem -Path .\ZoneDirectorConfigs -Name "BlankFile.txt")
        {
            Remove-Item -Path .\ZoneDirectorConfigs\BlankFile.txt
        }


        try
        {    
            
            $ToolPrompt1 = "Welcome to RUCKUS ZoneDirector Configuration Migration Script"
            $ToolPrompt2 = "This IS NOT an offical tool of RUCKUS"
            $ToolPrompt3 = "created by Dayne Conner a RUCKUS SE"

            $FullStarLine = "*" * $this.Width
            $BlankPrompt = " " * $ToolPrompt1.Length
            $ReducedStarsCount1 = ($this.Width - $ToolPrompt1.Length)/2
            $WhiteSpaceCount1 = $ReducedStarsCount1/2
            $ReducedStars1 = "*" * ($ReducedStarsCount1 - $WhiteSpaceCount1)
            $WhiteSpace1 = " " * $WhiteSpaceCount1
            $PromptLine1 = $ReducedStars1 + $WhiteSpace1 + $ToolPrompt1 + $WhiteSpace1 + $ReducedStars1                     
            $BlankLine = $ReducedStars1 + $WhiteSpace1 + $BlankPrompt + $WhiteSpace1 + $ReducedStars1
            
            
            $Diff1 = $ToolPrompt1.Length - $ToolPrompt2.Length
            $ReducedStarsCount2 = ($this.Width - $ToolPrompt2.Length)/2
            $WhiteSpaceCount2 = $Diff1 + 3
            $ReducedStars2 = "*" * ($ReducedStarsCount2 - $WhiteSpaceCount2)
            $WhiteSpace2 = " " * $WhiteSpaceCount2
            $PromptLine2 = $ReducedStars1 + $WhiteSpace2 + $ToolPrompt2 + $WhiteSpace2 + $ReducedStars1

            $Diff3 = $ToolPrompt1.Length - $ToolPrompt3.Length
            $ReducedStarsCount3 = ($this.Width - $ToolPrompt3.Length)/2
            $WhiteSpaceCount3 = $Diff3 + 2
            $ReducedStars3 = "*" * ($ReducedStarsCount3 - $WhiteSpaceCount3)
            $WhiteSpace3 = " " * $WhiteSpaceCount3
            $PromptLine3 = $ReducedStars1 + $WhiteSpace3 + $ToolPrompt3 + $WhiteSpace3 + $ReducedStars1



            Write-Host $FullStarLine
            Write-Host $FullStarLine
            Write-Host $BlankLine
            Write-Host $PromptLine1
            Write-Host $PromptLine3
            Write-Host $BlankLine
            Write-Host $BlankLine
            Write-Host $PromptLine2
            Write-Host $BlankLine
            Write-Host $FullStarLine
            Write-Host $FullStarLine
        }
        catch
        {
            Write-Host "***************"
            Write-Host "***************"
            Write-Host "Welcome to RUCKUS ZoneDirector Configuration Migration Tool"
            Write-Host "created by Dayne Conner a RUCKUS SE"
            Write-Host ""
            Write-Host ""
            Write-Host "This IS NOT an offical tool of RUCKUS"
            Write-Host "***************"
            Write-Host "***************"
        
        }

        
        if($this.Version.Major -lt 5)
        {
             if($this.Version.Minor -lt 1)
             {
                 if($this.Version.Build -lt 19041)
                 {
                     Write-Host "`r`r"
                     Write-Host "WARNING --- The running PowerShell Version is not 5.1.19041 or newer. There is no guarantee the script will run properly. --- WARNING"
                 }
             }
        }
        
        Write-Host "`r`r"
        $a = $null
        while($a -ne 1 -and $a -ne 2)
        {
            Write-Host "1: Migrate ZoneDirector configuration to Cloud Controller"
            #Write-Host "2: Migrate ZoneDirector configuration to SmartZone Controller"
            Write-Host "2: Close tool"
            $a = Read-Host -Prompt "Select one of the above Options: (1/2)"
        }
        
        if($a -eq 1)
        {
            $a = $null
            Write-Host "`r`r"
            While($a -ne 1)
            {
                Write-Host "Check your ZoneDirector version and select the correct version below"
                Write-Host "1: 10.4"
                $a = Read-Host -Prompt "Select one of the above Options: (1)"
            }

            if($a -eq 1)
            {
                
                $ErrorCheck = $true
                While($ErrorCheck)
                {
                    Write-Host "`r`r"
                    Write-Host "What You Need:"
                    Write-Host "`t 1: SSH network access to ZoneDirector controller"
                    Write-Host "`t 2: SSH network access to all ZoneDirector APs"
                    Write-Host "`t 3: HTTPS network access to Cloud controller"
                    Write-Host "`t 4: admin username and password for ZoneDirector controller"
                    Write-Host "`t 5: admin username and password for Cloud controller (Prime User)"
                    Write-Host "`t 6: cloud licenses need to be activated on Cloud Controller"
                    Write-Host "`t ** if AAA serverices are configrued, know if it is Cloudpath SaaS, Cloudpath on-premise, or third-party AAA server"
                    Write-Host "`t ** if DPSK is configured, download DPSK key list from ZoneDirector controller and upload to DPSKs folder"
                    Read-Host -Prompt "When ready hit Enter"
                    
                    Write-Host "`r`r"
                    Write-Host "Beginning ZoneDirector to Cloud Controller Migration"
                    $this.ZDIP = Read-Host -Prompt "Enter the IP address of the ZoneDirector"
                    Write-Host "Enter the admin credentials for the ZoneDirector"
                    $this.ZDCreds = Get-Credential -Message "ZoneDirector Admin Credentials"
                    $ErrorVar = $this.ZD.getConfigFiles_10_4_1_0_257($this.ZDIP,$this.ZDCreds)
                    $ErrorVar = "Success"
                    if($ErrorVar -imatch "Success")
                    {
                        $ErrorCheck = $false
                        $this.ZDParsedObjects = $this.ZD.getParse_10_4_1_0_257()
                    }
                    elseif($ErrorVar -imatch "")
                    {
                        Write-Host "`nError: $ErrorVar"
                    }
                }
                
                $ErrorCheck = $true
                While($ErrorCheck)
                {
                    [CloudController]$CC = [CloudController]::new()


                    Write-Host "Enter the admin credentials for the Cloud Controller"
                    $CloudCreds = Get-Credential -Message "Cloud Controller Prime Admin Credentials"
                    $ErrorCheck = $CC.getAPIToken($CloudCreds)
                    if($ErrorCheck -eq "Success")
                    {
                        $ErrorCheck = $false
                        $CC.setConfiguraiton_21_01_11($this.ZDParsedObjects,$this.ZDCreds,$this.ZDIP)
                    }
                    else
                    {
                        Write-Host "Error: $ErrorCheck"
                    }
                }
            }
        }
        <#
        if($a -eq 2)
        {
            #Need to remove once SmartZone Code is done
            Write-Host "`r`r"
            Write-Host "Code to support SmartZone Migraiton isn't completed yet"
            $this.endMigration()
        }
        #>
        elseif($a -eq 2)
        {
            $a = $null
            $this.endMigration()
        }
    }        

    endMigration()
    {
        Write-Host "`r`r"
        Write-Host "Ending migration and closing tool"
        exit
    }

}


[ZoneDirectorMigration]$ZM = [ZoneDirectorMigration]::new()
Remove-Variable -Name ZM