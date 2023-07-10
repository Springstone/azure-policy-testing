Import-Module -Name Az.Network
Import-Module -Name Az.Resources
Import-Module "$($PSScriptRoot)/../utils/Policy.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Rest.Utils.psm1" -Force
#Import-Module "$($PSScriptRoot)/../utils/RouteTable.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Test.Utils.psm1" -Force

Describe "Testing policy 'Deny-MgmtPorts-From-Internet'" -Tag "deny-mgmtports-from-internet" {
    # Create or update NSG is actually the same PUT request, hence testing create covers update as well.
    Context "When NSG is created or updated" -Tag "deny-mgmtports-from-internet-nsg-port" {
        It "Should deny non-compliant port '3389'" -Tag "deny-noncompliant-nsg-port-10" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name RDP-rule `
                        -Description "Allow RDP" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 3389 # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should deny non-compliant port '3389' inline" -Tag "deny-noncompliant-nsg-port-20" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                # Should be disallowed by policy, so exception should be thrown.
                {
                    New-AzNetworkSecurityGroup `
                        -Name "nsg-test" `
                        -ResourceGroupName $ResourceGroup.ResourceGroupName `
                        -Location $ResourceGroup.Location | Add-AzNetworkSecurityRuleConfig `
                        -Name RDP-rule `
                        -Description "Allow RDP" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 3389 # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should deny non-compliant port '22'" -Tag "deny-noncompliant-nsg-port-30" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name SSH-rule `
                        -Description "Allow SSH" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 22 # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should deny non-compliant port ranges (21-23)" -Tag "deny-noncompliant-nsg-port-40" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name SSH-rulePlus `
                        -Description "Allow Mgmt" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange "21-23" # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should allow compliant ports (443)" -Tag "allow-compliant-nsg-port-10" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name web-rule `
                        -Description "Allow Web" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 443 # Compliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Not -Throw
            }
        }

        It "Should deny non-compliant port ranges (Test)" -Tag "deny-noncompliant-nsg-port-50" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name RDP-rule `
                        -Description "Allow Mgmt" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange "22-3390" # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should deny non-compliant port range (Array)" -Tag "deny-noncompliant-nsg-port-60" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                -Name "nsg-test2" `
                -ResourceGroupName $ResourceGroup.ResourceGroupName `
                -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $networkSecurityGroup | Add-AzNetworkSecurityRuleConfig `
                        -Name Web-rule `
                        -Description "Allow Web2" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 300 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 443 
                    | Add-AzNetworkSecurityRuleConfig `
                        -Name SSH-rule `
                        -Description "Allow Mgmt2" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 310 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange "21-23" # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should deny non-compliant port ranges (Array) - API" -Tag "deny-noncompliant-nsg-port-70" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $payload = @"
{
    "properties": {
        "securityRules": [
            {
                "name": "Web-rule",
                "properties": {
                    "description": "Allow Web2",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "443",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 300,
                    "direction": "Inbound"
                }
            },
            {
                "name": "Multi-rule",
                "properties": {
                    "description": "Allow Mgmt3",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRanges": ["23","3388-3390","8080"],
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 310,
                    "direction": "Inbound"
                }
            }
        ]
    },
    "location": "uksouth"
}
"@

                    $httpResponse = Invoke-AzRestMethod `
                        -ResourceGroupName $ResourceGroup `
                        -ResourceProviderName "Microsoft.Network" `
                        -ResourceType "networkSecurityGroups" `
                        -Name "testNSG99" `
                        -ApiVersion "2022-11-01" `
                        -Method "PUT" `
                        -Payload $payload
            
                if ($httpResponse.StatusCode -eq 200 -or $httpResponse.StatusCode -eq 201) {
                    # NSG created
                }
                # Error response describing why the operation failed.
                else {
                    throw "Operation failed with message: '$($httpResponse.Content)'"
                }              
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should allow compliant port ranges (Array) - API" -Tag "allow-compliant-nsg-port-20" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $portRanges =  @("23","3388-3390","8080")

                # Create Payload for NSG
                $securityRules = @(
                    @{
                        name = "Web-rule"
                        properties = @{
                            description = "Allow Web2"
                            protocol = "Tcp"
                            sourcePortRange = "*"
                            destinationPortRange = "443"
                            sourceAddressPrefix = "*"
                            destinationAddressPrefix = "*"
                            access = "Allow"
                            priority = 300
                            direction = "Inbound"
                        }
                    },
                    @{
                        name = "Multi-rule"
                        properties = @{
                            description = "Allow Mgmt3"
                            protocol = "Tcp"
                            sourcePortRange = "*"
                            destinationPortRanges = $portRanges
                            sourceAddressPrefix = "*"
                            destinationAddressPrefix = "*"
                            access = "Allow"
                            priority = 310
                            direction = "Inbound"
                        }
                    }
                )

                $object = @{
                    properties = @{
                        securityRules = $securityRules
                    }
                    location = "uksouth"
                }

                $payload = ConvertTo-Json -InputObject $object -Depth 100

                # Should be disallowed by policy, so exception should be thrown.
                {
                    $httpResponse = Invoke-AzRestMethod `
                        -ResourceGroupName $ResourceGroup `
                        -ResourceProviderName "Microsoft.Network" `
                        -ResourceType "networkSecurityGroups" `
                        -Name "testNSG99" `
                        -ApiVersion "2022-11-01" `
                        -Method "PUT" `
                        -Payload $payload
            
                if ($httpResponse.StatusCode -eq 200 -or $httpResponse.StatusCode -eq 201) {
                    # NSG created
                }
                # Error response describing why the operation failed.
                else {
                    throw "Operation failed with message: '$($httpResponse.Content)'"
                }              
                } | Should Not -Throw
            }
        }
    }
}