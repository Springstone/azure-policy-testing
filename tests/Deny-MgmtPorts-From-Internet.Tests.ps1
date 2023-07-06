Import-Module -Name Az.Network
Import-Module -Name Az.Resources
Import-Module "$($PSScriptRoot)/../utils/Policy.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Rest.Utils.psm1" -Force
#Import-Module "$($PSScriptRoot)/../utils/RouteTable.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Test.Utils.psm1" -Force

Describe "Testing policy 'Deny-MgmtPorts-From-Internet'" -Tag "deny-mgmtports-from-internet" {
    # Create or update NSG is actually the same PUT request, hence testing create covers update as well.
    Context "When NSG is created or updated" -Tag "deny-mgmtports-from-internet-nsg-port" {
        It "Should deny non-compliant port '3389'" -Tag "deny-route-nexthopvirtualappliance-nsg-port-10" {
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

        It "Should deny non-compliant port '3389' inline" -Tag "deny-route-nexthopvirtualappliance-nsg-port-10" {
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

        It "Should deny non-compliant port '22'" -Tag "deny-route-nexthopvirtualappliance-nsg-port-20" {
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

        It "Should deny non-compliant port ranges" -Tag "deny-route-nexthopvirtualappliance-nsg-port-30" {
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
                        -DestinationPortRange "21-23,3389" # Incompliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Throw "*disallowed by policy*"
            }
        }

        It "Should allow compliant port ranges" -Tag "deny-route-nexthopvirtualappliance-nsg-port-40" {
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
                        -Description "Allow Web" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange "80,443" # Compliant.
                    | Set-AzNetworkSecurityGroup
                } | Should -Not -Throw
            }
        }
    }
}