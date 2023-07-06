Import-Module -Name Az.Network
Import-Module -Name Az.Resources
Import-Module "$($PSScriptRoot)/../utils/Policy.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Rest.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/RouteTable.Utils.psm1" -Force
Import-Module "$($PSScriptRoot)/../utils/Test.Utils.psm1" -Force

Describe "Testing policy 'Deny-MgmtPorts-From-Internet'" -Tag "deny-mgmtports-from-internet" {
    # Create or update route is actually the same PUT request, hence testing create covers update as well.
    # PATCH requests are currently not supported in Network Resource Provider.
    # See also: https://docs.microsoft.com/en-us/rest/api/virtualnetwork/routes/createorupdate
    Context "When NSG is created or updated" -Tag "deny-mgmtports-from-internet-nsg-port" {
        It "Should deny incompliant port '3389'" -Tag "deny-route-nexthopvirtualappliance-nsg-port-3389" {
            AzTest -ResourceGroup {
                param($ResourceGroup)

                $networkSecurityGroup = New-AzNetworkSecurityGroup `
                    -Name "nsg-test" `
                    -ResourceGroupName $ResourceGroup.ResourceGroupName `
                    -Location $ResourceGroup.Location

                # Should be disallowed by policy, so exception should be thrown.
                {
                    # Directly calling REST API with PUT routes, since New-AzRouteConfig/Set-AzRouteTable will issue PUT routeTables.
                    Set-AzNetworkSecurityRuleConfig `
                        -Name RDP-rule `
                        -NetworkSecurityGroup $networkSecurityGroup `
                        -Description "Allow RDP" `
                        -Access Allow `
                        -Protocol Tcp `
                        -Direction Inbound `
                        -Priority 200 `
                        -SourceAddressPrefix * `
                        -SourcePortRange * `
                        -DestinationAddressPrefix * `
                        -DestinationPortRange 3389 # Incompliant.
                    
                    Set-AzNetworkSecurityGroup -NetworkSecurityGroup $networkSecurityGroup
                } | Should -Throw "*RequestDisallowedByPolicy*Deny-MgmtPorts-From-Internet*"
            }
        }
    }
}