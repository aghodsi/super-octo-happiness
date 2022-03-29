
function GetAuditEntries {
    param (
    )    
    #https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#setup-app-only-authentication for ideal situation
    
    Connect-ExchangeOnline -UserPrincipalName 'ADMIN/SERVICEPRINCIPAL'
    #format mm/dd/yyy
    $startDate = '02/24/2022'
    $endDate = '03/29/2022'
    $targetedUsers = GetUsersFromAAD -countryFilter 'United States'
    $joinedUserPrincipals = [String]::Join(',', ($targetedUsers | Select-Object UserPrincipalName | ForEach-Object -Process { Write-Output $_.UserPrincipalName }))
    # adjust recordtype to what you'd like to get. For a list: https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide#audited-activities
    # https://docs.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog?view=exchange-ps
    $auditlogFiltered = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -RecordType 'AzureActiveDirectory' -UserIds $joinedUserPrincipals | Select-Object 'AuditData' | Foreach-Object { $_.AuditData }
    return $auditlogFiltered
}

function GetUsersFromAAD {
    param (
        [string]$countryFilter = 'United States'
    )
    #Connect-AzAccount
    return Get-AzADUser -Filter "startsWith(Country, '$countryFilter')"
}

# https://docs.microsoft.com/en-us/rest/api/eventhub/send-event
# https://docs.microsoft.com/en-us/rest/api/eventhub/generate-sas-token#powershell

function PostMessageToEventhub {
    param(
        [Parameter(Mandatory = $true)]
        [string] $namespace,

        [Parameter(Mandatory = $true)]
        [string] $hubname,

        [Parameter(Mandatory = $true)]
        [string] $accessPolicyName,

        [Parameter(Mandatory = $true)]
        [string] $primaryKeyforAccessPolicy,

        [Parameter(Mandatory = $true)]
        [string] $msg
    )
    
    
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | out-null
    
    # Get address
    $URI = "{0}.servicebus.windows.net/{1}" -f @($namespace, $hubname)
    $Access_Policy_Name = $accessPolicyName
    $Access_Policy_Key = $primaryKeyforAccessPolicy
    #Token expires now+300
    $Expires = ([DateTimeOffset]::Now.ToUnixTimeSeconds()) + 300
    $SignatureString = [System.Web.HttpUtility]::UrlEncode($URI) + "`n" + [string]$Expires
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $HMAC.key = [Text.Encoding]::ASCII.GetBytes($Access_Policy_Key)
    $Signature = $HMAC.ComputeHash([Text.Encoding]::ASCII.GetBytes($SignatureString))
    $Signature = [Convert]::ToBase64String($Signature)
    $SASToken = "SharedAccessSignature sr=" + [System.Web.HttpUtility]::UrlEncode($URI) + "&sig=" + [System.Web.HttpUtility]::UrlEncode($Signature) + "&se=" + $Expires + "&skn=" + $Access_Policy_Name

    # Create header
    $headers = @{
        "Authorization"  = $SASToken
        "Content-Type"   = "application/atom+xml;type=entry;charset=utf-8"; # must be this
    }

    # Use post method
    $method = "POST"

    # Rest api destination
    $dest = 'https://' + $URI + '/messages'

    
    # Call rest api
    $callResult = 0
    Invoke-RestMethod -Uri $dest -SkipHeaderValidation -StatusCodeVariable "callResult"  -Method $method -Headers $headers -Body $msg | Out-Null
    Write-Host "Tried writing $msg to event hub at $dest. Status code: $callResult"
}

# uncomment if not present
#Install-Module -Name Az -Force
#Install-Module ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
Import-Module Az 

$AccessPolicyName = "Name of your access policy"
$AccessPolicyKey = "the primary key of your policy"
$nameSpace = "the eventhub you created (namespace)"
$eventhub = "eventhub with partition within eventhub"
$auditEntries = GetAuditEntries
Write-Host "Audit events: $auditEntries"
$auditlogFiltered = $auditEntries | ForEach-Object {PostMessageToEventhub -namespace $nameSpace -hubname $eventhub -accessPolicyName $AccessPolicyName -primaryKeyforAccessPolicy $AccessPolicyKey -msg $_}



