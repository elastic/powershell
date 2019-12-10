# Simple script to prepare Elastic.Console for publishing
param(
    [string]
    [Parameter(Mandatory = $true)]
    $Version,

    [string]
    [Parameter()]
    $Prerelease = "",

    [string]
    [Parameter()]
    $ReleaseNotes,

    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    [Parameter()]
    $Certificate
)

function Log {
    param(
        [string]
        $Message
    )

    $FormattedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogMessage = "[$FormattedDate] $Message"

    Write-Output $LogMessage
}

$manifest = "./Elastic.Console/Elastic.Console.psd1"
Log "Updating $manifest"
if (-not $ReleaseNotes) {
    $ReleaseNotes = "Update to version $Version"
}

$updates = @{
    Path = $manifest
    ModuleVersion = $Version
    ReleaseNotes = $ReleaseNotes
    Prerelease = $Prerelease
    RequireLicenseAcceptance = $false
}

Update-ModuleManifest @updates

$module = "./Elastic.Console/Elastic.Console.psm1"
Log "Updating $module"
(Get-Content $module) -replace 'Set-ElasticsearchVersion -Version "(.*?)"',"Set-ElasticsearchVersion -Version `"$Version`"" | Set-Content -Path $module

Log "Creating autocompletion file for version $Version"
Import-Module $manifest -Force
Set-ElasticsearchVersion $Version
Remove-Module Elastic.Console

Log "Removing all files under ./Elastic.Console/specs except autocomplete.json for version $Version"
Get-ChildItem ./Elastic.Console/specs/* | ForEach-Object {   
    if ($_.Name -eq $Version) {
        $files = Get-ChildItem $_ | Where-Object { $_.Name -ne 'autocomplete.json' }
        $files | Remove-Item -Recurse -Force
    } else {
        Remove-Item $_ -Recurse -Force
    }
}

if ($Certificate) {
    Log "Signing $module with passed certificate $($cert.Subject)"
    Set-AuthenticodeSignature -FilePath $module -Certificate $Certificate

    Log "Checking signature"
    Get-AuthenticodeSignature -FilePath $module
    Log "Done. ready for publishing"

} else {
    Log "Done. Scripts should be signed for publishing with a Code Signing Certificate"
}



