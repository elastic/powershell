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
    $ReleaseNotes
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

Log "Removing all files under ./Elastic.Console/specs"
Remove-Item ./Elastic.Console/specs/* -Recurse -Force -ErrorAction Ignore

Log "Creating autocompletion file for version $Version"
Import-Module ./Elastic.Console/Elastic.Console.psd1 -Force
Set-ElasticsearchVersion $Version
Remove-Module Elastic.Console

Log "Removing REST API spec files other than autocomplete.json"
Remove-Item ./Elastic.Console/specs/* -Recurse -Force -Exclude "autocomplete.json"

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
Log "Done. Ready to publish"
