# Simple script to test Elastic.Console. Requires docker to run Elasticsearch
param(
    [string]
    [Parameter(Mandatory = $true)]
    $Version

)

$pesterVersion = "5.0.3"
$pester = Get-Module Pester | Where-Object { $_.Version  -eq $pesterVersion }
if (!($pester)) {
    Install-Module Pester -RequiredVersion $pesterVersion -Force -SkipPublisherCheck
}

Import-Module Pester -Version $pesterVersion
Import-Module -Name ./tests/elasticsearch.ps1 -Force | Out-Null

$pesterParameters = @{
    Path = "./tests/*.tests.ps1"
    Show = "All"
}

# skip ga release tests for versions that look like prereleases
if ($Version -match '-') {
    $pesterParameters.ExcludeTagFilter = "ga"
}

try {
    Invoke-Pester @pesterParameters
} finally {
    Stop-Elasticsearch
}


