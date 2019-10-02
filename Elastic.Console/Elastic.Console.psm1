# Register-ArgumentCompleter needs minimum v3.0
Set-StrictMode -Version 3.0

#load types used by the module
if (-not ([System.Management.Automation.PSTypeName]'Elastic.ElasticsearchRequestBody').Type) {
    # A type to accept only string or hashtable as input.
    # This allows $Body in Invoke-Elasticsearch to *not* bind to ElasticsearchRequest
    Add-Type -LiteralPath (Join-Path $PSScriptRoot -ChildPath "ElasticsearchRequestBody.cs")
}

if (-not ([System.Management.Automation.PSTypeName]'Elastic.ElasticVersion').Type) {
    # A type to represent an Elasticsearch version
    Add-Type -LiteralPath (Join-Path $PSScriptRoot -ChildPath "ElasticVersion.cs")
}

if (-not ([System.Management.Automation.PSTypeName]'Elastic.ServerCertificateValidation').Type) {
    # A type for skipping Certificate validation. There is a bug in some versions of PowerShell
    # where using a script block does not work, but using a class does.
    Add-Type -LiteralPath (Join-Path $PSScriptRoot -ChildPath "ServerCertificateValidation.cs")
}

# module scope variables
$Script:completerComponents = $null
$Script:version = $null
$Script:methods = @("GET", "PUT", "POST", "DELETE", "HEAD")

$forwardSlashChar = @('/')

# Rely on the OS default for valid SSL/TLS protocols
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::SystemDefault

# Disable nagling and expect 100 continue. Only valid for PowerShell versions
# where ServicePointManager is used i.e. PowerShell not based on .NET Core and NetStandard
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

<#
.Synopsis
    Tests if there is anything in the pipeline
#>
function Test-Any() {
    Begin {
        $any = $false
    }
    Process {
        $any = $true
    }
    End {
        $any
    }
}

<#
.Synopsis
    Gets the version of Elasticsearch with which to work
.Description
    Gets the version of Elasticsearch with which to work. Use the -Installed parameter to list
    Elasticsearch versions for which specs are installed.
.Parameter ListAvailable
    Lists the Elasticsearch versions for which specs have been downloaded, in descending version order.
    A version with downloaded specs does not require downloading files when using Set-ElasticsearchVersion
    to power tab completion.
.Example
    PS> Set-ElasticsearchVersion 6.2.0
    PS> Get-ElasticsearchVersion

    Sets the Elasticsearch version to 6.2.0, then retrieves the set version
.Example
    PS> Get-ElasticsearchVersion -ListAvailable

    Lists the Elasticsearch versions for which specs have been downloaded
.Example
    PS> Get-ElasticsearchVersion -ListAvailable | Select-Object -First 1 | Set-ElasticsearchVersion

    Lists the Elasticsearch versions for which specs have been downloaded, selecting the latest
    version downloaded, and setting this as the version of Elasticsearch to work with
#>
function Get-ElasticsearchVersion {
    [CmdletBinding()]
    param(
        [switch]
        [Parameter()]
        $ListAvailable
    )

    if ($ListAvailable) {
        $specsDir = (Join-Path $PSScriptRoot -ChildPath "specs")
        Get-ChildItem $specsDir -Directory -Name | ForEach-Object {
            $version = $null
            [Elastic.ElasticVersion]::TryParse($_, [ref]$version) | Out-Null
            $version
        } | Where-Object { $null -ne $_ } | Sort-Object -Descending
    } else {
        $Script:Version
    }
}

<#
.Synopsis
    Sets the version of Elasticsearch with which to work.
.Description
    Downloads the REST API specs for a specific version of Elasticsearch, using the
    API paths in the specification to power tab completion on paths
.Parameter Version
    The Elasticsearch version
.Parameter Force
    Forces the REST API specs to be downloaded, overwriting any existing
    specs for the version, and regenerating the file to power tab completion on paths
.Example
    PS> Set-ElasticsearchVersion 6.2.0

    Sets the version of Elasticsearch to 6.2.0
.Example
    PS> Set-ElasticsearchVersion -Version 7.0.0-beta1 -Force

    Sets the version of Elasticsearch to 7.0.0-beta1, overriding any existing downloaded
    files for the version
.Example
    PS> Set-ElasticsearchVersion 6.2

    Sets the version of Elasticsearch to 6.2.0. An omitted patch version part will have
    the value 0 by default
.Example
    PS> Set-ElasticsearchVersion 6

    Sets the version of Elasticsearch to 6.0.0. Omitted minor and patch version parts will have
    the value 0 by default
#>
function Set-ElasticsearchVersion {
    [CmdletBinding()]
    param(
        [Elastic.ElasticVersion]
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        $Version,

        [Parameter()]
        [switch]
        $Force
    )

    Begin {
    }

    Process {
        if ($Version -eq $Script:version -and -not $Force) {
            return
        }

        $Script:Version = $Version
        $Script:completerComponents = $null

        $specsDir = (Join-Path $PSScriptRoot -ChildPath "specs")
        if (-not (Test-Path $specsDir)) {
            New-Item -Path $specsDir -ItemType Directory | Out-Null
        }

        $versionDir = (Join-Path $specsDir -ChildPath ($Version.ToString()))
        if (-not (Test-Path $versionDir)) {
            New-Item -Path $versionDir -ItemType Directory | Out-Null
        }

        $autocompleteFileName = "autocomplete.json"
        $autocompleteFile = (Join-Path $versionDir -ChildPath $autocompleteFileName)

        # Get the REST API specs from GitHub for the Elasticsearch version
        if (-not (Test-Path $autocompleteFile) -or $Force) {

            $contentsApi = "https://api.github.com/repos/elastic/elasticsearch/contents"
            $specUrls = @("$contentsApi/rest-api-spec/src/main/resources/rest-api-spec/api?ref=v$Version")

            # Get the REST API specs for Elastic Stack Feature/X-Pack endpoints too, when available
            if ($Version -ge "6.3.0") {
                $specUrls += "$contentsApi/x-pack/plugin/src/test/resources/rest-api-spec/api?ref=v$Version"
            }

            $downloadurls = $specUrls | Foreach-Object  {
                Invoke-RestMethod $_ | Where-Object { $_.name.EndsWith(".json") } | Foreach-Object { $_.download_url }
            }

            # TODO: optimize by downloading in parallel
            for ($i = 0; $i -lt $downloadurls.count; $i++) {
                $downloadurl = $downloadurls[$i]
                $file = Split-Path $downloadurl -Leaf
                $outfile = Join-Path $versionDir -ChildPath $file

                Write-Progress -Activity "Downloading REST API specs for Elasticsearch $Version" -Status "Downloading $file" `
                    -PercentComplete ($i / $downloadurls.Count * 100)

                (New-Object System.Net.WebClient).DownloadFile($downloadurl, $outfile)
            }

            $excludeSpecs = @($autocompleteFileName, "_common.json")
            $specs = Get-ChildItem $versionDir -File -Filter *.json | Where-Object { $excludeSpecs -notcontains $_.Name } | ForEach-Object { $_.FullName }
            $apiCompleters = @()
            $pathCompleters = New-Object System.Collections.ArrayList

            foreach($spec in $specs) {
                $json = Get-Content $spec -Raw | ConvertFrom-Json
                $api = $json.PsObject.Properties | Select-Object -First 1

                # skip specs where the first key/value isn't an object
                if (-not ($api.Value -is [string])) {
                    $name = $api.Name

                    if ($api.Value.PsObject.Properties.Name -contains "methods") {
                        # old REST api spec format that lists methods at the top level
                        $methods = $api.Value.methods
                        $url = $api.Value.url

                        foreach($path in $url.paths) {
                            $apiCompleter = @{
                                name = $name
                                path = $path
                                parts = $path.Split($forwardSlashChar, [System.StringSplitOptions]::RemoveEmptyEntries)
                                methods = $methods
                            }

                            $apiCompleters += $apiCompleter

                            for ($i = 0; $i -lt $apiCompleter.parts.Length; $i++) {
                                if (($pathCompleters.Count - 1) -lt $i) {
                                    [void]$pathCompleters.Add($(New-Object System.Collections.Generic.HashSet[string]))
                                }

                                [void]$pathCompleters[$i].Add($apiCompleter.parts[$i])
                            }
                        }
                    } else {
                        # newer REST api spec format that lists methods against paths
                        $url = $api.Value.url

                        foreach($path in $url.paths) {
                            $apiCompleter = @{
                                name = $name
                                path = $path.path
                                parts = $path.path.Split($forwardSlashChar, [System.StringSplitOptions]::RemoveEmptyEntries)
                                methods = $path.methods
                            }

                            $apiCompleters += $apiCompleter

                            for ($i = 0; $i -lt $apiCompleter.parts.Length; $i++) {
                                if (($pathCompleters.Count - 1) -lt $i) {
                                    [void]$pathCompleters.Add($(New-Object System.Collections.Generic.HashSet[string]))
                                }

                                [void]$pathCompleters[$i].Add($apiCompleter.parts[$i])
                            }
                        }
                    }
                }
            }

            # $pathCompleters must be an array rather than an ArrayList. With the latter,
            # No autocompletion with urlCompleter after downloading REST specs otherwise
            $Script:completerComponents = @{
                apiCompleters = $apiCompleters
                pathCompleters = $pathCompleters.ToArray()
            }

            ConvertTo-Json -InputObject $Script:completerComponents -Compress -Depth 3 | Set-Content $autocompleteFile
        }

        if ($null -eq $Script:completerComponents) {
            $Script:completerComponents = Get-Content $autocompleteFile -Raw | ConvertFrom-Json
        }

        $uriCompleter = {
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $uriAndQuery = $wordToComplete.Trim('"').Split('?')
            $wordToComplete = $uriAndQuery[0]

            if ($uriAndQuery.Length -gt 1) {
                $query = $uriAndQuery[1]
            } else {
                $query = $null
            }

            # if the Uri contains an authority, this should be prepended to any autocompletion results.
            # if it doesn't, the Uri should be normalized to start with forward slash to match paths in REST API specs
            $parsedUri = $null
            $authority = $null
            $validUri = [Uri]::TryCreate($wordToComplete, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri)
            if ($validUri -and $parsedUri.IsAbsoluteUri) {
                $authority = $parsedUri.GetLeftPart([UriPartial]::Authority)
                $toComplete = [System.Web.HttpUtility]::UrlDecode($parsedUri.AbsolutePath)
            } else {
                if ($wordToComplete.StartsWith("/")) {
                    $toComplete = $wordToComplete
                } else {
                    $toComplete = "/" + $wordToComplete
                }
            }

            # Filter suggested APIs by passed Method
            $method = $fakeBoundParameters.ContainsKey("Method")
            if ($method) {
                $apis = ($Script:completerComponents).apiCompleters | Where-Object { $_.methods -contains "$($fakeBoundParameters.Method)" }
            } else {
                $apis = ($Script:completerComponents).apiCompleters
            }

            $parts = $toComplete.Split($forwardSlashChar, [System.StringSplitOptions]::RemoveEmptyEntries)

            # only filter when a value has been provided i.e. anything but empty string
            if ($parts.Length -gt 0) {

                # calculate if there are any paths that would be a like match for the last part of the passed path.
                # if there are, any token matches should be excluded later on
                $partsLikeness = New-Object bool[] -ArgumentList $parts.Length
                $likes = [string[]]($parts | ForEach-Object { "$_*" })

                for ($i = 0; $i -lt $parts.Length; $i++) {
                    $part = $parts[$i]
                    if (($Script:completerComponents).pathCompleters.Length -ge $parts.Length) {
                        $partsLikeness[$i] = ($Script:completerComponents).pathCompleters[$i] | Where-Object { $_ -like $likes[$i] } | Test-Any
                    }
                }

                $len = $parts.Length - 1

                $apis = $apis | Where-Object {
                    # Exclude APIs with parts shorter than the one we're gonna match
                    if ($_.parts.Length -lt $parts.Length) {
                        return $false
                    }

                    # for all parts of the path except the last, the part either needs
                    # to be an exact match or a token, like {index}
                    for ($i = 0; $i -lt $len; $i++) {
                        $part = $parts[$i]
                        if ($partsLikeness[$i] -and $part -ne $_.parts[$i]) {
                            return $false
                        } elseif ($part -ne $_.parts[$i] -and -not $_.parts[$i].StartsWith("{")) {
                            return $false
                        }
                    }

                    # for the last part of the path, the path part needs to be like the passed last part
                    # and if there aren't any matches, can also be a token
                    if ($partsLikeness[$len]) {
                        return $_.parts[$len] -like $likes[$len]
                    } else {
                        return $_.parts[$len] -like $likes[$len] -or $_.parts[$len].StartsWith("{")
                    }
                }
            }

            # completion suggestions
            $apis | ForEach-Object {

                $path = New-Object string[] -ArgumentList $_.parts.Length

                for ($i = 0; $i -lt $_.parts.Length; $i++) {
                    if ($i -eq ($_.parts.Length - 1)) {
                        if ($_.parts[$i] -eq "{index}") {
                            # TODO: Get the indices names and return as multiple values for this API
                            $path[$i] = $_.parts[$i]
                        } else {
                            $path[$i] = $_.parts[$i]
                        }
                    } elseif ($i -lt $parts.Length -and $_.parts[$i].StartsWith("{")) {
                        $path[$i] = $parts[$i]
                    } else {
                        $path[$i] = $_.parts[$i]
                    }
                }

                $path = "/" + ($path -join "/")

                if ($authority) {
                    $builder = New-Object System.UriBuilder -ArgumentList $authority
                    $builder.Path = $path

                    if ($query) {
                        $builder.Query = $query
                    }

                    # don't include default ports, if present
                    if (($builder.Scheme -eq "http" -and $builder.Port -eq 80) -or `
                        ($builder.Scheme -eq "https" -and $builder.Port -eq 443)) {
                        $builder.Port = -1
                    }

                    $completionText = [System.Web.HttpUtility]::UrlDecode($builder.ToString())
                } else {
                    if ($query) {
                        $completionText = $path + "?" + $query
                    } else {
                        $completionText = $path
                    }
                }

                # Always quote completion results as token URL parts like {index} represent script blocks when left unquoted
                New-Object System.Management.Automation.CompletionResult -ArgumentList "`"$completionText`"",
                    $_.path,
                    "ParameterValue",
                    $_.name
            }

            # pass back the original value as a completion suggestion too, if it has a value
            if ($wordToComplete) {
                New-Object System.Management.Automation.CompletionResult -ArgumentList "`"$wordToComplete`"",
                    $wordToComplete,
                    "ParameterValue",
                    $wordToComplete
            }
        }

        Register-ArgumentCompleter -CommandName Invoke-Elasticsearch -ParameterName Uri -ScriptBlock $uriCompleter
    }
}

# auto completion for HTTP methods
Register-ArgumentCompleter -CommandName Invoke-Elasticsearch -ParameterName Method -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    if ($null -eq $Script:completerComponents.apiCompleters -or $fakeBoundParameters.ContainsKey("Uri") -eq $false) {
        # If there's no Uri then all methods are valid
        $Script:methods | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult -ArgumentList $_, $_, "ParameterValue", $_
        }
    } else {

        # get just the path out of the Uri
        $uri = $fakeBoundParameters.Uri.Trim('"').Split('?')[0]
        $parsedUri = $null
        if ([Uri]::TryCreate($uri, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri) -and $parsedUri.IsAbsoluteUri) {
            $toComplete = [System.Web.HttpUtility]::UrlDecode($parsedUri.AbsolutePath)
        } else {
            if ($uri.StartsWith("/")) {
                $toComplete = $uri
            } else {
                $toComplete = "/" + $uri
            }
        }

        $parts = $toComplete.Split($forwardSlashChar, [System.StringSplitOptions]::RemoveEmptyEntries)
        $apis = $Script:completerComponents.apiCompleters

        # only filter when a value has been provided i.e. anything but empty string
        if ($parts.Length -gt 0) {

            # calculate if there are any paths that would be a like match for the last part of the passed path.
            # if there are, any token matches should be excluded later on
            $partsLikeness = New-Object bool[] -ArgumentList $parts.Length
            $likes = [string[]]($parts | ForEach-Object { "$_*" })

            for ($i = 0; $i -lt $parts.Length; $i++) {
                $part = $parts[$i]
                if ($Script:completerComponents.pathCompleters.Length -ge $parts.Length) {
                    $partsLikeness[$i] = $Script:completerComponents.pathCompleters[$i] | Where-Object { $_ -like $likes[$i] } | Test-Any
                }
            }

            $len = $parts.Length - 1

            $apis = $apis | Where-Object {
                # Exclude APIs with parts shorter than the one we're gonna match
                if ($_.parts.Length -lt $parts.Length) {
                    return $false
                }

                # for all parts of the path except the last, the part either needs
                # to be an exact match or a token
                for ($i = 0; $i -lt $len; $i++) {
                    $part = $parts[$i]
                    if ($partsLikeness[$i] -and $part -ne $_.parts[$i]) {
                        return $false
                    } elseif ($part -ne $_.parts[$i] -and -not $_.parts[$i].StartsWith("{")) {
                        return $false
                    }
                }

                # for the last part of the path, the path part needs to be like the passed last part
                # and if there aren't any matches, can also be a token
                if ($partsLikeness[$len]) {
                    return $_.parts[$len] -like $likes[$len]
                } else {
                    return $_.parts[$len] -like $likes[$len] -or $_.parts[$len].StartsWith("{")
                }
            }
        }

        if (-not $apis) {
            # If there's no match then all methods are valid
            $Script:methods | ForEach-Object {
                New-Object System.Management.Automation.CompletionResult -ArgumentList $_, $_, "ParameterValue", $_
            }
        } else {
            $apis | ForEach-Object { -split $_.methods } | Sort-Object -Unique | ForEach-Object {
                New-Object System.Management.Automation.CompletionResult -ArgumentList $_, $_, "ParameterValue", $_
            }
        }
    }
}

<#
.Synopsis
    Converts a Kibana console request to a request that can be piped to Invoke-Elasticsearch
.Description
    Converts a Kibana console request to a request that can be piped to Invoke-Elasticsearch.

    The converted request is a custom PowerShell object with request properties that can
    be piped to Invoke-Elasticsearch

.Example
    PS> @'
PUT /my_locations
{
    "mappings": {
        "properties": {
            "pin": {
                "properties": {
                    "location": {
                        "type": "geo_point"
                    }
                }
            }
        }
    }
}

PUT /my_locations/_doc/1
{
    "pin" : {
        "location" : {
            "lat" : 40.12,
            "lon" : -71.34
        }
    }
}
'@ | ConvertFrom-KibanaConsole | Invoke-Elasticsearch

    Converts two Kibana console requests to requests that can be piped to
    Elasticsearch to execute

.Example
    PS> 'GET /_cat/indices' | ckc | es

    Converts a Kibana console GET request to the _cat/indices endpoint and pipes the
    resulting request to Elasticsearch to execute
.Link
    https://www.elastic.co/guide/en/kibana/current/console-kibana.html
#>
function ConvertFrom-KibanaConsole {
    [CmdletBinding()]
    param (
        [string]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Request
    )

    Begin {
        $requests = @()
    }

    Process {
        # A command may be multiple API requests, so split by empty lines or lines starting with verbs
        $requests += [Regex]::Split($Request, "\r?\n\r?\n|\r?\n(?=HEAD|GET|PUT|POST|DELETE)")
    }

    End {
        $emptyChars = @(" ")
        $newLines = @("`n", "`r`n", [Environment]::NewLine)

        $requests | ForEach-Object {
            $consoleParts = $_.Split($newLines, 2, [StringSplitOptions]::RemoveEmptyEntries)
            $methodUriParts = $consoleParts[0].Split($emptyChars, 2, [StringSplitOptions]::None)

            if ($methodUriParts.Length -ne 2) {
                throw "'$($consoleParts[0])' is not a valid Kibana Console command of the form '<METHOD> <PATH>'"
            }

            $method = $methodUriParts[0]
            $uri = $methodUriParts[1]

            if ($consoleParts.Length -gt 1) {
                $body = $consoleParts[1]
            } else {
                $body = $null
            }

            return [PSCustomObject]@{
                PSTypeName = "ElasticsearchRequest"
                Method = $method
                Uri = $uri
                Body = $body
            }
        }
    }
}

<#
.Synopsis
    Executes a REST API request against Elasticsearch
.Description
    Provides a simpler experience for executing REST API requests against Elasticsearch.

    Use Set-ElasticsearchVersion <version> to download the REST API specs for a specific version
    of Elasticsearch, to power tab completion of available endpoints and methods.

    A request that does not specify a method

    - Without a body will be a GET request
    - With a body will be a POST request

    In addition, a GET request with a body will be sent as a POST request, since PowerShell does
    not allow sending a GET request with a body.
.Example
    es _cat/indices

    Sends a request to Elasticsearch to list the indices in the cluster.
.Example
    PS> es twitter/_doc/1 -Pretty -Method PUT -Body @'
    {
        "user" : "kimchy",
        "post_date" : "2009-11-15T14:12:12",
        "message" : "trying out Elasticsearch"
    }
    '@

    Sends a request to Elasticsearch to create a document with id 1 in the twitter index.
    The document is sent as a JSON string literal

.Example
    PS> es posts/_search?pretty -u elastic:changeme -H @{ 'X-Opaque-Id' = 'track_this_call' } -ResponseVariable response -d @{
        query = @{
            match = @{
                user = "kimchy"
            }
        }
    }

    PS> $statusCode = $response.StatusCode
    PS> $responseHeaders = $response.Headers

    Sends a request to Elasticsearch to search all indices, passing an X-Opaque-Id header to track the call
    using the tasks API. The search query is passed as a Hashtable. The underlying PowerShell response is captured
    with the response variable, allowing the status code and response headers to be inspected.

.Example
    PS> es posts/_bulk -ContentType application/x-ndjson -d C:\data.json

    Sends a bulk request to Elasticsearch with the newline delimited application/x-ndjson content type. The
    body of the request is read from the file C:\data.json
.Example
    PS> gc C:\data.json | es posts/_bulk -ContentType application/x-ndjson

    Sends a bulk request to Elasticsearch with the newline delimited application/x-ndjson content type. The
    body of the request is piped to the command.
.Parameter Method
    The HTTP method to use. For requests with a body, will default to 'POST' and without, 'GET'.
.Parameter Uri
    The URI to make the request against. A relative URI path will make a request using the base URI 'http://localhost:9200'
.Parameter User
    The username for Authentication. the password may also be specified here using the format 'username:password'
.Parameter Password
    The password for Authentication. if username is specified but password is not, an interactive prompt will be displayed to provide the password.
.Parameter Body
    The request body. May be a JSON string literal, a Hashtable, or a path to a file containing JSON
.Parameter ContentType
    The Content-Type HTTP header. By default, uses 'application/json'
.Parameter Headers
    A Hashtable of the HTTP headers to send
.Parameter Pretty
    Pretty print (indent) the JSON response. Alternatively, may be supplied as a query string parameter on the Uri with '?pretty' or '?pretty=true'
.Parameter SkipCertificateCheck
    By default, Server certificates are verified when making requests against Elasticsearch secured by SSL/TLS. Verification
    can be skipped by specifying SkipCertificateCheck. Can be useful when working with self-signed certificates, for example.
.Parameter ResponseVariable
    The name of a variable to which the response will be assigned, with global scope.
    The response can be inspected for response headers, status code, etc.
.Inputs
    The request body. May be a JSON string literal, a Hashtable, or a path to a file containing JSON
.Outputs
    The response body as a string
#>
function Invoke-Elasticsearch {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [string]
        # Use ValidateScript to work in conjunction with Register-ArgumentCompleter for Method
        [ValidateScript({
            if ($_ -in $Script:methods) {
                $true
            } else {
                throw "'$_' must be one of $($Script:methods -join ", ")"
            }
        })]
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias("X")]
        $Method,

        [string]
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        $Uri,

        [string]
        [Alias("u")]
        $User,

        [SecureString]
        $Password,

        [Alias("d")]
        [Alias("data")]
        [Elastic.ElasticsearchRequestBody]
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        $Body,

        [string]
        $ContentType = "application/json",

        [Alias("H")]
        $Headers = @{},

        [switch]
        $Pretty,

        [Alias("k")]
        [Alias("insecure")]
        [switch]
        $SkipCertificateCheck,

        [Alias("response")]
        [string]
        $ResponseVariable
    )
    Begin {
    }

    Process {
        if (-not $Method) {
            if ($Body) {
                $Method = "POST"
            } else {
                $Method = "GET"
            }
        } elseif ($Body -and $Method -eq "GET") {
            # Invoke-WebRequest does not allow sending a body with GET, so force POST
            $Method = "POST"
        }

        if ($Uri) {
            $parsedUri = $null
            if ([Uri]::TryCreate($Uri, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri) -and -not $parsedUri.IsAbsoluteUri) {
                $parsedUri = New-Object System.Uri "http://localhost:9200/$($parsedUri.OriginalString.TrimStart('/'))"
            }
        }
        else {
            $parsedUri = New-Object System.Uri "http://localhost:9200/"
        }

        # ParseQueryString does not respect keys without values, so test .Query directly
        if ($Pretty -and (-not $parsedUri.Query -or $parsedUri.Query -match "[?|&]pretty(?=\=true)" -eq $false)) {
            $queryString = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
            if (-not $queryString) {
                $queryString = New-Object System.Collections.Specialized.NameValueCollection
            }
            $queryString.Set("pretty","true")
            $uriBuilder = New-Object System.UriBuilder $parsedUri
            $uriBuilder.Query = $queryString.ToString();
            $parsedUri = $uriBuilder.Uri
        }

        if ($User) {
            $userParts = $User.Split(':', 2)
            if ($userParts.Length -eq 2) {
                $User = $userParts[0]
                $Password = $userParts[1] | ConvertTo-SecureString -AsPlainText -Force
            }

            while (-not $Password -or $Password.Length -eq 0) {
                $Password = Read-Host -AsSecureString "Enter password for $($User):"
            }

            $credential = New-Object System.Management.Automation.PSCredential ($User, $Password)
        } else {
            $credential = $null
        }

        $requestParameters = @{
            Uri = $parsedUri
            ContentType = $ContentType
            Headers = $Headers
            Credential = $credential
            Method = $Method
            UseBasicParsing = $true
        }

        # Allow PowerShell Core to send credentials over unencrypted connection. Possibly expose as param?
        if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey("AllowUnencryptedAuthentication")) {
            $requestParameters.AllowUnencryptedAuthentication = $true
        }

        if ($Body) {
            if ($Body.Input -is [string]) {
                if (Test-Path $Body.Input -PathType Leaf) {
                    $requestParameters.InFile = $Body.Input
                } else {
                    $requestParameters.Body = $Body.Input
                }
            } else {
                $requestParameters.Body = $Body.Input | ConvertTo-Json
            }
        }

        if ($SkipCertificateCheck) {
            if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey("SkipCertificateCheck")) {
                # PowerShell Core
                $requestParameters.SkipCertificateCheck = $true
            } else {
                # PowerShell
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [Elastic.ServerCertificateValidation]::AllowAll()
            }
        }

        try {
            $response = Invoke-WebRequest @requestParameters
            if ($ResponseVariable) {
                Set-Variable -Name $ResponseVariable -Value $response -Scope Global
            }

            if ($response.Content -is [string]) {
                #PowerShell
                return $response.Content
            } else {
                #PowerShell Core
                return $response.Content.ReadAsStringAsync().Result;
            }
        }
        catch {
            if ($_.Exception | Get-Member Response) {
                # Powershell
                $response = $_.Exception.Response
            } else {
                # PowerShell Core
                $response = $null
            }

            if ($ResponseVariable) {
                Set-Variable -Name $ResponseVariable -Value $response -Scope Global
            }

            if ($response) {
                if ($response | Get-Member GetResponseStream) {
                    # PowerShell
                    $responseStream = $response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    return $reader.ReadToEnd()
                } else {
                    # PowerShell Core
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        return $_.ErrorDetails.Message;
                    } else {
                        throw $_.Exception
                    }
                }
            }
            else {
                throw $_.Exception
            }
        }
        finally {
            if ($SkipCertificateCheck -and (Get-Command Invoke-WebRequest).Parameters.ContainsKey("SkipCertificateCheck") -eq $false) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
    }

    End {

    }
}

function Get-ElasticsearchIndex
{
    [OutputType([string[]])]
    param(
        [string]
        [Parameter(Position=0,ValueFromPipelineByPropertyName=$true)]
        $Uri,

        [string]
        [Alias("u")]
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $User,

        [SecureString]
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $Password
    )

    $parsedUri = $null
    $authority = $null
    if ([Uri]::TryCreate($Uri, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri) -and $parsedUri.IsAbsoluteUri) {
        $authority = $parsedUri.GetLeftPart([UriPartial]::Authority)
    }

    if ($authority) {
        $builder = New-Object System.UriBuilder -ArgumentList $authority
        $builder.Path = "_cat/indices"
        $builder.Query = "?h=index"

        if (($builder.Scheme -eq "http" -and $builder.Port -eq 80) -or `
            ($builder.Scheme -eq "https" -and $builder.Port -eq 443)) {
            $builder.Port = -1
        }

        $catIndicesUri = $builder.ToString()
    } else {
        $catIndicesUri = "_cat/indices?h=index"
    }

    $parameters = @{
        User = $User
        Password = $Password
        Method = "GET"
        Uri = $catIndicesUri
    }

    try {
        $indices = Invoke-Elasticsearch @parameters
        return $indices.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    }
    catch {
        Write-Warning "Unable to retrieve indices for $($parameters.Keys.ForEach({"$_ $($parameters.$_)"}) -join ','). $_.Exception"
        return @()
    }
}

# Set Elasticsearch version to the one being installed
Set-ElasticsearchVersion -Version "7.4.0"

Set-Alias -Name es -Value Invoke-Elasticsearch -Description "Sends a request to Elasticsearch"
Set-Alias -Name ckc -Value ConvertFrom-KibanaConsole -Description "Converts a Kibana Console command to Invoke-Elasticsearch command"
Set-Alias -Name hash -Value ConvertFrom-Json -Description "Converts JSON into a dictionary/hashmap"
