# Elastic.Console

cmdlets to simplify making requests to Elasticsearch from PowerShell.

Works with 
- PowerShell Desktop 3.0+ on Windows
- PowerShell Core on Windows, macOS, Linux

## Installation

Install from the [PowerShell gallery](https://www.powershellgallery.com/packages/Elastic.Console/)

```powershell
Install-Module Elastic.Console
```

If installing a prerelease version, `-AllowPrerelease` switch is required

```powershell
Install-Module Elastic.Console -AllowPrerelease
```

Install from a local directory

```
Import-Module ./Elastic.Console/Elastic.Console.psd1
```

### Including in your PowerShell profile

Open your PowerShell profile in your favourite text editor. You can find the location of your profile in PowerShell with

```
$PROFILE
```

Add the following lines to your profile and save

```powershell
if (Get-Module -ListAvailable -Name Elastic.Console) {
    Import-Module Elastic.Console
} else {
    Install-Module Elastic.Console -AllowPrerelease
}
```

## Commands

To list the available commands in the module

```powershell
Get-Command -Module Elastic.Console
```

Full details of each command, including examples, can be viewed with

```powershell
Get-Help <Command Name> -Full
```

### `Set-ElasticsearchVersion`

Sets the version of Elasticsearch to work against. This will download the REST API specs for the given version
of Elasticsearch if not already downloaded, using the specs to power tab completion of API endpoints and HTTP methods.

`Set-ElasticsearchVersion` only needs to be called once in a PowerShell session, ideally at the start of the session,
to set the version of Elasticsearch for the session.

#### Example

```powershell
Set-ElasticsearchVersion 7.3.0
```

### `Get-ElasticsearchVersion`

Gets the version of Elasticsearch that has been set with `Set-ElasticsearchVersion`, or lists the versions of Elasticsearch for which specs
have been downloaded, when using the `-ListAvailable` switch

#### Examples

```powershell
Get-ElasticsearchVersion
```

Gets the version of Elasticsearch that has been set with `Set-ElasticsearchVersion`

```powershell
(Get-ElasticsearchVersion) -gt "7.3.0"
```

Gets the version of Elasticsearch that has been set with `Set-ElasticsearchVersion`, and compares against version 7.3.0

```powershell
Get-ElasticsearchVersion -ListAvailable
```

Lists the versions of Elasticsearch for which specs have been downloaded, that can
be used to power tab completion.

### `Invoke-Elasticsearch`

Executes a REST API request against Elasticsearch. The return type is the response body as a `string`, allowing
this to be piped to other commands like `jq`, to file, etc.

If `Set-ElasticsearchVersion` is called prior to calling `Invoke-Elasticsearch`, PowerShell tab completion
can be used to complete API endpoints and accepted HTTP methods.

`Invoke-Elasticsearch` is aliased to `es` to make usage more concise.

----
**NOTE**

When running on PowerShell Core on macOS or Linux, the default `EditMode` for reading lines from the terminal
is `Emacs`, meaning tab completion lists available completion values starting with typed characters, when you have not
typed enough characters to match a single completion. To change this behaviour to allow tab completion to
cycle through available completion values, you can change the `EditMode` with

```powershell
Set-PSReadLineOption -EditMode Windows
```
----

### Examples

#### Simple requests

```powershell
es _cat/indices
```

Sends a request to Elasticsearch to list the indices in the cluster.

The default endpoint is `http://localhost:9200` but you can connect to any host and port

```powershell
es https://example.com:9200/_cat/indices
```

#### Requests with a string body

```powershell
es twitter/_doc/1 -Pretty -Method PUT -Body @'
{
    "user" : "kimchy",
    "post_date" : "2009-11-15T14:12:12",
    "message" : "trying out Elasticsearch"
}
'@
```

Sends a request to Elasticsearch to create a document with id 1 in the twitter index. The document is sent as a 
JSON string literal.

#### Requests with a Hashtable body

```powershell
es posts/_search?pretty -u elastic:changeme -H @{ 'X-Opaque-Id' = 'track_this_call' } -ResponseVariable response -d @{
    query = @{
        match = @{ 
            user = "kimchy" 
        }
    }
}

$statusCode = $response.StatusCode
$responseHeaders = $response.Headers
```

Sends a request to Elasticsearch to search all indices, passing an `X-Opaque-Id` header to track the call
using the tasks API. The search query is passed as a `Hashtable`. The underlying PowerShell response is captured
with the `response` variable passed to `-ResponseVariable`, allowing the status code and response headers to be 
inspected.

#### Requests with a body read from file

```powershell
es posts/_bulk -ContentType application/x-ndjson -d ./data.json
```

Sends a bulk request to Elasticsearch with the newline delimited `application/x-ndjson` content type. The
body of the request is read from the file `./data.json`

```powershell
Get-Content C:\data.json | es posts/_bulk -ContentType application/x-ndjson
```

Sends a bulk request to Elasticsearch with the newline delimited application/x-ndjson content type. The
body of the request is piped to the command.

### `ConvertFrom-KibanaConsole`

Converts Kibana console requests to a form that can be piped to `Invoke-Elasticsearch`. Can handle multiple requests

#### Multiple console requests

```powershell
@'
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
```

Converts two Kibana console requests to requests that can be piped to
Elasticsearch to execute

#### Pipe console strings

```powershell
'GET /_cat/indices' | ckc | es
```

Converts a Kibana console GET request to the `_cat/indices` endpoint and pipes the
resulting request to Elasticsearch to execute

### Development

#### Building

The Elastic.Console can be built using the simple `build.ps1` script in the repository root.
Take a look at the `params()` within the script to see what parameters are supported.

#### Code signing

In order to publish Elastic.Console, the module should be built using the `build.ps1` script,
passing a code signing certificate to sign the module.

An example of building the module for publishing

```powershell
$cert = (dir Cert:\CurrentUser\My -CodeSigningCert)[0]
.\build.ps1 -Version 7.5.0 -Prerelease rc1 -Certificate $cert
```

This retrieves the first code signing certificate from the current user's personal 
certificate store (on Windows), and uses it to sign the Elastic.Console.psm1 module file.

#### Publishing

The module can be published to the [PowerShell gallery](https://www.powershellgallery.com/)
with

```powershell
Publish-Module -Path .\Elastic.Console\ -NuGetApiKey '<NugetApiKey>' -Exclude .\Elastic.Console\README.md
```

where `<NugetApiKey>` is an API key tied to your PowerShell gallery account. 