param(
    [Parameter()]
    [ValidateNotNullOrEmpty]
    $Version
)

Describe "Unit tests" {
    Import-Module -Name $PSScriptRoot/../Elastic.Console/Elastic.Console.psd1 -Force

    Context "Get-ElasticsearchVersion" {

        It "should have at least one available version" {
            $versions = Get-ElasticsearchVersion -ListAvailable 
            $versions.Count | Should -BeGreaterOrEqual 1
        }
    }

    Context "Aliases" {

        It "es should be an alias for Invoke-Elasticsearch" {
            $alias = Get-Alias es -ErrorAction Ignore
            $alias | Should -Not -BeNullOrEmpty
            $alias.ResolvedCommand.Name | Should -Be 'Invoke-Elasticsearch'
            $alias.ResolvedCommand.Module.Name | Should -Be 'Elastic.Console'
        }
    
        It "ckc should be an alias for ConvertFrom-KibanaConsole" {
            $alias = Get-Alias ckc -ErrorAction Ignore
            $alias | Should -Not -BeNullOrEmpty
            $alias.ResolvedCommand.Name | Should -Be 'ConvertFrom-KibanaConsole'
            $alias.ResolvedCommand.Module.Name | Should -Be 'Elastic.Console'
        }
    
        It "hash should be an alias for ConvertFrom-Json" {
            $alias = Get-Alias hash -ErrorAction Ignore
            $alias | Should -Not -BeNullOrEmpty
            $alias.ResolvedCommand.Name | Should -Be 'ConvertFrom-Json'
            $alias.ResolvedCommand.Module.Name | Should -Be 'Microsoft.PowerShell.Utility'
        }
    }

    Context "ConvertFrom-KibanaConsole" {

        It "should parse single console request" {
            $request = @'
PUT /my-index-000001
{
    "settings": {
    "index": {
        "number_of_shards": 3,  
        "number_of_replicas": 2 
    }
    }
}
'@ | ckc

            $request | Should -Not -BeNullOrEmpty
            $request | Should -BeOfType 'PSCustomObject'
            $request.Method | Should -Be PUT
            $request.Uri | Should -Be /my-index-000001
            $request.Body | Should -Be @'
{
    "settings": {
    "index": {
        "number_of_shards": 3,  
        "number_of_replicas": 2 
    }
    }
}
'@
        }

        It "should parse multiple console requests" {
            $request = @'
PUT /my-index-000001
{
    "settings": {
    "index": {
        "number_of_shards": 3,  
        "number_of_replicas": 2 
    }
    }
}
POST /my-index-000001/_doc/1
{ "message": "foo" }

POST /my-index-000001/_doc/2
{ "message": "bar" }
'@ | ckc

            $request | Should -HaveCount 3

            $request[0] | Should -BeOfType 'PSCustomObject'
            $request[0].Method | Should -Be PUT
            $request[0].Uri | Should -Be /my-index-000001
            $request[0].Body | Should -Be @'
{
    "settings": {
    "index": {
        "number_of_shards": 3,  
        "number_of_replicas": 2 
    }
    }
}
'@

            $request[1] | Should -BeOfType 'PSCustomObject'
            $request[1].Method | Should -Be POST
            $request[1].Uri | Should -Be /my-index-000001/_doc/1
            $request[1].Body | Should -Be '{ "message": "foo" }'

            
            $request[2] | Should -BeOfType 'PSCustomObject'
            $request[2].Method | Should -Be POST
            $request[2].Uri | Should -Be /my-index-000001/_doc/2
            $request[2].Body | Should -Be '{ "message": "bar" }'

        }
    }
}

