param(
    [Parameter()]
    [ValidateNotNullOrEmpty]
    $Version
)

Import-Module -Name $PSScriptRoot/../Elastic.Console/Elastic.Console.psd1 -Force
Import-Module -Name $PSScriptRoot/elasticsearch.ps1 -Force | Out-Null

Describe "Oss distribution tests" {
    BeforeAll {
        Start-Elasticsearch -Version $Version -Distribution oss
    }

    Context "Set-ElasticsearchVersion" {
        It "should set the Elasticsearch version" -Tag "ga" {
            $elasticVersion = [Elastic.ElasticVersion]$Version

            Set-ElasticsearchVersion $Version

            Get-ElasticsearchVersion -ListAvailable | Should -Contain $elasticVersion
            Get-ElasticsearchVersion | Should -Be $elasticVersion
        }
    }

    Context "Invoke-Elasticsearch" {

        It "should use http://localhost:9200 by default" {
            es "/" | Should -Not -BeNullOrEmpty
        }

        It "should return compact json" {
            $json = es /_nodes
            $json | Should -Not -BeNullOrEmpty
            $json | Should -Not -BeLike "*`n*"
        }

        It "should return pretty json with -Pretty" {
            es /_nodes -Pretty | Should -BeLike "*`n*"
        }

        It "should accept json string input" {
            es /basic_test_index/_doc/string_input -Body '{ "message": "string test" }' | Should -Match '"result":"created"'
        }

        It "should accept json string from pipeline" {
            '{ "message": "string test" }' | es /basic_test_index/_doc/string_pipeline  | Should -Match '"result":"created"'
        }

        It "should accept hashtable input" {
            es /basic_test_index/_doc/hash_input -Body @{ message = "hashtable test" } | Should -Match '"result":"created"'
        }

        It "should accept hashtable from pipeline" {
            @{ message = "hashtable test" } | es /basic_test_index/_doc/hash_pipeline  | Should -Match '"result":"created"'
        }

        It "should return bytes with -Bytes" {
            es -X PUT "bytes_index_1" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200

            $bytes = es "_cat/indices?format=json" -Bytes
            $bytes | Should -BeOfType [byte]
            $json = [System.Text.Encoding]::UTF8.GetString($bytes)
            { ConvertFrom-Json $json } | Should -Not -Throw
        }

        It "should capture underlying response object with -ResponseVariable" {
            es "/" -ResponseVariable odt1
            $odt1 | Should -Not -BeNullOrEmpty
        }

        It "should send content-type header with -ContentType" {
            es -X PUT "content_type_index_1" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200
            es -X PUT "content_type_index_2" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200

            es "_cat/indices" -ContentType "text/plain" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200
            $odt2.Headers.Keys | Should -Contain "Content-Type" 
            $odt2.Headers["Content-Type"] | Should -Be "text/plain; charset=UTF-8"
        }

        It "should send headers with -Headers" {
            es -X PUT "headers_index_1" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200
            es -X PUT "headers_index_2" -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200

            es "_cat/indices" -Headers @{ "Content-Type" = "text/plain"; Accept = "text/plain" } -ResponseVariable odt2
            $odt2.StatusCode | Should -Be 200
            $odt2.Headers.Keys | Should -Contain "Content-Type" 
            $odt2.Headers["Content-Type"] | Should -Be "text/plain; charset=UTF-8"
        }

    }

    Context "ConvertFrom-KibanaConsole" {

        It "should pipe ConvertFrom-KibanaConsole to Invoke-Elasticsearch" {
            $json = ConvertFrom-KibanaConsole 'GET /' | es
            $json | Should -Match '"tagline" : "You Know, for Search"'
        }
    }

    AfterAll {
        Stop-Elasticsearch
    }
}

Describe "Default distribution tests" {
    BeforeAll {
        Start-Elasticsearch -Version $Version -Distribution "default"
    }

    Context "Invoke-Elasticsearch" {

        It "should skip certificate check with untrusted self-signed certificate with -SkipCertificateCheck" {
            es "https://localhost:9200/" -ResponseVariable ddt1 -SkipCertificateCheck
            $ddt1.StatusCode | Should -Be 401
        }

        It "should throw exception with untrusted self-signed certificate" {
            { es "https://localhost:9200/" -User "elastic:changeme" } | Should -Throw
        }

        It "should pass username and password colon separated in -User" {
            es "https://localhost:9200/" -User "elastic:changeme" -ResponseVariable ddt2 -SkipCertificateCheck
            $ddt2.StatusCode | Should -Be 200
        }

        It "should pass username and password in -User and -Password" {
            $password = ConvertTo-SecureString "changeme" -AsPlainText
            es "https://localhost:9200/" -User "elastic" -Password $password -ResponseVariable ddt2 -SkipCertificateCheck
            $ddt2.StatusCode | Should -Be 200
        }
    }

    Context "ConvertFrom-KibanaConsole" {

        It "should use the console url in Invoke-Elasticsearch" {
            ConvertFrom-KibanaConsole 'GET https://localhost:9200/' | 
            es -User "elastic:changeme" -SkipCertificateCheck -ResponseVariable ddt3
            $ddt3.StatusCode | Should -Be 200
        }
    }


    AfterAll {
        Stop-Elasticsearch
    }
}

