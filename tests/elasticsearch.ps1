New-Module -Name Elasticsearch -Scriptblock {
function Log {
    [CmdletBinding()]
    param(
      [string]
      [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
      $Message,
  
      [string]
      [ValidateSet("Success", "Info", "Error")]
      $Level
    )
  
    $ESC = [char]27
  
    if (!$Level) {
      $Level = "Info"
    }
  
    switch ($Level) {
      "Success" { $levelMessage = "[32;1mSUCCESS:" }
      "Info" { $levelMessage = "[34;1mINFO:" }
      "Error" { $levelMessage = "[31;1mERROR:" }
    }
  
    Write-Host "$ESC$levelMessage$ESC[0m $message$ESC[0m"
}

function Test-Docker {
    try {
        docker --version | Out-Null
        return $true
    } catch {
        Log "docker not installed or running. Please install and run docker" -Level Error
        return $false
    }
}

function Remove-Volume {
    param(
        [string]
        $Name
    )

    if ("$(docker volume ls --quiet --filter name="$Name")") {
        Log "Removing volume $Name"
        docker volume rm "$Name" | Out-Null
    }
}

function Remove-Node {
    param(
        [string]
        $Name
    )

    if ("$(docker ps --quiet --filter name="$Name")" -ne "") {
        Log "Removing container $Name"
        docker container rm --force --volumes "$Name" | Out-Null
        Remove-Volume "$Name-data" 
    }
}
function Remove-Network {
    param(
        [string]
        $Name
    )

    if ("$(docker network ls --quiet --filter name="$Name")" -ne "") {
        Log "Removing network $Name"
        docker network rm $Name | Out-Null
    }
}

function Stop-Elasticsearch {
    [CmdletBinding()]
    param(
        $NetworkName = "es-net"
    )

    if (!(Test-Docker)) {
        return
    }

    if ("$(docker network ls --quiet --filter name=$NetworkName)" -eq "") {
        Log "$NetworkName is already deleted"
        return
    }

    $containers = $(docker network inspect --format '{{ range $key, $value := .Containers }}{{ println .Name}}{{ end }}' $NetworkName)
    
    foreach($container in $containers) {
        Remove-Node "$container"
    }
    
    Remove-Network $NetworkName
    Log "Cleaned up and exiting" -Level Success
}

function Start-Elasticsearch {
    [CmdletBinding()]
    param(
        [string]
        [Parameter(Mandatory = $true)]
        $Version,

        [string]
        [ValidateSet("oss", "default")]
        $Distribution = "default",

        [string]
        $NodeName = "instance",

        [string]
        $ClusterName = "es",

        [int]
        $HttpPort = 9200,

        [string]
        $ElasticPassword = "changeme",

        [string]
        $SslCert = "$PWD/.ci/testnode.crt",

        [string]
        $SslKey = "$PWD/.ci/testnode.key",

        [string]
        $SslCa = "$PWD/.ci/ca.crt",

        [string]
        $NetworkName = "es-net"
    )

    if (!(Test-Docker)) {
        return
    }

    $VolumeName = "$NodeName-data"

    trap {
        Remove-Node $NodeName
        Remove-Network $NetworkName
    }

    Log "Making sure previous run leftover infrastructure is removed"

    Remove-Node $NodeName
    Remove-Network $NetworkName

    Log "Creating network $NetworkName"

    docker network create $NetworkName | Log

    $environment = @(
        "--env", "node.name=`"$NodeName`"",
        "--env", "cluster.name=`"$ClusterName`"",
        "--env", "cluster.initial_master_nodes=`"$NodeName`"",
        "--env", "discovery.seed_hosts=`"$NodeName`"",
        "--env", "cluster.routing.allocation.disk.threshold_enabled=false",
        "--env", "bootstrap.memory_lock=true",
        "--env", "node.attr.testattr=test",
        "--env", "path.repo=/tmp",
        "--env", "repositories.url.allowed_urls=http://snapshot.test*"
    )

    $volumes = @(
        "--volume", "${VolumeName}:/usr/share/elasticsearch/data"
    )

    $url="http://$NodeName"

    if ($Distribution -eq "default") {
        $environment += @(
            "--env", "ELASTIC_PASSWORD=`"$ElasticPassword`"",
            "--env", "xpack.license.self_generated.type=trial",
            "--env", "xpack.security.enabled=true",
            "--env", "xpack.security.http.ssl.enabled=true",
            "--env", "xpack.security.http.ssl.verification_mode=certificate",
            "--env", "xpack.security.http.ssl.key=certs/testnode.key",
            "--env", "xpack.security.http.ssl.certificate=certs/testnode.crt",
            "--env", "xpack.security.http.ssl.certificate_authorities=certs/ca.crt",
            "--env", "xpack.security.transport.ssl.enabled=true",
            "--env", "xpack.security.transport.ssl.key=certs/testnode.key",
            "--env", "xpack.security.transport.ssl.certificate=certs/testnode.crt",
            "--env", "xpack.security.transport.ssl.certificate_authorities=certs/ca.crt"
        )

        $volumes += @(
            "--volume", "`"${SslCert}`":/usr/share/elasticsearch/config/certs/testnode.crt",
            "--volume", "`"${SslKey}`":/usr/share/elasticsearch/config/certs/testnode.key",
            "--volume", "`"${SslCa}`":/usr/share/elasticsearch/config/certs/ca.crt"
        )

        $url="https://elastic:$ElasticPassword@$NodeName"

        $elasticsearchImage = "elasticsearch:$Version"
        $curlFlags = "--insecure --cacert /usr/share/elasticsearch/config/certs/ca.crt --resolve ${NodeName}:443:127.0.0.1"
    } else {
        $elasticsearchImage = "elasticsearch-oss:$Version"
        $curlFlags = ""
    }

    Log "Starting container $NodeName"

    docker run `
        --name "`"$NodeName`"" `
        --network "`"$NetworkName`"" `
        --env ES_JAVA_OPTS=-"`"Xms1g -Xmx1g`"" `
        $environment `
        $volumes `
        --publish ${HttpPort}:9200 `
        --ulimit nofile=65536:65536 `
        --ulimit memlock=-1:-1 `
        --detach="`"true`"" `
        --health-cmd="`"curl $curlFlags --fail ${url}:9200/_cluster/health || exit 1`"" `
        --health-interval=2s `
        --health-retries=20 `
        --health-timeout=2s `
        docker.elastic.co/elasticsearch/$elasticsearchImage | Log


    while("$(docker inspect -f '{{.State.Health.Status}}' $NodeName)" -eq "starting") {
        Start-Sleep 2;
        Log "waiting for node $NodeName to be up"
    }

    docker logs $NodeName | Log

    if ("$(docker inspect -f '{{.State.Health.Status}}' $NodeName)" -ne "healthy") {
        Remove-Node $NodeName
        Remove-Network $NetworkName
        Log "Failed to start Elasticsearch $Version in detached mode beyond health checks" -Level Error
        Log "dumped the docker log before shutting the node down" -Level Error
        throw "Failed to start Elasticsearch $Version"
    } else {
        Log "Detached and healthy: $NodeName on docker network: $NetworkName" -Level Success     
        $localhost = $url.Replace("$NodeName", "localhost")
        Log "Running on: ${localhost}:${HttpPort}" -Level Success
        return "${localhost}:${HttpPort}"
    }
}

Export-ModuleMember -Function Start-Elasticsearch,Stop-Elasticsearch

}