if ($args.count -lt 2) {
    Write-Error "Requires 2 args: job matrix number and number of builds for this job."
    exit 1
}

# The first argument remains a workflow shard identifier for compatibility.
# Ordinary builds are intentionally identical; byte-identity source changes are
# owned exclusively by the fixed manifest driver.
$BuildCount = [int]$args[1]

$build_ids = 0..($BuildCount - 1)

$build_dirs   = foreach($i in $build_ids) { "build$i" }
$stdout_files = foreach($i in $build_ids) { "stdout$i.txt" }
$stderr_files = foreach($i in $build_ids) { "stderr$i.txt" }

$procs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]

foreach($i in $build_ids) {
    Write-Output "Preparing clean ordinary build (instance $i)"

    # Prepare to build
    $params = @{
        FilePath = "cmake"
        PassThru = $null
        ArgumentList = @(
            "-B", $build_dirs[$i],
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "-G", "`"NMake Makefiles`""
        )
    }

    # For the first job, display stdout and stderr.
    # Else dump to file so we don't see 50 at once.
    if ($i -eq 0) {
        $params.Add("NoNewWindow", $null)
    } else {
        $params.Add("RedirectStandardOutput", $stdout_files[$i])
        $params.Add("RedirectStandardError", $stderr_files[$i])
    }

    $procs.Add($(Start-Process @params))
}

$failed = $false
try { Wait-Process -InputObject $procs } catch { $failed = $true }

# Check for failure
foreach($i in $build_ids) {
    if ($procs[$i].ExitCode -ne 0) {
        if ($i -ne 0) {
            Get-Content $stdout_files[$i] -Tail 10
            Get-Content $stderr_files[$i] -Tail 10
        }
        $failed = $true
    }
}

if ($failed) { exit 1 }
