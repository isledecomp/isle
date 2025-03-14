if ($args.count -lt 1) {
    Write-Error "Requires 1 arg: number of builds for this job."
    exit 1
}

$BuildCount = [int]$args[0]

$build_ids = 0..($BuildCount - 1)
$build_dirs   = foreach($i in $build_ids) { "build$i" }
$stdout_files = foreach($i in $build_ids) { "stdout$i.txt" }
$stderr_files = foreach($i in $build_ids) { "stderr$i.txt" }

# Create unique temp dir for each build thread
$temp_dirs = foreach($dir in $build_dirs) { "$env:temp\$dir" }
New-Item -ItemType Directory -Force -Path $temp_dirs

$procs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]

foreach($i in $build_ids) {
    $params = @{
        FilePath = "cmake"
        PassThru = $null
        ArgumentList = @("--build", $build_dirs[$i])
        Environment = @{ TEMP = $temp_dirs[$i]; TMP = $temp_dirs[$i] }
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

# Wait for all builds to finish
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
