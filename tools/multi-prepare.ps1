if ($args.count -lt 2) {
    Write-Error "Requires 2 args: job matrix number and number of builds for this job."
    exit 1
}

function Get-BaseSeed {
    Param (
        [int]$Matrix
    )

    # GITHUB_SHA is the commit hash. This means the entropy files will be consistent
    # unless you push a new commit.
    $sha = [System.Convert]::ToUInt32($env:GITHUB_SHA.Substring(0, 8), 16)

    # Mask off the last 16 bits
    $base_seed = ($sha -band 0xffff0000)

    # Add the matrix number * 256. We can run 256 unique builds on this job.
    return $base_seed + ($Matrix -shl 8)
}

$MatrixNo = [int]$args[0]
$BuildCount = [int]$args[1]
$base_seed = $(Get-BaseSeed -Matrix $MatrixNo)

$build_ids = 0..($BuildCount - 1)

$build_dirs   = foreach($i in $build_ids) { "build$i" }
$stdout_files = foreach($i in $build_ids) { "stdout$i.txt" }
$stderr_files = foreach($i in $build_ids) { "stderr$i.txt" }

$procs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]

foreach($i in $build_ids) {
    # Create the entropy file
    $entropy_file = "entropy$i.h"
    $seed = $base_seed + $i

    Write-Output "Using seed: $seed (instance $i)"
    python3 tools/entropy.py $seed > $entropy_file

    # Prepare to build
    $params = @{
        FilePath = "cmake"
        PassThru = $null
        ArgumentList = @(
            "-B", $build_dirs[$i],
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "-DISLE_INCLUDE_ENTROPY=ON",
            "-DISLE_ENTROPY_FILENAME=$entropy_file",
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
