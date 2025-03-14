if ($args.count -lt 1) {
    Write-Error "Requires 1 arg: number of builds for this job."
    exit 1
}

$BuildCount = [int]$args[0]
$build_ids = 0..($BuildCount-1)

$build_dirs = foreach($i in $build_ids) { "build$i" }
$stdout_files = foreach($i in $build_ids) { "stdout$i.txt" }
$stderr_files = foreach($i in $build_ids) { "stderr$i.txt" }

$artifacts = @(
    @{prog = "CONFIGPROGRESS"; binfile = "CONFIG.EXE"; pdbfile = "CONFIG.PDB"; codedir = "."}
    @{prog = "ISLEPROGRESS";   binfile = "ISLE.EXE";   pdbfile = "ISLE.PDB";   codedir = "."}
    @{prog = "LEGO1PROGRESS";  binfile = "LEGO1.DLL";  pdbfile = "LEGO1.PDB";  codedir = "LEGO1"}
)

foreach($a in $artifacts) {
    $procs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]

    foreach($i in $build_ids) {
        $params = @{
            FilePath = "reccmp-reccmp"
            PassThru = $null
            ArgumentList = @(
                "--paths",
                $("legobin/" + $a["binfile"]),
                $($build_dirs[$i] + "/" + $a["binfile"]),
                $($build_dirs[$i] + "/" + $a["pdbfile"]),
                $a["codedir"],
                "--json",
                $($a["prog"] + "$i.json"),
                "--silent"
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

    foreach($i in $build_ids) {
        if ($procs[$i].ExitCode -ne 0) {
            Get-Content $stdout_files[$i] -Tail 20
            Get-Content $stderr_files[$i] -Tail 20
            $failed = $true
        }
    }

    if ($failed) { exit 1 }
}
