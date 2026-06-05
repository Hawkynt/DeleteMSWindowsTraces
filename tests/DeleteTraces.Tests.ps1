#Requires -Version 5.1
# Pester 5 test suite for DeleteTraces.bat
#
# There is no compiler for batch files, so quality assurance is split into:
#   1. static analysis  - file format and internal consistency (labels, calls, scoping)
#   2. behavior (smoke) - the script must refuse to run when its prerequisites are missing,
#                         which is the only path that is safe to execute on any machine

BeforeAll {
  $script:batPath = (Resolve-Path (Join-Path $PSScriptRoot '..\DeleteTraces.bat')).Path
  $script:bytes = [System.IO.File]::ReadAllBytes($batPath)
  $script:text = [System.IO.File]::ReadAllText($batPath)
  $script:lines = [System.IO.File]::ReadAllLines($batPath)

  # a label definition is a line consisting only of ":name"
  $script:labelPattern = '^\s*:(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*$'
  $script:labels = @(foreach ($line in $lines) { if ($line -match $labelPattern) { $Matches.name } })

  # split the script into regions: everything between one label and the next
  $script:regions = [ordered]@{ '(header)' = [System.Collections.Generic.List[string]]::new() }
  $current = '(header)'
  foreach ($line in $lines) {
    if ($line -match $labelPattern) {
      $current = $Matches.name
      $regions[$current] = [System.Collections.Generic.List[string]]::new()
    } else {
      $regions[$current].Add($line)
    }
  }
}

Describe 'DeleteTraces.bat file format' {

  Context 'Given the raw bytes of the script' {

    It 'When inspecting the file start, Then there is no byte order mark' {
      # cmd.exe chokes on a UTF-8 BOM in front of @echo off
      if ($bytes.Length -ge 3) {
        -join ($bytes[0..2] | ForEach-Object { '{0:X2}' -f $_ }) | Should -Not -Be 'EFBBBF'
      }
    }

    It 'When inspecting all bytes, Then the file is plain ASCII' {
      # non-ASCII bytes silently change meaning depending on the active codepage
      $offenders = for ($i = 0; $i -lt $bytes.Length; ++$i) { if ($bytes[$i] -gt 127) { $i } }
      @($offenders) | Should -BeNullOrEmpty
    }

    It 'When inspecting line endings, Then every line break is CRLF' {
      # lone LF breaks label lookup and multi-line parser behavior in cmd.exe
      $text | Should -Not -Match '(?<!\r)\n'
    }
  }
}

Describe 'DeleteTraces.bat internal consistency' {

  Context 'Given all label definitions' {

    It 'When collecting them, Then at least one subroutine exists' {
      $labels.Count | Should -BeGreaterThan 0
    }

    It 'When comparing them, Then no label is defined twice' {
      # cmd.exe silently jumps to the first match, shadowing the second definition
      $duplicates = $labels | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -GT 1
      @($duplicates | ForEach-Object Name) | Should -BeNullOrEmpty
    }
  }

  Context 'Given every call :target in the script' {

    It 'When resolving the targets, Then each one is a defined label' {
      $known = @($labels | ForEach-Object { $_.ToLowerInvariant() }) + 'eof'
      $unresolved = [regex]::Matches($text, '(?i)\bcall\s+:(?<name>[A-Za-z_][A-Za-z0-9_]*)') |
        ForEach-Object { $_.Groups['name'].Value } |
        Where-Object { $known -notcontains $_.ToLowerInvariant() }
      @($unresolved) | Should -BeNullOrEmpty
    }
  }

  Context 'Given every goto in the script' {

    It 'When resolving the targets, Then each one is a defined label or :eof' {
      $known = @($labels | ForEach-Object { $_.ToLowerInvariant() }) + 'eof'
      $unresolved = [regex]::Matches($text, '(?i)\bgoto\s+:?(?<name>[A-Za-z_][A-Za-z0-9_]*)') |
        ForEach-Object { $_.Groups['name'].Value } |
        Where-Object { $known -notcontains $_.ToLowerInvariant() }
      @($unresolved) | Should -BeNullOrEmpty
    }
  }

  Context 'Given every subroutine that opens a setlocal scope' {

    It 'When scanning its body, Then it also closes the scope with endlocal' {
      $offenders = foreach ($name in $regions.Keys) {
        $body = $regions[$name]
        $opens = @($body | Where-Object { $_ -match '^\s*setlocal\b' }).Count
        $closes = @($body | Where-Object { $_ -match '^\s*endlocal\b' }).Count
        if ($opens -gt 0 -and $closes -eq 0) { $name }
      }
      @($offenders) | Should -BeNullOrEmpty
    }
  }
}

Describe 'DeleteTraces.bat behavior' -Skip:($env:OS -ne 'Windows_NT') {

  # needs a real cmd.exe, so this block self-skips on non-Windows runners
  Context 'Given the wim tweak tool is not present next to the script' {

    BeforeAll {
      # run from an isolated sandbox so %~dp0.. can never contain the real tools
      $script:sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ('DeleteTraces.Tests_' + [guid]::NewGuid().ToString('N'))
      $bin = Join-Path $sandbox 'bin'
      $null = New-Item -ItemType Directory -Path $bin -Force
      Copy-Item -Path $batPath -Destination $bin
      $script:output = & $env:ComSpec /d /c (Join-Path $bin 'DeleteTraces.bat') 2>&1 | Out-String
    }

    AfterAll {
      if ($sandbox) { Remove-Item -Path $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'When executed, Then it warns about the missing tool' {
      $output | Should -Match '\[Warning\] Wim Tweak Tool not found'
    }

    It 'When executed, Then it aborts with an error message' {
      $output | Should -Match '\[Error\].+aborting'
    }

    It 'When executed, Then it performs no cleaning action at all' {
      # every action announces itself via DisplayTitle's "[Info]" line
      $output | Should -Not -Match '\[Info\]'
    }
  }
}
