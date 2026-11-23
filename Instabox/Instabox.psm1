$script:ModuleRoot = $PSScriptRoot

$classFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Classes') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($f in $classFiles) {
    . $f.FullName
}

$privateFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($f in $privateFiles) {
    . $f.FullName
}

$publicFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($f in $publicFiles) {
    . $f.FullName
}
