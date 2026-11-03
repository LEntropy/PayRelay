# Runs every test and writes test-results\report.html
#   1) C unit tests, built with AddressSanitizer + UBSan
#   2) JavaScript codec tests (cross-checked against frames from the C gateway)
#   3) fresh gateway start, then the end-to-end test (normal, attack, reconciliation, load)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force test-results | Out-Null

Write-Host "`n==== [1/4] C unit tests (ASan + UBSan) ====" -ForegroundColor Cyan
docker build -q -t payrelay-build -f docker/build.Dockerfile docker | Out-Null
docker run --rm -v "${PSScriptRoot}:/src" -w /src payrelay-build bash -c "make -s clean && make -s bin/test_common SANITIZE=1 && ./bin/test_common; s=`$?; make -s clean; exit `$s" | Tee-Object -FilePath test-results/unit_c.txt
$c = $LASTEXITCODE

Write-Host "`n==== [2/4] Start the stack ====" -ForegroundColor Cyan
docker compose up -d --build
# Restart the gateway so the end-to-end test starts on a fresh process (first-connection regression).
docker compose restart gateway | Out-Null
Start-Sleep -Seconds 4

Write-Host "`n==== [3/4] JavaScript codec tests ====" -ForegroundColor Cyan
docker compose exec -T admin node --test --test-reporter=tap test/ | Tee-Object -FilePath test-results/unit_js.txt
$js = $LASTEXITCODE

Write-Host "`n==== [4/4] End-to-end test ====" -ForegroundColor Cyan
docker compose --profile test run --rm --build tester
$e2e = $LASTEXITCODE

python tools/make_report.py
Write-Host "Report: $PSScriptRoot\test-results\report.html" -ForegroundColor Green
if ($c -ne 0 -or $js -ne 0 -or $e2e -ne 0) { exit 1 }
