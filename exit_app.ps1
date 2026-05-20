param(
    [string]$ExeName = "EZ-OpenVPN-Toolkit-Web.exe",
    [int]$DelayMs = 900
)

# Allow API response to complete before killing the app process tree.
Start-Sleep -Milliseconds $DelayMs

taskkill /F /IM "$ExeName" *> $null
