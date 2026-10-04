# Generate Pages CMS secrets for .env.local
# Usage: pwsh ./scripts/keygen.ps1
# Optional: pwsh ./scripts/keygen.ps1 -Copy  (copies block to clipboard)

[CmdletBinding()]
param(
  [switch]$Copy
)

function New-Base64UrlSecret {
  param([int]$Bytes = 32)
  $buffer = [byte[]]::new($Bytes)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
  return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# URL-safe (no + / =) so Vercel/env UIs do not mangle the value.
$betterAuthSecret = New-Base64UrlSecret -Bytes 32
$cryptoKey = New-Base64UrlSecret -Bytes 32
$webhookSecret = New-Base64UrlSecret -Bytes 32

$block = @"
BETTER_AUTH_SECRET="$betterAuthSecret"
CRYPTO_KEY="$cryptoKey"
GITHUB_APP_WEBHOOK_SECRET="$webhookSecret"
"@

Write-Output $block

if ($Copy) {
  Set-Clipboard -Value $block
  Write-Host "`nCopied to clipboard." -ForegroundColor Green
}
