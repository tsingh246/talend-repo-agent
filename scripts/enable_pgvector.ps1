param(
    [string]$HostName = "localhost",
    [int]$Port = 5432,
    [string]$Database = "talend_kb",
    [string]$User = "postgres",
    [string]$Password = "postgres"
)

$env:PGPASSWORD = $Password
$scriptPath = Join-Path $PSScriptRoot "enable_pgvector.sql"

if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
    Write-Host "psql was not found on PATH."
    Write-Host "Add your PostgreSQL bin folder to PATH, for example:"
    Write-Host "  C:\Program Files\PostgreSQL\16\bin"
    exit 1
}

psql -h $HostName -p $Port -U $User -d $Database -f $scriptPath

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "pgvector could not be enabled."
    Write-Host "If PostgreSQL says extension 'vector' is not available, install pgvector for your local PostgreSQL version first."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "pgvector is enabled for database '$Database'."
