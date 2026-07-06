<#
push_to_github.ps1
Pushes this project to a GitHub repository.

Usage:
    .\push_to_github.ps1 -RepoUrl "https://github.com/<username>/<repo>.git"

First run will trigger a browser-based GitHub login via Git Credential Manager
if you aren't already authenticated — no token needs to be pasted anywhere.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoUrl
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".git")) {
    Write-Host "No git repo here yet — running 'git init'..."
    git init
}

$existingRemote = git remote 2>$null
if ($existingRemote -contains "origin") {
    Write-Host "Remote 'origin' already set, updating URL..."
    git remote set-url origin $RepoUrl
} else {
    git remote add origin $RepoUrl
}

git branch -M main
git push -u origin main

Write-Host "Done. Pushed to $RepoUrl"
