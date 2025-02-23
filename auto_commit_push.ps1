# auto_commit_push.ps1
param (
    [string]$RepoPath = ".",
    [string]$BranchName = "main",
    [string]$PrivateKeyPath = "C:\Playson\playson_toolbox_extension",
    [string]$CommitMessage = "Update files with latest changes",
    [int]$PollInterval = 1,  # Poll every second
    [string]$RemoteUrl = "git@github.com:manuel-veladojr/playson-toolbox-extension.git"
)

# Function to log messages with timestamps
function Log-Message {
    param (
        [string]$Message,
        [string]$Type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Type] $Message"
}

# Start SSH agent and set environment variables
Log-Message "Starting SSH agent..."
$sshAgentOutput = & ssh-agent -s | Out-String
if ($sshAgentOutput -match "Agent pid") {
    Log-Message "SSH agent started successfully."
    foreach ($line in $sshAgentOutput -split "`n") {
        if ($line -match "SSH_AUTH_SOCK=([^;]+);") {
            $env:SSH_AUTH_SOCK = $matches[1]
        }
        if ($line -match "SSH_AGENT_PID=([^;]+);") {
            $env:SSH_AGENT_PID = $matches[1]
        }
    }
} else {
    Log-Message "Failed to start SSH agent." "ERROR"
    exit 1
}

Start-Sleep -Seconds 2

# Add the private key
Log-Message "Adding private key..."
$sshAddResult = & ssh-add $PrivateKeyPath 2>&1
if ($sshAddResult -match "Identity added") {
    Log-Message "Private key added successfully."
} else {
    Log-Message "Failed to add private key. Please check your SSH key and try again." "ERROR"
    Log-Message $sshAddResult "ERROR"
    exit 1
}

# Verify SSH connection to GitHub
Log-Message "Verifying SSH connection to GitHub..."
$sshTestResult = & ssh -T git@github.com 2>&1
if ($sshTestResult -like "*successfully authenticated*") {
    Log-Message "SSH connection to GitHub verified successfully."
} else {
    Log-Message "SSH connection to GitHub failed. Please check your SSH key and try again." "ERROR"
    Log-Message $sshTestResult "ERROR"
    exit 1
}

# Change to the repository directory
Set-Location -Path $RepoPath

# Initialize repository if needed
try {
    $isGitRepoOutput = git rev-parse --is-inside-work-tree 2>$null
    if ([string]::IsNullOrEmpty($isGitRepoOutput) -or $isGitRepoOutput.Trim() -ne "true") {
        Log-Message "Directory '$RepoPath' is not a Git repository. Initializing a new Git repository..." "INFO"
        git init | Out-Null
        $headExists = git rev-parse HEAD 2>$null
        if ([string]::IsNullOrEmpty($headExists)) {
            Log-Message "No commits found. Creating an initial empty commit..." "INFO"
            git commit --allow-empty -m "Initial commit" | Out-Null
        }
    }
} catch {
    Log-Message "Error checking Git repository status: $_" "ERROR"
    exit 1
}

# Ensure on desired branch
$currentBranch = git rev-parse --abbrev-ref HEAD 2>$null
if ($currentBranch -eq "HEAD" -or [string]::IsNullOrEmpty($currentBranch)) {
    Log-Message "No branch detected. Creating and switching to branch '$BranchName'..."
    git checkout -B $BranchName | Out-Null
} elseif ($currentBranch -ne $BranchName) {
    Log-Message "Current branch is '$currentBranch'. Switching to branch '$BranchName'..."
    git checkout -B $BranchName | Out-Null
}

# Configure remote repository
try {
    $existingRemoteUrl = (git remote get-url origin 2>$null).Trim()
} catch {
    $existingRemoteUrl = ""
}
if ([string]::IsNullOrEmpty($existingRemoteUrl)) {
    if (-not [string]::IsNullOrEmpty($RemoteUrl)) {
        Log-Message "No remote configured. Adding remote 'origin' with URL $RemoteUrl" "INFO"
        git remote add origin $RemoteUrl
    } else {
        Log-Message "WARNING: No remote repository configured. Changes will be committed locally but cannot be pushed." "WARNING"
    }
} elseif (-not [string]::IsNullOrEmpty($RemoteUrl) -and $existingRemoteUrl -ne $RemoteUrl) {
    Log-Message "Remote 'origin' is configured with URL '$existingRemoteUrl'. Updating remote URL to '$RemoteUrl'..." "INFO"
    git remote remove origin
    git remote add origin $RemoteUrl
}

# Function to commit and force push changes
function CommitAndPush {
    $statusResult = git status -s
    if (-not [string]::IsNullOrEmpty($statusResult)) {
        git add .
        $commitResult = git commit -m $CommitMessage 2>&1
        Write-Output "`n$commitResult"
        $pushResult = git push --force origin $BranchName 2>&1
        Write-Output "`n$pushResult"
    } else {
        Write-Output "`nNothing to commit, working tree clean."
    }
}

# Polling loop to check for changes every $PollInterval seconds
Log-Message "Starting polling loop to check for changes every $PollInterval seconds..."
while ($true) {
    Start-Sleep -Seconds $PollInterval
    $statusResult = git status -s
    if (-not [string]::IsNullOrEmpty($statusResult)) {
        Log-Message "Changes detected. Committing and pushing..."
        CommitAndPush
    } else {
        Log-Message "No changes detected."
    }
}