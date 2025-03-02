#!/bin/bash

# Configurable Parameters
REPO_PATH="."
BRANCH_NAME="main"
PRIVATE_KEY_PATH="$HOME/.ssh/id_rsa"  # Update with your private key path
COMMIT_MESSAGE="Update files with latest changes"
DEBOUNCE_DELAY=1  # Minimal debounce delay for real-time updates

# Function to log messages with timestamps
log_message() {
    local MESSAGE_TYPE=$1
    local MESSAGE=$2
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$TIMESTAMP] [$MESSAGE_TYPE] $MESSAGE"
}

# Start SSH agent and add the private key
log_message "INFO" "Starting SSH agent..."
eval "$(ssh-agent -s)"

if ssh-add "$PRIVATE_KEY_PATH"; then
    log_message "INFO" "Private key added successfully."
else
    log_message "ERROR" "Failed to add private key. Please check your SSH key and try again."
    exit 1
fi

# Verify SSH connection to GitHub
log_message "INFO" "Verifying SSH connection to GitHub..."
if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
    log_message "INFO" "SSH connection to GitHub verified successfully."
else
    log_message "ERROR" "SSH connection to GitHub failed. Please check your SSH key and try again."
    exit 1
fi

# Change to the repository directory
cd "$REPO_PATH" || { log_message "ERROR" "Failed to change directory to $REPO_PATH"; exit 1; }

# Function to commit and push changes
commit_and_push() {
    if [[ -n $(git status -s) ]]; then
        git add .
        git commit -m "$COMMIT_MESSAGE"
        git push origin "$BRANCH_NAME"
        log_message "INFO" "Changes committed and pushed to $BRANCH_NAME."
    else
        log_message "INFO" "No changes to commit."
    fi
}

# Initial commit and push
commit_and_push

# Monitor the directory for changes using fswatch
log_message "INFO" "Monitoring directory for changes..."
fswatch -o -r "$REPO_PATH" --event-flags | while read -r event; do
    log_message "INFO" "File system change detected. Committing changes..."
    commit_and_push
    sleep "$DEBOUNCE_DELAY"
done