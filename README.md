# Terabox CLI Usage Guide

This document provides instructions on how to set up and use the Terabox Command-Line Interface.

## Prerequisites

- A Debian-based Linux distribution (e.g., Ubuntu) or any OS with Python support.
- Python 3.8+
- `sudo` privileges may be required for initial setup on some systems.

## Installation and Setup

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/your-username/your-repository-name
    cd your-repository-name
    ```

2.  **Install Dependencies**

    Install the required Python packages using pip.
    ```bash
    pip install -r requirements.txt
    ```
    *(If no `requirements.txt` is present, install manually)*
    ```bash
    pip install requests playwright cryptography tqdm
    ```

3.  **Install Browser Binaries**

    Playwright requires browser files for automation. This command will download them.
    ```bash
    playwright install
    ```

4.  **Add Your First Terabox Account**

    You must add at least one account to use the script. This command will open a browser to automate the login and save your session.
    ```bash
    python terabox.py add primary
    ```
    Enter your email and password when prompted in the terminal. A browser window will appear and log in for you; do not interact with it.

---

## Command Reference

All commands follow the structure: `python terabox.py [flag] <command> [arguments]`

### Account Flags
-   `--primary`: Use the primary account (default).
-   `--secondary <N>`: Use a secondary account (e.g., `--secondary 1`).

### Core Commands

-   **`add <role>`**
    Adds a new account. `role` can be `primary` or `secondary`.
    ```bash
    # Add an additional account
    python terabox.py add secondary
    ```

-   **`upload [option] <local_path>`**
    Uploads a file.
    -   `--secure`: Encrypts the file before uploading (recommended).
    -   `--insecure`: Uploads the file directly.
    ```bash
    # Securely upload a file
    python terabox.py upload --secure "My Project.zip"
    
    # Upload a file to a secondary account
    python terabox.py --secondary 1 upload --insecure "public-document.pdf"
    ```

-   **`decrypt <local_path>`**
    Decrypts a local `.enc` file created by this tool.
    ```bash
    python terabox.py decrypt "My Project.[uuid].enc"
    ```

-   **`keys`**
    Lists all saved encryption keys from the local database.
    ```bash
    python terabox.py keys
    ```

### File Management Commands

-   **`ls [remote_path]`**
    Lists files and directories on Terabox. Defaults to the root directory (`/`).
    ```bash
    # List files in the root
    python terabox.py ls
    
    # List files in a specific folder
    python terabox.py ls /my_backups/
    ```

-   **`mkdir <remote_path>`**
    Creates a new directory on Terabox.
    ```bash
    python terabox.py mkdir "/my_backups/2024-archive"
    ```

-   **`mv <source> <destination>`**
    Moves a file or directory.
    ```bash
    python terabox.py mv "/file.txt" "/new_folder/"
    ```

-   **`cp <source> <destination>`**
    Copies a file or directory.
    ```bash
    python terabox.py cp "/file.txt" "/archive_folder/"
    ```

-   **`rm <paths...>`**
    Deletes one or more files/directories.
    ```bash
    # Delete a single file
    python terabox.py rm "/old_file.zip"
    
    # Delete multiple items
    python terabox.py rm "/temp_folder/" "/another_old_file.txt"
    ```
