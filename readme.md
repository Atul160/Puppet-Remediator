# Puppet Remediator API

A lightweight, Go API designed to automate the remediation of Puppet SSL certificate issues (expiration, mismatch, or corruption) across a fleet of Linux servers.

## Features
-   **Multi-OS Support:** 
    -   **Linux:** Uses SSH + Sudo.
    -   **Windows:** Uses WinRM + PowerShell.
-   **Automated Diagnostics:** Checks if `puppet agent -t` is healthy via SSH before attempting any fixes.
-   **Smart Remediation:** If certificates are invalid, it automatically:
    1.  Cleans the local SSL directory on the client.
    2.  Revokes and cleans the certificate on the Puppet CA.
    3.  Orchestrates an asynchronous re-signing process (Client requests -> Master signs).
-   **Credential Rotation:** Supports multiple SSH passwords (e.g., for rotating admin credentials) via `.env`.
-   **Concurrency:** Handles multiple client requests in parallel using Goroutines.
-   **Secure Configuration:** Separation of code and credentials using environment variables.

## Prerequisites

-   **Go**: Version 1.18 or higher.
-   **Network Access**: The host running this API must have SSH access (port 22) to both the target Clients and the Puppet CA.
-   **Sudo Privileges**: The `SSH_USER` must have sudo rights on target machines (specifically for `puppet`, `rm`, and `facter`).

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://your-repo/puppet-remediator.git
    cd puppet-remediator
    ```

2.  **Initialize the module & Install dependencies:**
    ```bash
    go mod init puppet-remediator
    go get github.com/gin-gonic/gin # (https://github.com/gin-gonic/gin)
    go get golang.org/x/crypto/ssh
    go get github.com/joho/godotenv # (https://github.com/joho/godotenv)
    ```
    If you come across any network related errors during downloading dependencies, run below:
    ```bash
    # Set GOPROXY to direct
    go env -w GOPROXY=direct

    # Retry the tidy or build command
    go mod tidy
    ```

3.  **Configure Environment Variables:**
    Create a `.env` file in the root directory:
    ```ini
    # --- Linux Credentials (SSH) ---
    SSH_USER=t2admin
    SSH_PASSWORDS=LinuxPwd1!,LinuxPwd2!
    
    # --- Windows Credentials (WinRM) ---
    WIN_USER=Administrator
    WIN_PASSWORD=WinSecretPassword!
    WIN_PORT=5985 # Default 5985 for HTTP, 5986 for HTTPS

    # Server Port
    PORT=8080
    
    # Gin Framework Mode (debug or release ot test)
    GIN_MODE=release
    ```

4.  **Start the Server:**
    ```bash
    go run main.go
    ```
    *Output:* `[GIN-debug] Listening and serving HTTP on :8080`

---

## API Reference

### Remediate Puppet Clients

**Endpoint:** `POST /remediate-puppet`

Triggers the diagnostic and remediation workflow for a list of clients against a specific Certificate Authority (CA) server.

#### Request Body

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `clients` | `[]string` | **Required**. An array of IP addresses or FQDNs of the target client servers. |
| `ca_server` | `string` | **Required**. The IP address or FQDN of the Puppet Master/CA server. |
| `os_type` | `string` | **Required**. Either `"linux"` or `"windows"`. |

**Sample JSON:**
```json
{
    "clients": [
        "web-server-01.example.com",
        "192.168.10.55"
    ],
    "ca_server": "puppet-ca.example.com",
    "os_type": "windows",
}
```

### Example Usage (cURL)
```json
curl -X POST http://localhost:8080/remediate-puppet \
     -H "Content-Type: application/json" \
     -d '{
           "clients": ["10.20.30.40", "10.20.30.41"], 
           "ca_server": "10.10.10.100",
           "os_type": "windows",
         }'
```

### Sample JSON Response:
```json
{
    "results": [
        {
            "client": "10.20.30.40",
            "status": "SUCCESS",
            "summary": "Puppet run completed successfully.",
            "raw_output": "Info: Using configured environment 'production'..."
        },
        {
            "client": "10.20.30.41",
            "status": "REMEDIATED",
            "summary": "Certificates regenerated and catalog applied successfully.",
            "raw_output": "Info: Creating a new SSL key...\nNotice: Signed certificate request for..."
        }
    ]
}
```

### Status Codes & Definitions

The `status` field in the response object will contain one of the following values:

| Status Value | Meaning |
| :--- | :--- |
| `SUCCESS` | The Puppet agent is healthy. No remediation was needed. |
| `REMEDIATED` | Certificate issues were found and successfully fixed. The agent run completed. |
| `CONN_FAIL` | Failed to establish an SSH connection to the client (Network/Auth issue). |
| `CA_CONN_FAIL` | Failed to establish an SSH connection to the CA Server. |
| `EXEC_FAIL` | SSH connection succeeded, but command execution failed (e.g., Sudo password incorrect). |
| `REMEDIATION_FAIL` | Attempted to fix certificates, but the signing process or subsequent agent run failed. |
| `FAILED_OTHER` | The Puppet agent failed for reasons unrelated to certificates (e.g., syntax error in manifest). |