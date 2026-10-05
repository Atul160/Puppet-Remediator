package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"
)

// ==========================
// CONFIGURATION & STRUCTS
// ==========================

// RequestPayload defines the expected JSON input
type RequestPayload struct {
	Clients  []string `json:"clients" binding:"required"`
	OSType   string   `json:"os_type" binding:"required"` // "linux" or "windows"
	CAServer string   `json:"ca_server" binding:"required"`
}

// ResponseResult defines the output for each client
type ResponseResult struct {
	Client    string `json:"client"`
	Status    string `json:"status"` // SUCCESS, FAILED, REMEDIATED
	Summary   string `json:"summary"`
	RawOutput string `json:"raw_output,omitempty"`
}

// AppConfig holds environment variables
type AppConfig struct {
	SSHUser       string
	SSHPasswords  []string
	WinUser       string
	WinPassword   string
	WinPort       int
	Port          string
	PuppetVersion string
}

var config AppConfig

// initConfig loads environment variables from .env
func initConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}

	config.SSHUser = os.Getenv("SSH_USER")
	if config.SSHUser == "" {
		log.Fatal("SSH_USER is not set in environment")
	}

	// Passwords should be comma-separated in .env, e.g., PASSWORDS="pass1,pass2"
	pwds := os.Getenv("SSH_PASSWORDS")
	if pwds == "" {
		log.Fatal("SSH_PASSWORDS is not set in environment")
	}
	config.SSHPasswords = strings.Split(pwds, ",")

	// Windows Config
	config.WinUser = os.Getenv("WIN_USER")
	config.WinPassword = os.Getenv("WIN_PASSWORD")
	wPort := os.Getenv("WIN_PORT")
	if wPort == "" {
		config.WinPort = 5985 // Default WinRM HTTP
	} else {
		p, _ := strconv.Atoi(wPort)
		config.WinPort = p
	}

	config.Port = os.Getenv("PORT")
	if config.Port == "" {
		config.Port = "8080"
	}

	config.PuppetVersion = os.Getenv("PUPPET_VERSION")
	if config.PuppetVersion == "" {
		log.Println("PUPPET_VERSION not set. Version maintenance will be skipped.")
	}
}

// ==========================
// LINUX UTILITIES (SSH)
// ==========================

// SSHClient wraps the connection logic
type SSHClient struct {
	Client *ssh.Client
	Host   string
}

// ConnectWithRetries attempts to connect using the list of passwords
func ConnectWithRetries(host string) (*SSHClient, int, error) {
	// Ensure port 22 is attached if missing
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	var lastErr error

	// Try each password
	for i, pwd := range config.SSHPasswords {
		sshConfig := &ssh.ClientConfig{
			User: config.SSHUser,
			Auth: []ssh.AuthMethod{
				ssh.Password(strings.TrimSpace(pwd)),
			},
			// WARNING: InsecureIgnoreHostKey is used for ease of demo.
			// In Enterprise, use ssh.FixedHostKey(key) or parse known_hosts
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", host, sshConfig)
		if err == nil {
			return &SSHClient{Client: client, Host: host}, i, nil
		}
		lastErr = err
	}
	return nil, -1, fmt.Errorf("failed to auth with any provided credentials: %v", lastErr)
}

// Close closes the underlying SSH client
func (s *SSHClient) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

// runSudoWithPassword executes a command with sudo, piping the password to stdin
func (s *SSHClient) runSudoWithPassword(cmd string, password string) (string, error) {
	session, err := s.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// -S reads password from stdin, -p '' removes the prompt
	fullCmd := fmt.Sprintf("echo '%s' | sudo -S -p '' %s", password, cmd)

	var b bytes.Buffer
	var bErr bytes.Buffer
	session.Stdout = &b
	session.Stderr = &bErr

	if err := session.Run(fullCmd); err != nil {
		outputErr := bErr.String()
		// Check if error is due to password
		if strings.Contains(outputErr, "incorrect password") {
			return "", fmt.Errorf("AUTH_FAIL")
		}
		// Return exit code errors (like Puppet failing) as valid output
		if _, ok := err.(*ssh.ExitError); ok {
			// Combine stdout and stderr for full context
			return b.String() + "\n" + outputErr, err
		}
		return "", fmt.Errorf("failed to run: %s, stderr: %s", err, outputErr)
	}
	return b.String(), nil
}

// ==========================
// WINDOWS UTILITIES (WinRM)
// ==========================

// utf16leBytes encodes a string as UTF-16LE, the encoding PowerShell requires
// for -EncodedCommand payloads.
func utf16leBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		buf[i*2] = byte(u)
		buf[i*2+1] = byte(u >> 8)
	}
	return buf
}

func runWindowsCommand(host string, cmd string) (string, error) {
	endpoint := winrm.NewEndpoint(host, config.WinPort, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, config.WinUser, config.WinPassword)
	if err != nil {
		return "", err
	}

	// Create a shell process
	// Note: masterzen/winrm Run() returns exit code, stdout, stderr handling can be tricky
	stdout, stderr, rc, err := client.RunWithString(cmd, "")
	if err != nil {
		return "", err
	}
	if rc != 0 {
		return stdout + "\n" + stderr, fmt.Errorf("command failed with exit code %d", rc)
	}
	return stdout, nil
}

// ==========================
//  CORE LOGIC - LINUX
// ==========================

func handleLinuxCheck(clientHost, caHost string) ResponseResult {
	result := ResponseResult{Client: clientHost, Status: "UNKNOWN"}

	// 1. Connect to Client
	sshClient, pwdIdx, err := ConnectWithRetries(clientHost)
	if err != nil {
		result.Status = "CONN_FAIL"
		result.Summary = fmt.Sprintf("SSH failed: %v", err)
		return result
	}
	defer sshClient.Close()

	// Using the first password based returned index by ConnectWithRetries
	activePwd := strings.TrimSpace(config.SSHPasswords[pwdIdx])

	// Version-fix note is tracked separately and prepended to whatever summary
	// is ultimately returned, since later steps overwrite result.Summary.
	var versionNote string
	defer func() {
		if versionNote != "" {
			result.Summary = versionNote + result.Summary
		}
	}()

	// VERSION MAINTAINER BLOCK
	if config.PuppetVersion != "" {
		log.Printf("[%s] Checking Puppet version. Desired: %s", clientHost, config.PuppetVersion)

		verOut, err := sshClient.runSudoWithPassword("puppet --version", activePwd)
		clientVersion := strings.TrimSpace(verOut)

		if err == nil && clientVersion != "" && clientVersion != config.PuppetVersion {
			log.Printf("[%s] Version mismatch! Current: %s. Attempting to install %s...", clientHost, clientVersion, config.PuppetVersion)

			// Cross-platform install command (handles RedHat/CentOS and Debian/Ubuntu)
			// Use a shell wrapper so shell constructs and substitutions work over sudo,
			// and use dpkg -i with apt-get -f install fallback to resolve deps.
			// `set -e` plus `curl --fail` ensures a failed download or install aborts
			// with a nonzero exit code instead of silently falling through to apt-get -f
			// install (which succeeds even when nothing was actually installed).
			upgradeCmd := fmt.Sprintf(`bash -lc 'set -e
if command -v dpkg &> /dev/null; then
	curl -sS --fail -o /tmp/puppet_agent.deb "https://packages.gametools.dev/artifactory/tk2-systems-tools-debs/pool/puppet-agent_%s-1$(lsb_release -sc)_amd64.deb"
	DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/puppet_agent.deb || DEBIAN_FRONTEND=noninteractive apt-get -f install -y
	dpkg -l puppet-agent | grep -q "^ii.*%s"
elif command -v yum &> /dev/null; then
	yum install -y puppet-agent-%s
else
	echo "Unsupported package manager"
	exit 1
fi'`, config.PuppetVersion, config.PuppetVersion, config.PuppetVersion)

			_, installErr := sshClient.runSudoWithPassword(upgradeCmd, activePwd)

			// Re-verify the installed version rather than trusting the install
			// command's exit code alone (a silent no-op could still exit 0).
			postVerOut, postErr := sshClient.runSudoWithPassword("puppet --version", activePwd)
			postVersion := strings.TrimSpace(postVerOut)

			if installErr != nil {
				log.Printf("[%s] WARNING: Failed to install Puppet %s: %v", clientHost, config.PuppetVersion, installErr)
				versionNote = "[Version fix failed] "
			} else if postErr != nil || postVersion != config.PuppetVersion {
				log.Printf("[%s] WARNING: Install command succeeded but version is still %q, expected %q", clientHost, postVersion, config.PuppetVersion)
				versionNote = "[Version fix failed: post-install check mismatch] "
			} else {
				log.Printf("[%s] Successfully updated Puppet to %s", clientHost, config.PuppetVersion)
				versionNote = fmt.Sprintf("[Version enforced to %s] ", config.PuppetVersion)
			}
		} else if clientVersion == config.PuppetVersion {
			log.Printf("[%s] Puppet version %s matches target state.", clientHost, clientVersion)
		} else {
			log.Printf("[%s] Could not detect current Puppet version. Skipping enforcement.", clientHost)
		}
	}

	// 2. Run Diagnostic (Puppet Agent -t)
	// Valid exit codes: 0 (No changes), 2 (Changes applied). Everything else is an error.
	output, err := sshClient.runSudoWithPassword("puppet agent -t", activePwd)

	rc := 0
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			rc = exitErr.ExitStatus()
		} else {
			result.Status = "EXEC_FAIL"
			result.Summary = "Failed to execute diagnostic command"
			return result
		}
	}

	log.Printf("[%s] Diagnostic complete. Exit Code: %d, Status: %s", clientHost, rc, result.Status) // LOGGING ADDED

	if rc == 0 || rc == 2 {
		result.Status = "SUCCESS"
		result.Summary = "Puppet run completed successfully."
		result.RawOutput = output
		return result
	}

	// 3. Analyze Failure
	if !strings.Contains(output, "certificate verify failed") && !strings.Contains(output, "SSL_connect") {
		result.Status = "FAILED_OTHER"
		result.Summary = fmt.Sprintf("Puppet failed with non-cert issue (Exit: %d)", rc)
		result.RawOutput = output
		return result
	}

	// ==========================
	// REMEDIATION FLOW
	// ==========================
	result.Summary = "Cert issue detected. Attempting remediation..."

	// A. Get Client FQDN
	fqdnOut, _ := sshClient.runSudoWithPassword("facter fqdn", activePwd)
	clientFQDN := strings.TrimSpace(fqdnOut)
	if clientFQDN == "" {
		clientFQDN = clientHost
	}

	// B. Client: Remove SSL Dir
	_, err = sshClient.runSudoWithPassword("rm -rf /etc/puppetlabs/puppet/ssl/", activePwd)
	if err != nil {
		result.Status = "REMEDIATION_FAIL"
		result.Summary = "Could not remove SSL dir on client"
		return result
	}

	// C. Master: Connect & Revoke
	caSSH, capwdIdx, err := ConnectWithRetries(caHost)
	if err != nil {
		result.Status = "CA_CONN_FAIL"
		result.Summary = "Could not connect to CA Server"
		return result
	}
	defer caSSH.Close()

	// Use the CA's working password
	caActivePwd := strings.TrimSpace(config.SSHPasswords[capwdIdx])

	// Clean commands on Master
	caSSH.runSudoWithPassword(fmt.Sprintf("puppetserver ca revoke --certname %s", clientFQDN), caActivePwd)
	caSSH.runSudoWithPassword(fmt.Sprintf("puppetserver ca clean --certname %s", clientFQDN), caActivePwd)

	// D. ASYNC SIGNING PROCESS
	var wg sync.WaitGroup
	wg.Add(2)

	clientChan := make(chan string, 1)
	masterChan := make(chan string, 1)

	// Goroutine 1: Client Request
	go func() {
		defer wg.Done()
		// waitforcert=60 means it will retry for 60 seconds
		cmd := fmt.Sprintf("puppet agent -t --waitforcert=60 --server %s", caHost)
		out, _ := sshClient.runSudoWithPassword(cmd, activePwd)
		clientChan <- out
	}()

	// Goroutine 2: Master Sign
	go func() {
		defer wg.Done()
		// Wait 5 seconds to ensure Client CSR has reached the master
		time.Sleep(5 * time.Second)

		cmd := fmt.Sprintf("puppetserver ca sign --certname %s", clientFQDN)
		out, _ := caSSH.runSudoWithPassword(cmd, activePwd)
		masterChan <- out
	}()

	wg.Wait()
	close(clientChan)
	close(masterChan)

	clientOut := <-clientChan

	// E. Validation
	if strings.Contains(clientOut, "Applied catalog") || strings.Contains(clientOut, "compiled catalog") {
		result.Status = "REMEDIATED"
		result.Summary = "Certificates regenerated and catalog applied successfully."
		result.RawOutput = clientOut
	} else {
		result.Status = "REMEDIATION_FAIL"
		result.Summary = "Remediation attempted but Puppet run failed."
		result.RawOutput = clientOut
	}

	return result
}

// ==========================
// CORE LOGIC - WINDOWS
// ==========================

func handleWindowsCheck(clientHost, caHost string) ResponseResult {
	result := ResponseResult{Client: clientHost, Status: "UNKNOWN"}

	// Version-fix note is tracked separately and prepended to whatever summary
	// is ultimately returned, since later steps overwrite result.Summary.
	var versionNote string
	defer func() {
		if versionNote != "" {
			result.Summary = versionNote + result.Summary
		}
	}()

	// 1. Diagnostic Run
	// Windows Puppet agent location varies, but usually in PATH.
	// If not, use full path: '& "C:\Program Files\Puppet Labs\Puppet\bin\puppet.bat" agent -t'

	if config.PuppetVersion != "" {
		log.Printf("[%s] Checking Windows Puppet version. Desired: %s", clientHost, config.PuppetVersion)

		verOut, err := runWindowsCommand(clientHost, "puppet --version")
		clientVersion := strings.TrimSpace(verOut)

		if err == nil && clientVersion != "" && clientVersion != config.PuppetVersion {
			log.Printf("[%s] Version mismatch! Current: %s. Attempting to install MSI %s...", clientHost, clientVersion, config.PuppetVersion)

			// Download MSI from Artifactory and install silently.
			// RunWithString executes via cmd.exe, so the script is passed to
			// powershell -EncodedCommand (base64 UTF-16LE) rather than as raw
			// PowerShell text — this avoids cmd.exe quoting issues with the
			// embedded quotes/variables and matches how other Windows calls in
			// this file invoke powershell explicitly.
			// $ErrorActionPreference = 'Stop' makes Invoke-WebRequest throw (and thus
			// return a nonzero exit code via runWindowsCommand) on a failed download,
			// and the msiexec exit code is checked explicitly since Start-Process -Wait
			// does not itself throw on a nonzero installer exit code.
			// Note: Update the URL to match your exact Windows artifacts repository
			upgradeScript := fmt.Sprintf(`
				$ErrorActionPreference = 'Stop'
				$url = 'https://packages.gametools.dev/artifactory/tk2-systems-tools-windows/puppet-agent-%s-x64.msi'
				$dest = 'C:\Windows\Temp\puppet_agent.msi'
				Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
				$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/qn', '/i', $dest -Wait -NoNewWindow -PassThru
				Remove-Item -Force $dest -ErrorAction SilentlyContinue
				if ($proc.ExitCode -ne 0) {
					Write-Error "msiexec failed with exit code $($proc.ExitCode)"
					exit $proc.ExitCode
				}
			`, config.PuppetVersion)
			encodedScript := base64.StdEncoding.EncodeToString(utf16leBytes(upgradeScript))
			upgradeCmd := "powershell -NoProfile -NonInteractive -EncodedCommand " + encodedScript

			_, installErr := runWindowsCommand(clientHost, upgradeCmd)

			// Re-verify the installed version rather than trusting the install
			// command's exit code alone.
			postVerOut, postErr := runWindowsCommand(clientHost, "puppet --version")
			postVersion := strings.TrimSpace(postVerOut)

			if installErr != nil {
				log.Printf("[%s] WARNING: Failed to install Puppet %s: %v", clientHost, config.PuppetVersion, installErr)
				versionNote = "[Version fix failed] "
			} else if postErr != nil || postVersion != config.PuppetVersion {
				log.Printf("[%s] WARNING: Install command succeeded but version is still %q, expected %q", clientHost, postVersion, config.PuppetVersion)
				versionNote = "[Version fix failed: post-install check mismatch] "
			} else {
				log.Printf("[%s] Successfully updated Puppet to %s", clientHost, config.PuppetVersion)
				versionNote = fmt.Sprintf("[Version enforced to %s] ", config.PuppetVersion)
			}
		} else if clientVersion == config.PuppetVersion {
			log.Printf("[%s] Puppet version %s matches target state.", clientHost, clientVersion)
		} else {
			log.Printf("[%s] Could not detect current Puppet version. Skipping enforcement.", clientHost)
		}
	}

	// We use PowerShell to wrap the call
	cmdCheck := "puppet agent -t --color=false"
	output, err := runWindowsCommand(clientHost, cmdCheck)

	// Puppet exit codes are same on Windows (0 or 2 is success)
	// However, WinRM library might return error struct on non-zero exit code depending on implementation.
	// We handle the text output primarily.

	if err == nil || (strings.Contains(output, "Applied catalog") && !strings.Contains(output, "certificate verify failed")) {
		result.Status = "SUCCESS"
		result.Summary = "Puppet run completed successfully."
		result.RawOutput = output
		return result
	}

	// 2. Analyze Failure
	if !strings.Contains(output, "certificate verify failed") && !strings.Contains(output, "SSL_connect") {
		result.Status = "FAILED_OTHER"
		result.Summary = "Puppet failed with non-cert issue."
		result.RawOutput = output + "\nError: " + fmt.Sprintf("%v", err)
		return result
	}

	// ==========================
	// REMEDIATION FLOW
	// ==========================
	result.Summary = "Cert issue detected. Attempting Windows remediation..."

	// A. Get Client FQDN
	fqdnOut, _ := runWindowsCommand(clientHost, "facter fqdn")
	clientFQDN := strings.TrimSpace(fqdnOut)
	if clientFQDN == "" {
		clientFQDN = clientHost // Fallback
	}

	// B. Client: Remove SSL Dir
	// Windows Path: C:\ProgramData\PuppetLabs\puppet\etc\ssl (Check your version)
	// Or usually: C:\ProgramData\PuppetLabs\puppet\ssl
	rmCmd := "Remove-Item -Path 'C:\\ProgramData\\PuppetLabs\\puppet\\ssl' -Recurse -Force"
	_, err = runWindowsCommand(clientHost, "powershell -Command \""+rmCmd+"\"")
	if err != nil {
		result.Status = "REMEDIATION_FAIL"
		result.Summary = "Could not remove SSL dir on Windows client"
		result.RawOutput = fmt.Sprintf("%v", err)
		return result
	}

	// C. Master: Connect & Revoke (SSH to Linux CA)
	// We reuse the Linux SSH logic to talk to the Master
	caSSH, capwdIdx, err := ConnectWithRetries(caHost)
	if err != nil {
		result.Status = "CA_CONN_FAIL"
		result.Summary = "Could not connect to CA Server"
		return result
	}
	defer caSSH.Close()

	// Clean commands on Master
	// Assuming sudo password is the first one in list
	caActivePwd := strings.TrimSpace(config.SSHPasswords[capwdIdx])
	caSSH.runSudoWithPassword(fmt.Sprintf("puppetserver ca revoke --certname %s", clientFQDN), caActivePwd)
	caSSH.runSudoWithPassword(fmt.Sprintf("puppetserver ca clean --certname %s", clientFQDN), caActivePwd)

	// D. ASYNC SIGNING PROCESS
	var wg sync.WaitGroup
	wg.Add(2)

	clientChan := make(chan string, 1)
	masterChan := make(chan string, 1)

	// Goroutine 1: Windows Client Request
	go func() {
		defer wg.Done()
		// Windows waitforcert
		cmd := fmt.Sprintf("puppet agent -t --waitforcert=60 --server %s --color=false", caHost)
		out, _ := runWindowsCommand(clientHost, cmd)
		clientChan <- out
	}()

	// Goroutine 2: Master Sign (Linux)
	go func() {
		defer wg.Done()
		time.Sleep(8 * time.Second) // Give Windows a bit more time to network negotiation
		cmd := fmt.Sprintf("puppetserver ca sign --certname %s", clientFQDN)
		out, _ := caSSH.runSudoWithPassword(cmd, caActivePwd)
		masterChan <- out
	}()

	wg.Wait()
	close(clientChan)
	close(masterChan)

	clientOut := <-clientChan

	// E. Validation
	if strings.Contains(clientOut, "Applied catalog") || strings.Contains(clientOut, "compiled catalog") {
		result.Status = "REMEDIATED"
		result.Summary = "Certificates regenerated and catalog applied successfully."
		result.RawOutput = clientOut
	} else {
		result.Status = "REMEDIATION_FAIL"
		result.Summary = "Remediation attempted but Puppet run failed."
		result.RawOutput = clientOut
	}

	return result
}

// ==========================
// API HANDLERS
// ==========================

func main() {
	initConfig()                 // Load .env
	gin.SetMode(gin.ReleaseMode) // Set to release for production
	r := gin.Default()

	r.POST("/remediate-puppet", func(c *gin.Context) {
		var jsonPayload RequestPayload
		if err := c.ShouldBindJSON(&jsonPayload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate OS Type
		osType := strings.ToLower(jsonPayload.OSType)
		if osType != "linux" && osType != "windows" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "os_type must be 'linux' or 'windows'"})
			return
		}

		log.Printf("Received puppet remediation request for %d clients ", len(jsonPayload.Clients)) // LOGGING ADDED

		// Parallel processing using Goroutines for multiple clients
		// Limitation: Be careful with too many parallel SSH connections
		var wg sync.WaitGroup
		results := make([]ResponseResult, len(jsonPayload.Clients))

		for i, client := range jsonPayload.Clients {
			wg.Add(1)
			go func(idx int, clientHost string) {
				defer wg.Done()
				if osType == "linux" {
					results[idx] = handleLinuxCheck(clientHost, jsonPayload.CAServer)
				} else {
					results[idx] = handleWindowsCheck(clientHost, jsonPayload.CAServer)
				}
			}(i, client)
		}
		wg.Wait()

		c.JSON(http.StatusOK, gin.H{"results": results})
	})

	log.Printf("Starting Puppet Remediator API on port %s...", config.Port)
	if err := r.Run(":" + config.Port); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
