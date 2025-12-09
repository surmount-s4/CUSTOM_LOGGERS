package detector

import (
	"regexp"
	"strings"

	"uls-detection-server/internal/models"
)

// Detector handles security event detection
type Detector struct {
	// Compiled regex patterns for performance
	patterns map[string]*regexp.Regexp
}

// New creates a new Detector instance
func New() *Detector {
	d := &Detector{
		patterns: make(map[string]*regexp.Regexp),
	}
	d.compilePatterns()
	return d
}

// compilePatterns pre-compiles regex patterns for better performance
func (d *Detector) compilePatterns() {
	patternDefs := map[string]string{
		// Execution patterns
		"powershell_encoded":    `(?i)-e(nc(odedcommand)?)?[\s]+[A-Za-z0-9+/=]{20,}`,
		"powershell_download":   `(?i)(downloadstring|downloadfile|invoke-webrequest|iwr|wget|curl)`,
		"powershell_bypass":     `(?i)(-ep\s+bypass|-executionpolicy\s+bypass|set-executionpolicy\s+bypass)`,
		"powershell_hidden":     `(?i)(-w\s+hidden|-windowstyle\s+hidden)`,
		"powershell_noprofile":  `(?i)-nop(rofile)?`,
		"base64_pattern":        `[A-Za-z0-9+/]{50,}={0,2}`,
		"cmd_suspicious":        `(?i)(whoami|net\s+(user|localgroup|group)|systeminfo|ipconfig|netstat|tasklist)`,
		
		// Defense Evasion patterns
		"amsi_bypass":           `(?i)(amsi|antimalware)`,
		"etw_bypass":            `(?i)(etw|eventtrace)`,
		"disable_defender":      `(?i)(disable|remove).*defender`,
		"clear_logs":            `(?i)(wevtutil\s+cl|clear-eventlog)`,
		
		// Credential Access patterns
		"mimikatz":              `(?i)(mimikatz|sekurlsa|logonpasswords|kerberos::)`,
		"lsass_access":          `(?i)lsass`,
		"sam_dump":              `(?i)(sam|system|security).*dump`,
		"credential_file":       `(?i)(\.rdg|\.vnc\.config|credentials|password)`,
		
		// Lateral Movement patterns
		"psexec":                `(?i)psexec`,
		"wmi_exec":              `(?i)(wmic|invoke-wmimethod|get-wmiobject).*process`,
		"winrm":                 `(?i)(winrm|invoke-command|enter-pssession)`,
		"rdp_hijack":            `(?i)tscon`,
		
		// Persistence patterns
		"scheduled_task":        `(?i)(schtasks|at\s+\d|new-scheduledtask)`,
		"registry_run":          `(?i)(currentversion\\run|currentversion\\runonce)`,
		"service_create":        `(?i)(sc\s+create|new-service)`,
		"wmi_subscription":      `(?i)(eventsubscription|commandlinetemplate)`,
		
		// Discovery patterns
		"domain_trust":          `(?i)(nltest|dsquery|get-adtrust)`,
		"network_share":         `(?i)(net\s+share|net\s+view)`,
		"ad_recon":              `(?i)(get-adcomputer|get-aduser|get-adgroup)`,
		
		// C2 patterns
		"dns_txt":               `(?i)(nslookup.*txt|resolve-dnsname.*txt)`,
		"cobalt_beacon":         `(?i)(beacon|cobaltstrike)`,
		"suspicious_port":       `(?i)(4444|5555|8080|8443|1337)`,
		
		// Exfiltration patterns
		"archive_data":          `(?i)(compress-archive|7z|rar|zip).*(-p|password)`,
		"cloud_upload":          `(?i)(dropbox|gdrive|onedrive|mega|pastebin)`,
		
		// Impact patterns
		"ransomware":            `(?i)(encrypt|ransom|bitcoin|\.locked|\.encrypted)`,
		"shadow_delete":         `(?i)(vssadmin|wmic\s+shadowcopy|delete\s+shadows)`,
		"bcdedit":               `(?i)bcdedit.*(recoveryenabled|bootstatuspolicy)`,
	}

	for name, pattern := range patternDefs {
		d.patterns[name] = regexp.MustCompile(pattern)
	}
}

// Detect applies all detection rules to an event and returns results
func (d *Detector) Detect(event *models.SecurityEvent) models.DetectionResult {
	result := models.DetectionResult{
		Severity:       "INFO",
		MitreTechnique: "",
		DetectionModule: "",
		EventDetails:   "",
	}

	// Get key fields for detection
	logSource := strings.ToLower(event.LogSource5)
	eventID := event.EventID0
	image := strings.ToLower(event.Image2)
	cmdLine := strings.ToLower(event.CommandLine2)
	parentImage := strings.ToLower(event.ParentImage2)
	targetFilename := strings.ToLower(event.TargetFilename2)
	destPort := event.DestinationPort2
	destIP := event.DestinationIp2
	targetObject := strings.ToLower(event.TargetObject2)
	grantedAccess := event.GrantedAccess2
	pipeName := strings.ToLower(event.PipeName2)

	// Security log specific fields
	logonType := event.LogonType3
	targetUser := event.TargetUserName3
	ipAddress := event.IpAddress3
	serviceName := event.ServiceName3
	serviceFileName := strings.ToLower(event.ServiceFileName3)
	taskName := event.TaskName3
	newProcessName := strings.ToLower(event.NewProcessName3)

	// ==================== SYSMON DETECTIONS ====================
	if strings.Contains(logSource, "sysmon") {
		switch eventID {
		case "1": // Process Creation
			result = d.detectProcessCreation(image, cmdLine, parentImage, event)
			if result.MitreTechnique != "" {
				return result
			}
			// Try additional detections
			result = d.detectCollection(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectDiscovery(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectCredentialAccessAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectLateralMovementAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectCommandAndControlAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectExfiltrationAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectImpactAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectPrivilegeEscalationAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectExecutionAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
			result = d.detectInitialAccessAdditional(event)
			if result.MitreTechnique != "" {
				return result
			}
		case "3": // Network Connection
			result = d.detectNetworkConnection(image, destPort, destIP, event)
		case "7": // Image Loaded
			result = d.detectImageLoad(event)
			if result.MitreTechnique != "" {
				return result
			}
			// Try collection detection for DLL loads
			result = d.detectCollection(event)
		case "8": // CreateRemoteThread
			result = d.detectRemoteThread(event)
		case "10": // ProcessAccess
			result = d.detectProcessAccess(image, grantedAccess, event)
		case "11": // FileCreate
			result = d.detectFileCreate(targetFilename, event)
			if result.MitreTechnique != "" {
				return result
			}
			// Try collection detection
			result = d.detectCollection(event)
		case "12", "13", "14": // Registry events
			result = d.detectRegistryEvent(targetObject, event)
		case "17", "18": // Pipe events
			result = d.detectPipeEvent(pipeName, event)
		case "22": // DNS Query
			result = d.detectDNSQuery(event)
			if result.MitreTechnique != "" {
				return result
			}
			// Try C2 and exfiltration detection
			result = d.detectCommandAndControlAdditional(event)
		case "23": // FileDelete
			result = d.detectFileDelete(targetFilename, event)
			if result.MitreTechnique != "" {
				return result
			}
			// Try impact detection for deletions
			result = d.detectImpactAdditional(event)
		}
	}

	// ==================== SECURITY LOG DETECTIONS ====================
	if strings.Contains(logSource, "security") {
		switch eventID {
		case "4624": // Successful Logon
			result = d.detectLogonSuccess(logonType, targetUser, ipAddress, event)
		case "4625": // Failed Logon
			result = d.detectLogonFailure(logonType, targetUser, ipAddress, event)
		case "4648": // Explicit Credentials
			result = d.detectExplicitCredentials(event)
		case "4672": // Special Privileges Assigned
			result = d.detectPrivilegeAssignment(event)
		case "4688": // Process Creation
			result = d.detectSecurityProcessCreation(newProcessName, event)
		case "4697": // Service Installed
			result = d.detectServiceInstall(serviceName, serviceFileName, event)
		case "4698", "4702": // Scheduled Task
			result = d.detectScheduledTaskCreation(taskName, event)
		case "4720": // User Account Created
			result = d.detectUserCreation(event)
		case "4732": // Member Added to Local Group
			result = d.detectGroupMembership(event)
		case "4768": // Kerberos TGT Request
			result = d.detectKerberosTGT(event)
		case "4769": // Kerberos Service Ticket
			result = d.detectKerberosServiceTicket(event)
		case "4776": // NTLM Authentication
			result = d.detectNTLMAuth(event)
		case "4778", "4779": // RDP Session
			result = d.detectRDPSession(eventID, event)
		case "5140": // Network Share Access
			result = d.detectShareAccess(event)
		}
	}

	// ==================== SYSTEM LOG DETECTIONS ====================
	if strings.Contains(logSource, "system") {
		switch eventID {
		case "7045": // Service Installed
			result = d.detectSystemServiceInstall(serviceName, serviceFileName, event)
		case "7036": // Service State Change
			result = d.detectServiceStateChange(event)
		case "104": // Log Cleared
			result = d.detectLogCleared(event)
		}
	}

	return result
}

// ==================== PROCESS CREATION DETECTIONS ====================

func (d *Detector) detectProcessCreation(image, cmdLine, parentImage string, event *models.SecurityEvent) models.DetectionResult {
	result := models.DetectionResult{Severity: "INFO"}

	// PowerShell detections
	if strings.Contains(image, "powershell") || strings.Contains(image, "pwsh") {
		// T1059.001 - PowerShell
		if d.patterns["powershell_encoded"].MatchString(cmdLine) {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1059.001",
				DetectionModule: "Execution",
				EventDetails:    "Encoded PowerShell command detected",
				AdditionalContext: "Base64 encoded command execution is commonly used to evade detection",
			}
		}
		if d.patterns["powershell_download"].MatchString(cmdLine) {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1059.001,T1105",
				DetectionModule: "Execution",
				EventDetails:    "PowerShell download cradle detected",
				AdditionalContext: "File download via PowerShell may indicate malware delivery",
			}
		}
		if d.patterns["powershell_bypass"].MatchString(cmdLine) && d.patterns["powershell_hidden"].MatchString(cmdLine) {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1059.001,T1564.003",
				DetectionModule: "Execution",
				EventDetails:    "Hidden PowerShell with execution policy bypass",
				AdditionalContext: "Combination of hidden window and bypass suggests malicious intent",
			}
		}
		if d.patterns["amsi_bypass"].MatchString(cmdLine) {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1562.001",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "AMSI bypass attempt detected",
				AdditionalContext: "Antimalware Scan Interface bypass indicates evasion attempt",
			}
		}
	}

	// cmd.exe detections
	if strings.Contains(image, "cmd.exe") {
		if d.patterns["cmd_suspicious"].MatchString(cmdLine) {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1059.003",
				DetectionModule: "Discovery",
				EventDetails:    "Reconnaissance command via cmd.exe",
				AdditionalContext: "System enumeration commands detected",
			}
		}
	}

	// wscript/cscript detections
	if strings.Contains(image, "wscript") || strings.Contains(image, "cscript") {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1059.005",
			DetectionModule: "Execution",
			EventDetails:    "Script host execution detected",
			AdditionalContext: "Windows Script Host can execute malicious VBS/JS",
		}
	}

	// mshta.exe - T1218.005
	if strings.Contains(image, "mshta") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1218.005",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "MSHTA execution detected",
			AdditionalContext: "MSHTA can be used to proxy execution of malicious code",
		}
	}

	// rundll32.exe
	if strings.Contains(image, "rundll32") {
		if strings.Contains(cmdLine, "javascript:") || strings.Contains(cmdLine, "vbscript:") {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1218.011",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "Rundll32 script execution",
				AdditionalContext: "Rundll32 executing script indicates proxy execution",
			}
		}
	}

	// regsvr32.exe - T1218.010
	if strings.Contains(image, "regsvr32") {
		if strings.Contains(cmdLine, "/s") && strings.Contains(cmdLine, "/i:") {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1218.010",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "Regsvr32 proxy execution (Squiblydoo)",
				AdditionalContext: "Regsvr32 can be abused to execute code from remote scripts",
			}
		}
	}

	// certutil.exe - T1140
	if strings.Contains(image, "certutil") {
		if strings.Contains(cmdLine, "-decode") || strings.Contains(cmdLine, "-urlcache") {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1140,T1105",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "Certutil abuse detected",
				AdditionalContext: "Certutil used for file download or decode",
			}
		}
	}

	// bitsadmin.exe - T1197
	if strings.Contains(image, "bitsadmin") {
		if strings.Contains(cmdLine, "/transfer") {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1197,T1105",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "BITS job for file transfer",
				AdditionalContext: "BITS can be abused for stealthy file downloads",
			}
		}
	}

	// Credential dumping tools
	if d.patterns["mimikatz"].MatchString(cmdLine) || strings.Contains(image, "mimikatz") {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1003.001",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Mimikatz detected",
			AdditionalContext: "Credential dumping tool execution",
		}
	}

	// PsExec detection
	if d.patterns["psexec"].MatchString(image) || d.patterns["psexec"].MatchString(cmdLine) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1569.002,T1021.002",
			DetectionModule: "LateralMovement",
			EventDetails:    "PsExec execution detected",
			AdditionalContext: "Remote execution tool commonly used for lateral movement",
		}
	}

	// Shadow copy deletion - T1490
	if d.patterns["shadow_delete"].MatchString(cmdLine) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1490",
			DetectionModule: "Impact",
			EventDetails:    "Shadow copy deletion detected",
			AdditionalContext: "Ransomware commonly deletes shadow copies",
		}
	}

	// BCDedit recovery disable - T1490
	if d.patterns["bcdedit"].MatchString(cmdLine) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1490",
			DetectionModule: "Impact",
			EventDetails:    "Boot configuration modification",
			AdditionalContext: "Disabling recovery options may indicate ransomware",
		}
	}

	// Log clearing - T1070.001
	if d.patterns["clear_logs"].MatchString(cmdLine) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1070.001",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "Event log clearing detected",
			AdditionalContext: "Attackers clear logs to cover tracks",
		}
	}

	// Suspicious parent-child relationships
	if strings.Contains(parentImage, "winword") || strings.Contains(parentImage, "excel") || strings.Contains(parentImage, "outlook") {
		if strings.Contains(image, "powershell") || strings.Contains(image, "cmd") || strings.Contains(image, "wscript") {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1566.001",
				DetectionModule: "InitialAccess",
				EventDetails:    "Office application spawned suspicious process",
				AdditionalContext: "May indicate macro-based malware execution",
			}
		}
	}

	return result
}

// ==================== NETWORK DETECTION ====================

func (d *Detector) detectNetworkConnection(image, destPort, destIP string, event *models.SecurityEvent) models.DetectionResult {
	result := models.DetectionResult{Severity: "INFO"}

	// Suspicious ports - C2
	suspiciousPorts := map[string]bool{
		"4444": true, "5555": true, "6666": true, "7777": true,
		"8080": true, "8443": true, "1337": true, "31337": true,
	}
	if suspiciousPorts[destPort] {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1571",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Connection to suspicious port: " + destPort,
			AdditionalContext: "Non-standard port may indicate C2 communication",
		}
	}

	// PowerShell network connection
	if strings.Contains(image, "powershell") && destPort != "" {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1059.001,T1071",
			DetectionModule: "Execution",
			EventDetails:    "PowerShell network connection",
			AdditionalContext: "PowerShell connecting to " + destIP + ":" + destPort,
		}
	}

	// Common C2 ports
	c2Ports := map[string]string{
		"443": "HTTPS", "80": "HTTP", "53": "DNS", "8080": "Alt-HTTP",
	}
	if _, ok := c2Ports[destPort]; ok {
		if strings.Contains(image, "rundll32") || strings.Contains(image, "regsvr32") {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1071.001",
				DetectionModule: "CommandAndControl",
				EventDetails:    "Suspicious binary making web connection",
				AdditionalContext: "LOLBin network activity may indicate C2",
			}
		}
	}

	return result
}

// ==================== PROCESS ACCESS DETECTION ====================

func (d *Detector) detectProcessAccess(sourceImage, grantedAccess string, event *models.SecurityEvent) models.DetectionResult {
	targetImage := strings.ToLower(event.TargetImage2)

	// LSASS access - T1003.001
	if strings.Contains(targetImage, "lsass") {
		// Suspicious access masks for credential dumping
		suspiciousAccess := map[string]bool{
			"0x1010": true, "0x1410": true, "0x1438": true,
			"0x143a": true, "0x1fffff": true,
		}
		if suspiciousAccess[grantedAccess] {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1003.001",
				DetectionModule: "CredentialAccess",
				EventDetails:    "LSASS memory access detected",
				AdditionalContext: "Source: " + sourceImage + ", Access: " + grantedAccess,
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== FILE CREATION DETECTION ====================

func (d *Detector) detectFileCreate(targetFilename string, event *models.SecurityEvent) models.DetectionResult {
	// Executable in suspicious locations
	suspiciousLocations := []string{
		"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
		"\\users\\public\\", "\\programdata\\",
	}
	execExtensions := []string{".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta"}

	for _, loc := range suspiciousLocations {
		if strings.Contains(targetFilename, loc) {
			for _, ext := range execExtensions {
				if strings.HasSuffix(targetFilename, ext) {
					return models.DetectionResult{
						Severity:        "MEDIUM",
						MitreTechnique:  "T1105",
						DetectionModule: "Execution",
						EventDetails:    "Executable created in suspicious location",
						AdditionalContext: targetFilename,
					}
				}
			}
		}
	}

	// Startup folder - T1547.001
	if strings.Contains(targetFilename, "\\startup\\") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1547.001",
			DetectionModule: "Persistence",
			EventDetails:    "File created in Startup folder",
			AdditionalContext: targetFilename,
		}
	}

	// Web shell indicators
	webShellPaths := []string{"\\inetpub\\", "\\wwwroot\\", "\\htdocs\\"}
	webShellExts := []string{".asp", ".aspx", ".php", ".jsp"}
	for _, path := range webShellPaths {
		if strings.Contains(targetFilename, path) {
			for _, ext := range webShellExts {
				if strings.HasSuffix(targetFilename, ext) {
					return models.DetectionResult{
						Severity:        "CRITICAL",
						MitreTechnique:  "T1505.003",
						DetectionModule: "Persistence",
						EventDetails:    "Potential web shell created",
						AdditionalContext: targetFilename,
					}
				}
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== REGISTRY DETECTION ====================

func (d *Detector) detectRegistryEvent(targetObject string, event *models.SecurityEvent) models.DetectionResult {
	// Run keys - T1547.001
	if d.patterns["registry_run"].MatchString(targetObject) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1547.001",
			DetectionModule: "Persistence",
			EventDetails:    "Registry Run key modification",
			AdditionalContext: targetObject,
		}
	}

	// Services registry - T1543.003
	if strings.Contains(targetObject, "\\services\\") {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1543.003",
			DetectionModule: "Persistence",
			EventDetails:    "Service registry modification",
			AdditionalContext: targetObject,
		}
	}

	// Disabled security features
	if strings.Contains(targetObject, "disableantispyware") ||
		strings.Contains(targetObject, "disablerealtimemonitoring") {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1562.001",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "Security feature disabled via registry",
			AdditionalContext: targetObject,
		}
	}

	// UAC bypass registry keys
	if strings.Contains(targetObject, "\\mscfile\\shell\\open\\command") ||
		strings.Contains(targetObject, "\\fodhelper") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1548.002",
			DetectionModule: "PrivilegeEscalation",
			EventDetails:    "Potential UAC bypass registry modification",
			AdditionalContext: targetObject,
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== PIPE DETECTION ====================

func (d *Detector) detectPipeEvent(pipeName string, event *models.SecurityEvent) models.DetectionResult {
	// Known malicious pipes
	maliciousPipes := []string{
		"\\msagent_", "\\isapi", "\\msse-", "\\postex_",
		"\\status_", "\\mypipe-", "\\win_svc",
	}
	for _, mp := range maliciousPipes {
		if strings.Contains(pipeName, mp) {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1570",
				DetectionModule: "CommandAndControl",
				EventDetails:    "Known malicious named pipe detected",
				AdditionalContext: pipeName,
			}
		}
	}

	// Cobalt Strike default pipes
	if strings.HasPrefix(pipeName, "\\msagent_") || strings.HasPrefix(pipeName, "\\postex_") {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1071.001",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Potential Cobalt Strike pipe detected",
			AdditionalContext: pipeName,
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== DNS DETECTION ====================

func (d *Detector) detectDNSQuery(event *models.SecurityEvent) models.DetectionResult {
	queryName := strings.ToLower(event.QueryName2)

	// Known bad domains (sample list)
	badDomains := []string{
		"pastebin.com", "githubusercontent.com", "ngrok.io",
		"duckdns.org", "no-ip.com",
	}
	for _, bd := range badDomains {
		if strings.Contains(queryName, bd) {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1071.004",
				DetectionModule: "CommandAndControl",
				EventDetails:    "DNS query to suspicious domain",
				AdditionalContext: queryName,
			}
		}
	}

	// Very long subdomain (potential DNS tunneling)
	parts := strings.Split(queryName, ".")
	for _, part := range parts {
		if len(part) > 50 {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1071.004",
				DetectionModule: "Exfiltration",
				EventDetails:    "Potential DNS tunneling detected",
				AdditionalContext: "Long subdomain: " + queryName,
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== FILE DELETE DETECTION ====================

func (d *Detector) detectFileDelete(targetFilename string, event *models.SecurityEvent) models.DetectionResult {
	// Security tool deletion
	securityTools := []string{
		"\\windows defender\\", "\\malwarebytes\\", "\\symantec\\",
		"\\mcafee\\", "\\avg\\", "\\avast\\",
	}
	for _, st := range securityTools {
		if strings.Contains(targetFilename, st) {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1562.001",
				DetectionModule: "DefenseEvasion",
				EventDetails:    "Security tool file deletion",
				AdditionalContext: targetFilename,
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== IMAGE LOAD DETECTION ====================

func (d *Detector) detectImageLoad(event *models.SecurityEvent) models.DetectionResult {
	imageLoaded := strings.ToLower(event.ImageLoaded2)
	image := strings.ToLower(event.Image2)

	// Unsigned DLL loaded
	if event.Signed2 == "false" && event.SignatureStatus2 != "Valid" {
		// DLL in suspicious location
		if strings.Contains(imageLoaded, "\\temp\\") || strings.Contains(imageLoaded, "\\appdata\\") {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1574.001",
				DetectionModule: "Persistence",
				EventDetails:    "Unsigned DLL loaded from suspicious path",
				AdditionalContext: imageLoaded,
			}
		}
	}

	// Credential theft related DLLs
	credDLLs := []string{"vaultcli.dll", "samlib.dll"}
	for _, dll := range credDLLs {
		if strings.Contains(imageLoaded, dll) {
			if !strings.Contains(image, "lsass") && !strings.Contains(image, "svchost") {
				return models.DetectionResult{
					Severity:        "HIGH",
					MitreTechnique:  "T1003",
					DetectionModule: "CredentialAccess",
					EventDetails:    "Credential-related DLL loaded by suspicious process",
					AdditionalContext: image + " loaded " + imageLoaded,
				}
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== REMOTE THREAD DETECTION ====================

func (d *Detector) detectRemoteThread(event *models.SecurityEvent) models.DetectionResult {
	sourceImage := strings.ToLower(event.SourceImage2)
	targetImage := strings.ToLower(event.TargetImage2)

	// Process injection indicators
	if sourceImage != targetImage {
		// Known injection targets
		injectionTargets := []string{"explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe"}
		for _, target := range injectionTargets {
			if strings.Contains(targetImage, target) {
				return models.DetectionResult{
					Severity:        "HIGH",
					MitreTechnique:  "T1055",
					DetectionModule: "DefenseEvasion",
					EventDetails:    "Remote thread creation in system process",
					AdditionalContext: sourceImage + " -> " + targetImage,
				}
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== SECURITY LOG DETECTIONS ====================

func (d *Detector) detectLogonSuccess(logonType, targetUser, ipAddress string, event *models.SecurityEvent) models.DetectionResult {
	// Type 10 = RemoteInteractive (RDP)
	if logonType == "10" {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1021.001",
			DetectionModule: "LateralMovement",
			EventDetails:    "RDP logon detected",
			AdditionalContext: "User: " + targetUser + ", Source: " + ipAddress,
		}
	}

	// Type 3 = Network logon
	if logonType == "3" {
		return models.DetectionResult{
			Severity:        "INFO",
			MitreTechnique:  "T1021.002",
			DetectionModule: "LateralMovement",
			EventDetails:    "Network logon",
			AdditionalContext: "User: " + targetUser + ", Source: " + ipAddress,
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

func (d *Detector) detectLogonFailure(logonType, targetUser, ipAddress string, event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "LOW",
		MitreTechnique:  "T1110",
		DetectionModule: "CredentialAccess",
		EventDetails:    "Failed logon attempt",
		AdditionalContext: "User: " + targetUser + ", Type: " + logonType + ", Source: " + ipAddress,
	}
}

func (d *Detector) detectExplicitCredentials(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "MEDIUM",
		MitreTechnique:  "T1078",
		DetectionModule: "DefenseEvasion",
		EventDetails:    "Explicit credential usage",
		AdditionalContext: "Subject: " + event.SubjectUserName3 + ", Target: " + event.TargetUserName3,
	}
}

func (d *Detector) detectPrivilegeAssignment(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "LOW",
		MitreTechnique:  "T1078",
		DetectionModule: "PrivilegeEscalation",
		EventDetails:    "Special privileges assigned to logon",
		AdditionalContext: "User: " + event.SubjectUserName3,
	}
}

func (d *Detector) detectSecurityProcessCreation(newProcessName string, event *models.SecurityEvent) models.DetectionResult {
	// Similar logic to Sysmon process creation
	if strings.Contains(newProcessName, "powershell") {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1059.001",
			DetectionModule: "Execution",
			EventDetails:    "PowerShell execution (Security log)",
			AdditionalContext: newProcessName,
		}
	}
	return models.DetectionResult{Severity: "INFO"}
}

func (d *Detector) detectServiceInstall(serviceName, serviceFileName string, event *models.SecurityEvent) models.DetectionResult {
	// Suspicious service paths
	if strings.Contains(serviceFileName, "\\temp\\") ||
		strings.Contains(serviceFileName, "\\appdata\\") ||
		strings.Contains(serviceFileName, "cmd.exe") ||
		strings.Contains(serviceFileName, "powershell") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1543.003",
			DetectionModule: "Persistence",
			EventDetails:    "Suspicious service installation",
			AdditionalContext: serviceName + ": " + serviceFileName,
		}
	}
	return models.DetectionResult{
		Severity:        "LOW",
		MitreTechnique:  "T1543.003",
		DetectionModule: "Persistence",
		EventDetails:    "Service installed",
		AdditionalContext: serviceName,
	}
}

func (d *Detector) detectScheduledTaskCreation(taskName string, event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "MEDIUM",
		MitreTechnique:  "T1053.005",
		DetectionModule: "Persistence",
		EventDetails:    "Scheduled task created",
		AdditionalContext: taskName,
	}
}

func (d *Detector) detectUserCreation(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "MEDIUM",
		MitreTechnique:  "T1136.001",
		DetectionModule: "Persistence",
		EventDetails:    "Local user account created",
		AdditionalContext: "Target: " + event.TargetUserName3,
	}
}

func (d *Detector) detectGroupMembership(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "MEDIUM",
		MitreTechnique:  "T1098",
		DetectionModule: "Persistence",
		EventDetails:    "User added to local group",
		AdditionalContext: "User: " + event.TargetUserName3,
	}
}

func (d *Detector) detectKerberosTGT(event *models.SecurityEvent) models.DetectionResult {
	// RC4 encryption (0x17) may indicate AS-REP Roasting
	if event.TicketEncryptionType3 == "0x17" {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1558.004",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Kerberos TGT with RC4 encryption",
			AdditionalContext: "Possible AS-REP Roasting target",
		}
	}
	return models.DetectionResult{Severity: "INFO"}
}

func (d *Detector) detectKerberosServiceTicket(event *models.SecurityEvent) models.DetectionResult {
	// RC4 encryption may indicate Kerberoasting
	if event.TicketEncryptionType3 == "0x17" {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1558.003",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Kerberos service ticket with RC4",
			AdditionalContext: "Possible Kerberoasting",
		}
	}
	return models.DetectionResult{Severity: "INFO"}
}

func (d *Detector) detectNTLMAuth(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "INFO",
		MitreTechnique:  "T1550.002",
		DetectionModule: "LateralMovement",
		EventDetails:    "NTLM authentication",
		AdditionalContext: "Account: " + event.TargetUserName3,
	}
}

func (d *Detector) detectRDPSession(eventID string, event *models.SecurityEvent) models.DetectionResult {
	action := "connected"
	if eventID == "4779" {
		action = "disconnected"
	}
	return models.DetectionResult{
		Severity:        "LOW",
		MitreTechnique:  "T1021.001",
		DetectionModule: "LateralMovement",
		EventDetails:    "RDP session " + action,
		AdditionalContext: "User: " + event.TargetUserName3 + ", Client: " + event.ClientName3,
	}
}

func (d *Detector) detectShareAccess(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "INFO",
		MitreTechnique:  "T1021.002",
		DetectionModule: "LateralMovement",
		EventDetails:    "Network share accessed",
		AdditionalContext: "Source: " + event.IpAddress3,
	}
}

// ==================== SYSTEM LOG DETECTIONS ====================

func (d *Detector) detectSystemServiceInstall(serviceName, serviceFileName string, event *models.SecurityEvent) models.DetectionResult {
	// Check for suspicious service binaries
	if strings.Contains(serviceFileName, "cmd") ||
		strings.Contains(serviceFileName, "powershell") ||
		strings.Contains(serviceFileName, "\\temp\\") ||
		strings.Contains(serviceFileName, "\\appdata\\") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1543.003",
			DetectionModule: "Persistence",
			EventDetails:    "Suspicious service installed (System log)",
			AdditionalContext: serviceName + ": " + serviceFileName,
		}
	}
	return models.DetectionResult{
		Severity:        "LOW",
		MitreTechnique:  "T1543.003",
		DetectionModule: "Persistence",
		EventDetails:    "Service installed",
		AdditionalContext: serviceName,
	}
}

func (d *Detector) detectServiceStateChange(event *models.SecurityEvent) models.DetectionResult {
	// Windows Defender service stopped
	serviceName := strings.ToLower(event.ServiceName3)
	if strings.Contains(serviceName, "defender") || strings.Contains(serviceName, "windefend") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1562.001",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "Windows Defender service state change",
			AdditionalContext: serviceName,
		}
	}
	return models.DetectionResult{Severity: "INFO"}
}

func (d *Detector) detectLogCleared(event *models.SecurityEvent) models.DetectionResult {
	return models.DetectionResult{
		Severity:        "HIGH",
		MitreTechnique:  "T1070.001",
		DetectionModule: "DefenseEvasion",
		EventDetails:    "Event log cleared",
		AdditionalContext: "Channel: " + event.Channel0,
	}
}

// ==================== COLLECTION DETECTIONS ====================

func (d *Detector) detectCollection(event *models.SecurityEvent) models.DetectionResult {
	logSource := strings.ToLower(event.LogSource5)
	eventID := event.EventID0
	cmdLine := strings.ToLower(event.CommandLine2)
	targetFilename := strings.ToLower(event.TargetFilename2)

	if strings.Contains(logSource, "sysmon") {
		switch eventID {
		case "1": // Process Creation
			// T1005 - Data from Local System
			if matchesPattern(cmdLine, `xcopy.*\/s|robocopy.*\/s|copy.*\*\.|findstr.*\/s|Get-ChildItem.*-Recurse`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1005",
					DetectionModule: "Collection",
					EventDetails:    "Potential local data collection detected",
					AdditionalContext: "Pattern suggests recursive file enumeration",
				}
			}

			// T1039 - Data from Network Shared Drive
			if matchesPattern(cmdLine, `\\\\[^\\]+\\|net use|pushd \\\\|copy.*\\\\|xcopy.*\\\\|robocopy.*\\\\`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1039",
					DetectionModule: "Collection",
					EventDetails:    "Network shared drive access detected",
					AdditionalContext: "Network path enumeration or copy operation",
				}
			}

			// T1025 - Data from Removable Media
			if matchesPattern(cmdLine, `[A-Z]:\\.*copy|[A-Z]:\\.*xcopy|[A-Z]:\\.*robocopy`) && matchesPattern(cmdLine, `[D-Z]:\\`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1025",
					DetectionModule: "Collection",
					EventDetails:    "Potential removable media data collection",
					AdditionalContext: "Copy operation from fixed to removable drive",
				}
			}

			// T1113 - Screen Capture
			if matchesPattern(cmdLine, `Graphics\.CopyFromScreen|PrintWindow|BitBlt|screenshot|screencap|nircmd.*savescreenshot`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1113",
					DetectionModule: "Collection",
					EventDetails:    "Screen capture activity detected",
					AdditionalContext: "Image capture utility or API usage detected",
				}
			}

			// T1125 - Video Capture
			if matchesPattern(cmdLine, `ffmpeg.*-f.*gdigrab|vlc.*--intf.*dummy.*--vout.*dummy`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1125",
					DetectionModule: "Collection",
					EventDetails:    "Video capture activity detected",
					AdditionalContext: "Media capture tool execution",
				}
			}

			// T1123 - Audio Capture
			if matchesPattern(cmdLine, `ffmpeg.*-f.*dshow.*audio|sox.*-t.*waveaudio`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1123",
					DetectionModule: "Collection",
					EventDetails:    "Audio capture activity detected",
					AdditionalContext: "Audio recording tool usage",
				}
			}

			// T1115 - Clipboard Data
			if matchesPattern(cmdLine, `Get-Clipboard|Set-Clipboard|Windows\.Forms\.Clipboard|clip\.exe|GetClipboardData`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1115",
					DetectionModule: "Collection",
					EventDetails:    "Clipboard access detected",
					AdditionalContext: "Access to clipboard data",
				}
			}

			// T1056.004 - Input Capture / Keylogging
			if matchesPattern(cmdLine, `SetWindowsHookEx|GetAsyncKeyState|RegisterHotKey|UnregisterHotKey|keylogger|keystroke|GetKeyboardState`) {
				return models.DetectionResult{
					Severity:        "CRITICAL",
					MitreTechnique:  "T1056.004",
					DetectionModule: "Collection",
					EventDetails:    "Potential input capture activity detected",
					AdditionalContext: "Keyboard hook or input capture attempt",
				}
			}

			// T1560 - Archive Collected Data
			if matchesPattern(cmdLine, `7z\.exe.*a.*-p|winrar\.exe.*a.*-hp|tar.*-c.*-z|gzip.*-r|Compress-Archive|makecab\.exe`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1560",
					DetectionModule: "Collection",
					EventDetails:    "Data archiving activity detected",
					AdditionalContext: "Compression tool with password protection",
				}
			}

			// T1074 - Data Staged
			if matchesPattern(cmdLine, `copy.*\\temp\\|copy.*\\appdata\\|move.*\\temp\\|xcopy.*\\temp\\`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1074",
					DetectionModule: "Collection",
					EventDetails:    "Data staging activity detected",
					AdditionalContext: "Files moved to temporary location",
				}
			}

			// T1119 - Automated Collection
			if matchesPattern(cmdLine, `for.*in.*do.*copy|for.*in.*do.*xcopy|while.*copy|while.*xcopy|ForEach.*Copy-Item`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1119",
					DetectionModule: "Collection",
					EventDetails:    "Automated data collection detected",
					AdditionalContext: "Scripted bulk file operations",
				}
			}

		case "7": // Image/DLL Load
			imageLoaded := strings.ToLower(event.ImageLoaded2)
			image := strings.ToLower(event.Image2)

			// T1113 - Graphics Library Loading
			if matchesPattern(imageLoaded, `gdi32\.dll|user32\.dll`) && matchesPattern(image, `powershell|cmd`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1113",
					DetectionModule: "Collection",
					EventDetails:    "Graphics library loaded by script",
					AdditionalContext: "GDI/User32 DLL for screen capture",
				}
			}

			// T1056 - Hook-related DLL Loading
			if matchesPattern(imageLoaded, `user32\.dll`) && matchesPattern(image, `powershell|cmd|rundll32`) {
				return models.DetectionResult{
					Severity:        "MEDIUM",
					MitreTechnique:  "T1056.004",
					DetectionModule: "Collection",
					EventDetails:    "User32.dll loaded - potential hook installation",
					AdditionalContext: "Hook-related DLL loaded by unusual process",
				}
			}

		case "11": // File Creation
			// T1113 - Screenshot Files
			if matchesPattern(targetFilename, `\.(png|jpg|jpeg|bmp|gif)$`) {
				return models.DetectionResult{
					Severity:        "LOW",
					MitreTechnique:  "T1113",
					DetectionModule: "Collection",
					EventDetails:    "Image file created - potential screenshot",
					AdditionalContext: "Image file in suspicious context",
				}
			}

			// T1125 - Video Files
			if matchesPattern(targetFilename, `\.(avi|mp4|wmv|mov|mkv)$`) {
				return models.DetectionResult{
					Severity:        "LOW",
					MitreTechnique:  "T1125",
					DetectionModule: "Collection",
					EventDetails:    "Video file created",
					AdditionalContext: "Video recording file",
				}
			}

			// T1123 - Audio Files
			if matchesPattern(targetFilename, `\.(wav|mp3|wma|flac|m4a)$`) {
				return models.DetectionResult{
					Severity:        "LOW",
					MitreTechnique:  "T1123",
					DetectionModule: "Collection",
					EventDetails:    "Audio file created",
					AdditionalContext: "Audio recording file",
				}
			}

			// T1560 - Archive Files
			if matchesPattern(targetFilename, `\.(zip|rar|7z|tar|gz|cab)$`) {
				return models.DetectionResult{
					Severity:        "LOW",
					MitreTechnique:  "T1560",
					DetectionModule: "Collection",
					EventDetails:    "Archive file created",
					AdditionalContext: "Compressed file archive",
				}
			}

			// T1074 - Staged Data Files
			if matchesPattern(targetFilename, `\\Temp\\.*\.(txt|doc|pdf|xls)|\\AppData\\.*\.(txt|doc|pdf|xls)`) {
				return models.DetectionResult{
					Severity:        "LOW",
					MitreTechnique:  "T1074",
					DetectionModule: "Collection",
					EventDetails:    "File staged in temporary location",
					AdditionalContext: "Data staging in temp folder",
				}
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== DISCOVERY DETECTIONS ====================

func (d *Detector) detectDiscovery(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)

	// T1087 - Account Discovery
	if matchesPattern(cmdLine, `net\s+user|get-localuser|wmic\s+useraccount|dsquery|get-aduser`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1087",
			DetectionModule: "Discovery",
			EventDetails:    "Account enumeration detected",
			AdditionalContext: "User/account discovery commands",
		}
	}

	// T1082 - System Information Discovery
	if matchesPattern(cmdLine, `systeminfo|wmic\s+os|Get-ComputerInfo|msinfo32`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1082",
			DetectionModule: "Discovery",
			EventDetails:    "System information enumeration",
			AdditionalContext: "OS and hardware discovery",
		}
	}

	// T1057 - Process Discovery
	if matchesPattern(cmdLine, `tasklist|Get-Process|wmic\s+process|ps\s+aux`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1057",
			DetectionModule: "Discovery",
			EventDetails:    "Process discovery detected",
			AdditionalContext: "Running process enumeration",
		}
	}

	// T1046 - Network Service Scanning
	if matchesPattern(cmdLine, `nmap|masscan|netstat.*-ano|Get-NetTCPConnection`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1046",
			DetectionModule: "Discovery",
			EventDetails:    "Network service scanning detected",
			AdditionalContext: "Port and service discovery",
		}
	}

	// T1016 - System Network Configuration Discovery
	if matchesPattern(cmdLine, `ipconfig|Get-NetIPConfiguration|route\s+print|netsh.*interface`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1016",
			DetectionModule: "Discovery",
			EventDetails:    "Network configuration discovery",
			AdditionalContext: "Network settings enumeration",
		}
	}

	// T1083 - File and Directory Discovery
	if matchesPattern(cmdLine, `dir|ls|Get-ChildItem|find\s+-name`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1083",
			DetectionModule: "Discovery",
			EventDetails:    "File system discovery",
			AdditionalContext: "Directory and file enumeration",
		}
	}

	// T1135 - Network Share Discovery
	if matchesPattern(cmdLine, `net\s+share|net\s+view|Get-SmbShare|nbtstat`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1135",
			DetectionModule: "Discovery",
			EventDetails:    "Network share discovery",
			AdditionalContext: "SMB share enumeration",
		}
	}

	// T1018 - Remote System Discovery
	if matchesPattern(cmdLine, `net\s+view|Get-ADComputer|dsquery\s+computer|nmap.*-sL`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1018",
			DetectionModule: "Discovery",
			EventDetails:    "Remote system discovery",
			AdditionalContext: "Network host enumeration",
		}
	}

	// T1217 - Browser Bookmark Discovery
	if matchesPattern(cmdLine, `favorites|bookmarks|browser|History`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1217",
			DetectionModule: "Discovery",
			EventDetails:    "Browser bookmark discovery",
			AdditionalContext: "Browser data access",
		}
	}

	// T1012 - Query Registry
	if matchesPattern(cmdLine, `reg\s+query|Get-ItemProperty|regedit`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1012",
			DetectionModule: "Discovery",
			EventDetails:    "Registry enumeration detected",
			AdditionalContext: "Registry key discovery",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== CREDENTIAL ACCESS ADDITIONAL DETECTIONS ====================

func (d *Detector) detectCredentialAccessAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	logSource := strings.ToLower(event.LogSource5)
	eventID := event.EventID0

	// T1558.001 - Golden Ticket
	if strings.Contains(logSource, "security") && eventID == "4624" {
		if strings.Contains(cmdLine, "krbtgt") {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1558.001",
				DetectionModule: "CredentialAccess",
				EventDetails:    "Potential Golden Ticket creation",
				AdditionalContext: "KRBTGT credential usage",
			}
		}
	}

	// T1040 - Network Sniffing
	if matchesPattern(cmdLine, `netsh.*trace|tcpdump|wireshark|rawcap`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1040",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Network sniffing tool detected",
			AdditionalContext: "Packet capture utility execution",
		}
	}

	// T1555 - Credentials from Password Stores
	if matchesPattern(cmdLine, `credential|password.*store|vault|keychain|chrome.*profile|firefox.*profile`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1555",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Password store access detected",
			AdditionalContext: "Browser or credential manager access",
		}
	}

	// T1552 - Unsecured Credentials
	if matchesPattern(cmdLine, `credentials\.txt|password\.txt|\.env|aws.*credentials|api.*key`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1552",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Unsecured credentials file accessed",
			AdditionalContext: "Plain text credentials discovery",
		}
	}

	// T1606 - Forge Web Credentials
	if matchesPattern(cmdLine, `forge.*credential|fake.*token|jwt.*encode|jwt.*create`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1606",
			DetectionModule: "CredentialAccess",
			EventDetails:    "Web credential forgery detected",
			AdditionalContext: "Artificial credential generation",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== LATERAL MOVEMENT ADDITIONAL DETECTIONS ====================

func (d *Detector) detectLateralMovementAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)

	// T1021.006 - WinRM Activity
	if matchesPattern(cmdLine, `winrm|invoke-command|enter-pssession|New-PSSession`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1021.006",
			DetectionModule: "LateralMovement",
			EventDetails:    "WinRM remote execution detected",
			AdditionalContext: "PowerShell remoting session creation",
		}
	}

	// T1210 - Exploitation of Remote Services
	if matchesPattern(cmdLine, `exploit|remote.*service|rce|vulnerability.*exploit`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1210",
			DetectionModule: "LateralMovement",
			EventDetails:    "Remote service exploitation detected",
			AdditionalContext: "Exploit code execution pattern",
		}
	}

	// T1021.004 - SSH
	if matchesPattern(cmdLine, `ssh|putty|plink.*-ssh`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1021.004",
			DetectionModule: "LateralMovement",
			EventDetails:    "SSH connection attempted",
			AdditionalContext: "SSH client execution",
		}
	}

	// T1080 - Taint Shared Content
	if matchesPattern(cmdLine, `copy.*\\\\.*\\shares|xcopy.*\\\\.*shared|robocopy.*network`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1080",
			DetectionModule: "LateralMovement",
			EventDetails:    "Shared content modification",
			AdditionalContext: "Network share content alteration",
		}
	}

	// T1091 - Replication Through Removable Media
	if matchesPattern(cmdLine, `copy.*removable|xcopy.*[d-z]:|usb.*copy`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1091",
			DetectionModule: "LateralMovement",
			EventDetails:    "Removable media replication",
			AdditionalContext: "USB device content modification",
		}
	}

	// T1563.002 - RDP Hijacking
	if matchesPattern(cmdLine, `tscon|rdp.*session.*hijack`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1563.002",
			DetectionModule: "LateralMovement",
			EventDetails:    "RDP session hijacking detected",
			AdditionalContext: "Terminal Services connection hijack",
		}
	}

	// T1072 - Software Deployment Tools
	if matchesPattern(cmdLine, `psexec|gpsexec|windows.*deployment|sccm|landesk|casper`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1072",
			DetectionModule: "LateralMovement",
			EventDetails:    "Software deployment tool usage",
			AdditionalContext: "System deployment/management tool",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== COMMAND AND CONTROL ADDITIONAL DETECTIONS ====================

func (d *Detector) detectCommandAndControlAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	queryName := strings.ToLower(event.QueryName2)
	logSource := strings.ToLower(event.LogSource5)
	eventID := event.EventID0

	// T1572 - Protocol Tunneling
	if matchesPattern(cmdLine, `ssh.*-l|ssh.*-r|ssh.*-d|stunnel|socat|chisel|ngrok|plink`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1572",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Protocol tunneling tool detected",
			AdditionalContext: "Port forwarding or VPN tunnel creation",
		}
	}

	// T1090.003 - Proxy/Anonymization Tools
	if matchesPattern(cmdLine, `proxychains|tor|i2p|freegate|ultrasurf|psiphon`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1090.003",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Proxy/anonymization tool detected",
			AdditionalContext: "Traffic anonymization tool usage",
		}
	}

	// T1573.001 - Encryption Tool Usage
	if matchesPattern(cmdLine, `openssl|gpg|aes|des|blowfish|twofish|serpent`) {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1573.001",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Encryption tool usage detected",
			AdditionalContext: "Cryptographic tool execution",
		}
	}

	// T1105 - Ingress Tool Transfer (not in C2 context but execution)
	if matchesPattern(cmdLine, `wget|curl|bitsadmin.*urlcache|certutil.*-urlcache|powershell.*downloadfile`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1105",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Tool transfer detected",
			AdditionalContext: "File download from internet",
		}
	}

	// T1219 - Remote Access Software
	if matchesPattern(cmdLine, `teamviewer|anydesk|zoho.*assist`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1219",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Remote access software detected",
			AdditionalContext: "Unauthorized remote access tool",
		}
	}

	// T1095 - Non-Application Layer Protocol
	if matchesPattern(cmdLine, `icmp|raw.*socket|igmp`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1095",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Non-standard protocol communication",
			AdditionalContext: "Non-application layer protocol usage",
		}
	}

	// T1568.002 - DGA Domain Generation
	if strings.Contains(logSource, "sysmon") && eventID == "22" {
		if len(queryName) > 0 && matchesPattern(queryName, `^[a-z0-9]{8,20}\.(com|net|org|info)$`) {
			return models.DetectionResult{
				Severity:        "HIGH",
				MitreTechnique:  "T1568.002",
				DetectionModule: "CommandAndControl",
				EventDetails:    "Potential DGA domain detected",
				AdditionalContext: "Algorithmically generated domain name",
			}
		}
	}

	// T1568.001 - Suspicious TLDs
	if strings.Contains(logSource, "sysmon") && eventID == "22" {
		if matchesPattern(queryName, `\.(tk|ml|ga|cf)$`) {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1568.001",
				DetectionModule: "CommandAndControl",
				EventDetails:    "Suspicious TLD query detected",
				AdditionalContext: "Free tier domain TLD usage",
			}
		}
	}

	// T1102 - Web Service C2
	webServices := []string{"pastebin.com", "github.com", "dropbox.com", "googledrive", "onedrive"}
	for _, svc := range webServices {
		if strings.Contains(queryName, svc) || strings.Contains(cmdLine, svc) {
			return models.DetectionResult{
				Severity:        "MEDIUM",
				MitreTechnique:  "T1102",
				DetectionModule: "CommandAndControl",
				EventDetails:    "Web service C2 usage detected",
				AdditionalContext: "Public web service for C2 communication",
			}
		}
	}

	// T1092 - Removable Media Communication
	if matchesPattern(cmdLine, `copy.*removable|xcopy.*[d-z]:\\`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1092",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Removable media communication",
			AdditionalContext: "Data transfer via removable device",
		}
	}

	// T1205 - Port Knocking
	if matchesPattern(cmdLine, `connect.*\d{1,5}.*then.*\d{1,5}|port.*knock`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1205",
			DetectionModule: "CommandAndControl",
			EventDetails:    "Port knocking pattern detected",
			AdditionalContext: "Sequential port connection pattern",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== EXFILTRATION ADDITIONAL DETECTIONS ====================

func (d *Detector) detectExfiltrationAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	targetFilename := strings.ToLower(event.TargetFilename2)
	destIP := event.DestinationIp2

	// T1020 - Automated Exfiltration
	if matchesPattern(cmdLine, `schtasks.*create.*daily|powershell.*-windowstyle.*hidden.*invoke-webrequest|curl.*-o.*--data-binary|wget.*--post-file|robocopy.*\\\\.*\/E`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1020",
			DetectionModule: "Exfiltration",
			EventDetails:    "Automated exfiltration activity",
			AdditionalContext: "Scheduled data transmission detected",
		}
	}

	// T1041 - Exfiltration Over C2 Channel
	if matchesPattern(cmdLine, `invoke-webrequest.*-method.*post.*-body|curl.*-X.*POST.*--data|certutil.*-urlcache.*-split.*-f.*http`) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1041",
			DetectionModule: "Exfiltration",
			EventDetails:    "C2 exfiltration channel detected",
			AdditionalContext: "Data transmission over C2",
		}
	}

	// T1048 - Exfiltration Over Alternative Protocol
	if matchesPattern(cmdLine, `ftp.*-s|sftp.*-b|scp.*-r|rsync.*-av`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1048",
			DetectionModule: "Exfiltration",
			EventDetails:    "Alternative protocol exfiltration",
			AdditionalContext: "Non-HTTP protocol data transfer",
		}
	}

	// T1567 - Exfiltration to Web Service
	if matchesPattern(cmdLine, `dropbox|googledrive|onedrive|icloud|mega\.nz|wetransfer|pastebin|github`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1567",
			DetectionModule: "Exfiltration",
			EventDetails:    "Web service exfiltration detected",
			AdditionalContext: "Cloud storage service usage",
		}
	}

	// T1052 - Exfiltration Over Physical Media
	if matchesPattern(targetFilename, `^[D-Z]:\\`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1052",
			DetectionModule: "Exfiltration",
			EventDetails:    "File exfiltration over removable media",
			AdditionalContext: "USB or removable device access",
		}
	}

	// T1029 - Scheduled Data Transfer
	if matchesPattern(cmdLine, `schtasks.*backup|schtasks.*export|schtasks.*transfer|schtasks.*sync`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1029",
			DetectionModule: "Exfiltration",
			EventDetails:    "Scheduled data transfer detected",
			AdditionalContext: "Scheduled task for data exfiltration",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== IMPACT ADDITIONAL DETECTIONS ====================

func (d *Detector) detectImpactAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	targetFilename := strings.ToLower(event.TargetFilename2)
	logSource := strings.ToLower(event.LogSource5)
	eventID := event.EventID0

	// T1486 - Ransomware Activity
	ransomwareExtensions := []string{
		"encrypted", "locked", "crypto", "crypt", "enc", "vault", "xxx",
		"teslacrypt", "cryptolocker", "cryptowall", "wannacry", "petya",
		"locky", "conti", "ryuk", "revil", "babuk", "avaddon",
	}
	for _, ext := range ransomwareExtensions {
		if strings.Contains(targetFilename, "."+ext) {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1486",
				DetectionModule: "Impact",
				EventDetails:    "File encrypted by ransomware",
				AdditionalContext: "Ransomware file extension: " + ext,
			}
		}
	}

	// T1486 - Ransomware command patterns
	if matchesPattern(cmdLine, `vssadmin.*delete.*shadows|wbadmin.*delete.*backup|cipher.*\/w|sdelete.*-z`) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1486",
			DetectionModule: "Impact",
			EventDetails:    "Ransomware preparation activity",
			AdditionalContext: "Shadow copy or backup deletion",
		}
	}

	// T1489 - Service Stop
	if matchesPattern(cmdLine, `net.*stop|sc.*stop|Get-Service.*Stop-Service|Stop-Service`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1489",
			DetectionModule: "Impact",
			EventDetails:    "Service stop attempt detected",
			AdditionalContext: "Critical service disruption",
		}
	}

	// T1529 - System Shutdown
	if matchesPattern(cmdLine, `shutdown.*\/s|shutdown.*\/r|Restart-Computer|Stop-Computer`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1529",
			DetectionModule: "Impact",
			EventDetails:    "System shutdown/reboot command",
			AdditionalContext: "System availability disruption",
		}
	}

	// T1485 - Data Destruction
	if matchesPattern(cmdLine, `del.*\/s.*\/q.*\/f.*\*|rmdir.*\/s.*\/q|format.*\/fs:|sdelete.*-s`) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1485",
			DetectionModule: "Impact",
			EventDetails:    "Data destruction activity",
			AdditionalContext: "Mass file deletion pattern",
		}
	}

	// T1561 - Disk Wipe
	if matchesPattern(cmdLine, `diskpart.*clean.*all|cipher.*\/w|sdelete.*-z|dd.*if=\/dev\/zero`) {
		return models.DetectionResult{
			Severity:        "CRITICAL",
			MitreTechnique:  "T1561",
			DetectionModule: "Impact",
			EventDetails:    "Disk wipe activity detected",
			AdditionalContext: "Complete disk wiping pattern",
		}
	}

	// T1531 - Account Access Removal
	if matchesPattern(cmdLine, `net.*user.*\/delete|net.*localgroup.*administrators.*\/delete|Remove-LocalUser|Disable-LocalUser`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1531",
			DetectionModule: "Impact",
			EventDetails:    "Account access removal detected",
			AdditionalContext: "User account deletion/disabling",
		}
	}

	// T1499 - Endpoint DoS
	if matchesPattern(cmdLine, `ping.*-t.*-l.*65500|ping.*flood|hping.*-S.*--flood|while.*Invoke-WebRequest`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1499",
			DetectionModule: "Impact",
			EventDetails:    "Endpoint DoS activity detected",
			AdditionalContext: "Denial of service attack pattern",
		}
	}

	// T1491 - Defacement
	if matchesPattern(cmdLine, `echo.*>.*index.html|echo.*>.*default.htm|copy.*ransom.*html`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1491",
			DetectionModule: "Impact",
			EventDetails:    "Potential defacement activity",
			AdditionalContext: "Website content modification",
		}
	}

	// T1531 - Account locked out (Security Log)
	if strings.Contains(logSource, "security") && eventID == "4740" {
		return models.DetectionResult{
			Severity:        "LOW",
			MitreTechnique:  "T1499.004",
			DetectionModule: "Impact",
			EventDetails:    "Account lockout detected",
			AdditionalContext: "Potential DoS via account lockout",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== PRIVILEGE ESCALATION ADDITIONAL DETECTIONS ====================

func (d *Detector) detectPrivilegeEscalationAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)

	// T1134 - Access Token Manipulation
	tokenPrivileges := []string{
		"sedebugprivilege", "setcbprivilege", "seimpersonateprivilege",
		"seassignprimarytokenprivilege", "seloaddriverprivilege",
	}
	for _, priv := range tokenPrivileges {
		if strings.Contains(cmdLine, priv) {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1134",
				DetectionModule: "PrivilegeEscalation",
				EventDetails:    "Access token manipulation attempt",
				AdditionalContext: "Privilege escalation via token",
			}
		}
	}

	// T1068 - Exploitation for Privilege Escalation
	exploitPatterns := []string{"cve-", "ms\\d{2}-\\d{3}", "exploit", "token manipulation", "uac.*bypass"}
	for _, pattern := range exploitPatterns {
		if matchesPattern(cmdLine, pattern) {
			return models.DetectionResult{
				Severity:        "CRITICAL",
				MitreTechnique:  "T1068",
				DetectionModule: "PrivilegeEscalation",
				EventDetails:    "Exploitation for privilege escalation",
				AdditionalContext: "Vulnerability exploitation detected",
			}
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== EXECUTION ADDITIONAL DETECTIONS ====================

func (d *Detector) detectExecutionAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	image := strings.ToLower(event.Image2)

	// T1203 - Exploitation for Client Execution
	if matchesPattern(cmdLine, `exploit|shellcode|payload|rce`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1203",
			DetectionModule: "Execution",
			EventDetails:    "Exploitation for client execution",
			AdditionalContext: "Malicious code execution attempt",
		}
	}

	// T1204 - User Execution
	if matchesPattern(cmdLine, `click.*file|open.*attachment|execute.*document`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1204",
			DetectionModule: "Execution",
			EventDetails:    "User execution of malicious file",
			AdditionalContext: "User-initiated file execution",
		}
	}

	// T1218.001 - WMIC Process Call
	if strings.Contains(image, "wmic") && matchesPattern(cmdLine, `process.*call.*create|process.*call.*delete`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1218.001",
			DetectionModule: "Execution",
			EventDetails:    "WMIC process creation",
			AdditionalContext: "WMI Command-line interface usage",
		}
	}

	// T1218.009 - MSBuild
	if strings.Contains(image, "msbuild") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1218.009",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "MSBuild execution",
			AdditionalContext: "Trusted binary proxy execution",
		}
	}

	// T1218.004 - InstallUtil
	if strings.Contains(image, "installutil") {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1218.004",
			DetectionModule: "DefenseEvasion",
			EventDetails:    "InstallUtil execution",
			AdditionalContext: ".NET installation utility abuse",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// ==================== INITIAL ACCESS ADDITIONAL DETECTIONS ====================

func (d *Detector) detectInitialAccessAdditional(event *models.SecurityEvent) models.DetectionResult {
	cmdLine := strings.ToLower(event.CommandLine2)
	parentImage := strings.ToLower(event.ParentImage2)

	// T1189 - Drive-by Compromise
	if matchesPattern(cmdLine, `download.*javascript|drive.*by|compromised.*website`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1189",
			DetectionModule: "InitialAccess",
			EventDetails:    "Drive-by compromise detected",
			AdditionalContext: "Compromised website infection",
		}
	}

	// T1190 - Exploit Public-Facing Application
	if matchesPattern(cmdLine, `exploit.*application|web.*vulnerability|cve-.*web`) {
		return models.DetectionResult{
			Severity:        "HIGH",
			MitreTechnique:  "T1190",
			DetectionModule: "InitialAccess",
			EventDetails:    "Public-facing app exploitation",
			AdditionalContext: "Web application vulnerability exploitation",
		}
	}

	// T1133 - External Remote Services
	if matchesPattern(cmdLine, `vpn|rdp.*external|remote.*access.*external|external.*login`) {
		return models.DetectionResult{
			Severity:        "MEDIUM",
			MitreTechnique:  "T1133",
			DetectionModule: "InitialAccess",
			EventDetails:    "External remote service access",
			AdditionalContext: "Remote access service exploitation",
		}
	}

	return models.DetectionResult{Severity: "INFO"}
}

// Helper function to match patterns
func matchesPattern(text, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return regex.MatchString(strings.ToLower(text))
}
