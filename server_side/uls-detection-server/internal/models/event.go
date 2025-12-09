package models

import (
	"time"
)

// SecurityEvent represents the parsed event from PowerShell agent
type SecurityEvent struct {
	// Agent metadata
	AgentHost      string `json:"agent_host"`
	AgentTimestamp string `json:"agent_timestamp"`

	// Normalized fields
	Timestamp   string `json:"timestamp"`
	ProcessID   string `json:"process_id"`
	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line"`
	Username    string `json:"username"`
	SourceIP    string `json:"source_ip"`
	DestIP      string `json:"dest_ip"`
	FilePath    string `json:"file_path"`
	RegistryKey string `json:"registry_key"`

	// Detection results (populated by server)
	Severity          string `json:"severity"`
	MitreTechnique    string `json:"mitre_technique"`
	DetectionModule   string `json:"detection_module"`
	EventDetails      string `json:"event_details"`
	AdditionalContext string `json:"additional_context"`

	// Level 0: System fields
	TimeCreated0        string `json:"TimeCreated_0"`
	ProviderName0       string `json:"ProviderName_0"`
	ProviderGuid0       string `json:"ProviderGuid_0"`
	EventID0            string `json:"EventID_0"`
	Version0            string `json:"Version_0"`
	Level0              string `json:"Level_0"`
	Task0               string `json:"Task_0"`
	Opcode0             string `json:"Opcode_0"`
	Keywords0           string `json:"Keywords_0"`
	EventRecordID0      string `json:"EventRecordID_0"`
	ExecutionProcessID0 string `json:"ExecutionProcessID_0"`
	ExecutionThreadID0  string `json:"ExecutionThreadID_0"`
	Channel0            string `json:"Channel_0"`
	Computer0           string `json:"Computer_0"`
	SecurityUserID0     string `json:"SecurityUserID_0"`

	// Level 1: Raw data
	EventData1  string `json:"EventData_1"`
	SystemData1 string `json:"SystemData_1"`
	UserData1   string `json:"UserData_1"`

	// Level 2: Sysmon fields
	UtcTime2                 string `json:"UtcTime_2"`
	ProcessGuid2             string `json:"ProcessGuid_2"`
	ProcessId2               string `json:"ProcessId_2"`
	Image2                   string `json:"Image_2"`
	FileVersion2             string `json:"FileVersion_2"`
	Description2             string `json:"Description_2"`
	Product2                 string `json:"Product_2"`
	Company2                 string `json:"Company_2"`
	CommandLine2             string `json:"CommandLine_2"`
	CurrentDirectory2        string `json:"CurrentDirectory_2"`
	User2                    string `json:"User_2"`
	LogonGuid2               string `json:"LogonGuid_2"`
	LogonId2                 string `json:"LogonId_2"`
	TerminalSessionId2       string `json:"TerminalSessionId_2"`
	IntegrityLevel2          string `json:"IntegrityLevel_2"`
	Hashes2                  string `json:"Hashes_2"`
	ParentProcessGuid2       string `json:"ParentProcessGuid_2"`
	ParentProcessId2         string `json:"ParentProcessId_2"`
	ParentImage2             string `json:"ParentImage_2"`
	ParentCommandLine2       string `json:"ParentCommandLine_2"`
	RuleName2                string `json:"RuleName_2"`
	TargetFilename2          string `json:"TargetFilename_2"`
	CreationUtcTime2         string `json:"CreationUtcTime_2"`
	PreviousCreationUtcTime2 string `json:"PreviousCreationUtcTime_2"`
	Protocol2                string `json:"Protocol_2"`
	Initiated2               string `json:"Initiated_2"`
	SourceIsIpv62            string `json:"SourceIsIpv6_2"`
	SourceIp2                string `json:"SourceIp_2"`
	SourceHostname2          string `json:"SourceHostname_2"`
	SourcePort2              string `json:"SourcePort_2"`
	SourcePortName2          string `json:"SourcePortName_2"`
	DestinationIsIpV62       string `json:"DestinationIsIpV6_2"`
	DestinationIp2           string `json:"DestinationIp_2"`
	DestinationHostname2     string `json:"DestinationHostname_2"`
	DestinationPort2         string `json:"DestinationPort_2"`
	DestinationPortName2     string `json:"DestinationPortName_2"`
	State2                   string `json:"State_2"`
	Version2                 string `json:"Version_2"`
	SchemaVersion2           string `json:"SchemaVersion_2"`
	ImageLoaded2             string `json:"ImageLoaded_2"`
	Signed2                  string `json:"Signed_2"`
	Signature2               string `json:"Signature_2"`
	SignatureStatus2         string `json:"SignatureStatus_2"`
	SourceProcessGuid2       string `json:"SourceProcessGuid_2"`
	SourceProcessId2         string `json:"SourceProcessId_2"`
	SourceImage2             string `json:"SourceImage_2"`
	TargetProcessId2         string `json:"TargetProcessId_2"`
	TargetImage2             string `json:"TargetImage_2"`
	NewThreadId2             string `json:"NewThreadId_2"`
	StartAddress2            string `json:"StartAddress_2"`
	StartModule2             string `json:"StartModule_2"`
	StartFunction2           string `json:"StartFunction_2"`
	Device2                  string `json:"Device_2"`
	SourceThreadId2          string `json:"SourceThreadId_2"`
	TargetProcessGuid2       string `json:"TargetProcessGuid_2"`
	GrantedAccess2           string `json:"GrantedAccess_2"`
	CallTrace2               string `json:"CallTrace_2"`
	EventType2               string `json:"EventType_2"`
	TargetObject2            string `json:"TargetObject_2"`
	Details2                 string `json:"Details_2"`
	NewName2                 string `json:"NewName_2"`
	Hash2                    string `json:"Hash_2"`
	Configuration2           string `json:"Configuration_2"`
	ConfigurationFileHash2   string `json:"ConfigurationFileHash_2"`
	PipeName2                string `json:"PipeName_2"`
	Operation2               string `json:"Operation_2"`
	Name2                    string `json:"Name_2"`
	Query2                   string `json:"Query_2"`
	Type2                    string `json:"Type_2"`
	Destination2             string `json:"Destination_2"`
	Consumer2                string `json:"Consumer_2"`
	Filter2                  string `json:"Filter_2"`
	QueryName2               string `json:"QueryName_2"`
	QueryType2               string `json:"QueryType_2"`
	QueryStatus2             string `json:"QueryStatus_2"`
	QueryResults2            string `json:"QueryResults_2"`
	IsExecutable2            string `json:"IsExecutable_2"`
	Archived2                string `json:"Archived_2"`
	Session2                 string `json:"Session_2"`
	ClientInfo2              string `json:"ClientInfo_2"`
	ParentUser2              string `json:"ParentUser_2"`
	RawAccessRead2           string `json:"RawAccessRead_2"`
	EventNamespace2          string `json:"EventNamespace_2"`

	// Level 3: Security fields
	LogonType3                 string `json:"LogonType_3"`
	TargetUserName3            string `json:"TargetUserName_3"`
	IpAddress3                 string `json:"IpAddress_3"`
	WorkstationName3           string `json:"WorkstationName_3"`
	FailureReason3             string `json:"FailureReason_3"`
	NewProcessName3            string `json:"NewProcessName_3"`
	SubjectUserName3           string `json:"SubjectUserName_3"`
	NewProcessId3              string `json:"NewProcessId_3"`
	TaskName3                  string `json:"TaskName_3"`
	TaskContent3               string `json:"TaskContent_3"`
	ServiceName3               string `json:"ServiceName_3"`
	ServiceFileName3           string `json:"ServiceFileName_3"`
	ServiceType3               string `json:"ServiceType_3"`
	ImagePath3                 string `json:"ImagePath_3"`
	AccountName3               string `json:"AccountName_3"`
	ProcessName3               string `json:"ProcessName_3"`
	SubjectLogonId3            string `json:"SubjectLogonId_3"`
	PrivilegeList3             string `json:"PrivilegeList_3"`
	OriginalFileName3          string `json:"OriginalFileName_3"`
	Status3                    string `json:"Status_3"`
	SubStatus3                 string `json:"SubStatus_3"`
	CallerComputerName3        string `json:"CallerComputerName_3"`
	TicketEncryptionType3      string `json:"TicketEncryptionType_3"`
	CertThumbprint3            string `json:"CertThumbprint_3"`
	AuthenticationPackageName3 string `json:"AuthenticationPackageName_3"`
	LogonProcessName3          string `json:"LogonProcessName_3"`
	SessionID3                 string `json:"SessionID_3"`
	ClientName3                string `json:"ClientName_3"`
	ActionName3                string `json:"ActionName_3"`
	Service3                   string `json:"Service_3"`

	// Level 5: Classification
	LogSource5     string `json:"LogSource_5"`
	EventCategory5 string `json:"EventCategory_5"`
}

// DetectionResult holds the results of detection rules
type DetectionResult struct {
	Severity          string
	MitreTechnique    string
	DetectionModule   string
	EventDetails      string
	AdditionalContext string
}

// ParseTimestamp parses the event timestamp
func (e *SecurityEvent) ParseTimestamp() time.Time {
	ts := e.TimeCreated0
	if ts == "" {
		ts = e.Timestamp
	}
	if ts == "" {
		return time.Now()
	}

	// Try various formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.0000000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t
		}
	}

	return time.Now()
}

// GetLogSource returns the log source
func (e *SecurityEvent) GetLogSource() string {
	if e.LogSource5 != "" {
		return e.LogSource5
	}
	return "Unknown"
}

// GetEventID returns the event ID
func (e *SecurityEvent) GetEventID() string {
	return e.EventID0
}

// EnrichedEvent wraps a SecurityEvent with enrichment metadata
type EnrichedEvent struct {
	Event           SecurityEvent `json:"event"`
	Severity        string        `json:"severity"`
	MitreTechnique  string        `json:"mitre_technique"`
	MitreTactic     string        `json:"mitre_tactic"`
	DetectionModule string        `json:"detection_module"`
	EventDetails    string        `json:"event_details"`
	DetectionRules  []string      `json:"detection_rules,omitempty"`
	ThreatScore     int           `json:"threat_score"`
	IsAnomaly       bool          `json:"is_anomaly"`
	EnrichmentTime  time.Duration `json:"enrichment_time_ns"`
}
