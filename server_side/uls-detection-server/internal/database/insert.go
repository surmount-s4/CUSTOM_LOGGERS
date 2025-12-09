package database

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"uls-detection-server/internal/models"
)

// InsertEvents batch inserts events into PostgreSQL
func (db *DB) InsertEvents(ctx context.Context, events []models.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Build batch insert query
	columns := []string{
		"agent_host", "agent_timestamp", "timestamp", "process_id", "process_name",
		"command_line", "username", "source_ip", "dest_ip", "file_path", "registry_key",
		"severity", "mitre_technique", "detection_module", "event_details", "additional_context",
		"timecreated_0", "providername_0", "providerguid_0", "eventid_0", "version_0",
		"level_0", "task_0", "opcode_0", "keywords_0", "eventrecordid_0",
		"executionprocessid_0", "executionthreadid_0", "channel_0", "computer_0", "securityuserid_0",
		"eventdata_1", "systemdata_1", "userdata_1",
		"utctime_2", "processguid_2", "processid_2", "image_2", "fileversion_2",
		"description_2", "product_2", "company_2", "commandline_2", "currentdirectory_2",
		"user_2", "logonguid_2", "logonid_2", "terminalsessionid_2", "integritylevel_2",
		"hashes_2", "parentprocessguid_2", "parentprocessid_2", "parentimage_2", "parentcommandline_2",
		"rulename_2", "targetfilename_2", "creationutctime_2", "previouscreationutctime_2",
		"protocol_2", "initiated_2", "sourceisipv6_2", "sourceip_2", "sourcehostname_2",
		"sourceport_2", "sourceportname_2", "destinationisipv6_2", "destinationip_2",
		"destinationhostname_2", "destinationport_2", "destinationportname_2",
		"state_2", "version_2", "schemaversion_2", "imageloaded_2", "signed_2",
		"signature_2", "signaturestatus_2", "sourceprocessguid_2", "sourceprocessid_2",
		"sourceimage_2", "targetprocessid_2", "targetimage_2", "newthreadid_2",
		"startaddress_2", "startmodule_2", "startfunction_2", "device_2", "sourcethreadid_2",
		"targetprocessguid_2", "grantedaccess_2", "calltrace_2", "eventtype_2", "targetobject_2",
		"details_2", "newname_2", "hash_2", "configuration_2", "configurationfilehash_2",
		"pipename_2", "operation_2", "name_2", "query_2", "type_2", "destination_2",
		"consumer_2", "filter_2", "queryname_2", "querytype_2", "querystatus_2",
		"queryresults_2", "isexecutable_2", "archived_2", "session_2", "clientinfo_2",
		"parentuser_2", "rawaccessread_2", "eventnamespace_2",
		"logontype_3", "targetusername_3", "ipaddress_3", "workstationname_3",
		"failurereason_3", "newprocessname_3", "subjectusername_3", "newprocessid_3",
		"taskname_3", "taskcontent_3", "servicename_3", "servicefilename_3",
		"servicetype_3", "imagepath_3", "accountname_3", "processname_3",
		"subjectlogonid_3", "privilegelist_3", "originalfilename_3", "status_3",
		"substatus_3", "callercomputername_3", "ticketencryptiontype_3", "certthumbprint_3",
		"authenticationpackagename_3", "logonprocessname_3", "sessionid_3", "clientname_3",
		"actionname_3", "service_3",
		"logsource_5", "eventcategory_5",
	}

	numCols := len(columns)
	valuePlaceholders := make([]string, len(events))
	args := make([]interface{}, 0, len(events)*numCols)

	for i, e := range events {
		placeholders := make([]string, numCols)
		for j := 0; j < numCols; j++ {
			placeholders[j] = fmt.Sprintf("$%d", i*numCols+j+1)
		}
		valuePlaceholders[i] = "(" + strings.Join(placeholders, ",") + ")"

		// Parse timestamp
		ts := e.ParseTimestamp()

		args = append(args,
			e.AgentHost, e.AgentTimestamp, ts, e.ProcessID, e.ProcessName,
			e.CommandLine, e.Username, e.SourceIP, e.DestIP, e.FilePath, e.RegistryKey,
			e.Severity, e.MitreTechnique, e.DetectionModule, e.EventDetails, e.AdditionalContext,
			e.TimeCreated0, e.ProviderName0, e.ProviderGuid0, e.EventID0, e.Version0,
			e.Level0, e.Task0, e.Opcode0, e.Keywords0, e.EventRecordID0,
			e.ExecutionProcessID0, e.ExecutionThreadID0, e.Channel0, e.Computer0, e.SecurityUserID0,
			e.EventData1, e.SystemData1, e.UserData1,
			e.UtcTime2, e.ProcessGuid2, e.ProcessId2, e.Image2, e.FileVersion2,
			e.Description2, e.Product2, e.Company2, e.CommandLine2, e.CurrentDirectory2,
			e.User2, e.LogonGuid2, e.LogonId2, e.TerminalSessionId2, e.IntegrityLevel2,
			e.Hashes2, e.ParentProcessGuid2, e.ParentProcessId2, e.ParentImage2, e.ParentCommandLine2,
			e.RuleName2, e.TargetFilename2, e.CreationUtcTime2, e.PreviousCreationUtcTime2,
			e.Protocol2, e.Initiated2, e.SourceIsIpv62, e.SourceIp2, e.SourceHostname2,
			e.SourcePort2, e.SourcePortName2, e.DestinationIsIpV62, e.DestinationIp2,
			e.DestinationHostname2, e.DestinationPort2, e.DestinationPortName2,
			e.State2, e.Version2, e.SchemaVersion2, e.ImageLoaded2, e.Signed2,
			e.Signature2, e.SignatureStatus2, e.SourceProcessGuid2, e.SourceProcessId2,
			e.SourceImage2, e.TargetProcessId2, e.TargetImage2, e.NewThreadId2,
			e.StartAddress2, e.StartModule2, e.StartFunction2, e.Device2, e.SourceThreadId2,
			e.TargetProcessGuid2, e.GrantedAccess2, e.CallTrace2, e.EventType2, e.TargetObject2,
			e.Details2, e.NewName2, e.Hash2, e.Configuration2, e.ConfigurationFileHash2,
			e.PipeName2, e.Operation2, e.Name2, e.Query2, e.Type2, e.Destination2,
			e.Consumer2, e.Filter2, e.QueryName2, e.QueryType2, e.QueryStatus2,
			e.QueryResults2, e.IsExecutable2, e.Archived2, e.Session2, e.ClientInfo2,
			e.ParentUser2, e.RawAccessRead2, e.EventNamespace2,
			e.LogonType3, e.TargetUserName3, e.IpAddress3, e.WorkstationName3,
			e.FailureReason3, e.NewProcessName3, e.SubjectUserName3, e.NewProcessId3,
			e.TaskName3, e.TaskContent3, e.ServiceName3, e.ServiceFileName3,
			e.ServiceType3, e.ImagePath3, e.AccountName3, e.ProcessName3,
			e.SubjectLogonId3, e.PrivilegeList3, e.OriginalFileName3, e.Status3,
			e.SubStatus3, e.CallerComputerName3, e.TicketEncryptionType3, e.CertThumbprint3,
			e.AuthenticationPackageName3, e.LogonProcessName3, e.SessionID3, e.ClientName3,
			e.ActionName3, e.Service3,
			e.LogSource5, e.EventCategory5,
		)
	}

	query := fmt.Sprintf(
		"INSERT INTO security_events (%s) VALUES %s",
		strings.Join(columns, ","),
		strings.Join(valuePlaceholders, ","),
	)

	start := time.Now()
	_, err := db.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to insert events: %w", err)
	}

	log.Printf("Inserted %d events in %v", len(events), time.Since(start))
	return nil
}
