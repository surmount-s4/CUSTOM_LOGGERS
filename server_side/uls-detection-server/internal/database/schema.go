package database

import (
	"context"
	"fmt"
	"log"
)

// InitSchema creates the security_events table if not exists
func InitSchema(ctx context.Context, db *DB) error {
	query := `
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Agent metadata
    agent_host TEXT,
    agent_timestamp TEXT,
    
    -- Normalized fields
    timestamp TIMESTAMPTZ,
    process_id TEXT,
    process_name TEXT,
    command_line TEXT,
    username TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    file_path TEXT,
    registry_key TEXT,
    
    -- Detection results
    severity TEXT,
    mitre_technique TEXT,
    detection_module TEXT,
    event_details TEXT,
    additional_context TEXT,
    
    -- Level 0: System fields
    timecreated_0 TEXT,
    providername_0 TEXT,
    providerguid_0 TEXT,
    eventid_0 TEXT,
    version_0 TEXT,
    level_0 TEXT,
    task_0 TEXT,
    opcode_0 TEXT,
    keywords_0 TEXT,
    eventrecordid_0 TEXT,
    executionprocessid_0 TEXT,
    executionthreadid_0 TEXT,
    channel_0 TEXT,
    computer_0 TEXT,
    securityuserid_0 TEXT,
    
    -- Level 1: Raw data
    eventdata_1 TEXT,
    systemdata_1 TEXT,
    userdata_1 TEXT,
    
    -- Level 2: Sysmon fields
    utctime_2 TEXT,
    processguid_2 TEXT,
    processid_2 TEXT,
    image_2 TEXT,
    fileversion_2 TEXT,
    description_2 TEXT,
    product_2 TEXT,
    company_2 TEXT,
    commandline_2 TEXT,
    currentdirectory_2 TEXT,
    user_2 TEXT,
    logonguid_2 TEXT,
    logonid_2 TEXT,
    terminalsessionid_2 TEXT,
    integritylevel_2 TEXT,
    hashes_2 TEXT,
    parentprocessguid_2 TEXT,
    parentprocessid_2 TEXT,
    parentimage_2 TEXT,
    parentcommandline_2 TEXT,
    rulename_2 TEXT,
    targetfilename_2 TEXT,
    creationutctime_2 TEXT,
    previouscreationutctime_2 TEXT,
    protocol_2 TEXT,
    initiated_2 TEXT,
    sourceisipv6_2 TEXT,
    sourceip_2 TEXT,
    sourcehostname_2 TEXT,
    sourceport_2 TEXT,
    sourceportname_2 TEXT,
    destinationisipv6_2 TEXT,
    destinationip_2 TEXT,
    destinationhostname_2 TEXT,
    destinationport_2 TEXT,
    destinationportname_2 TEXT,
    state_2 TEXT,
    version_2 TEXT,
    schemaversion_2 TEXT,
    imageloaded_2 TEXT,
    signed_2 TEXT,
    signature_2 TEXT,
    signaturestatus_2 TEXT,
    sourceprocessguid_2 TEXT,
    sourceprocessid_2 TEXT,
    sourceimage_2 TEXT,
    targetprocessid_2 TEXT,
    targetimage_2 TEXT,
    newthreadid_2 TEXT,
    startaddress_2 TEXT,
    startmodule_2 TEXT,
    startfunction_2 TEXT,
    device_2 TEXT,
    sourcethreadid_2 TEXT,
    targetprocessguid_2 TEXT,
    grantedaccess_2 TEXT,
    calltrace_2 TEXT,
    eventtype_2 TEXT,
    targetobject_2 TEXT,
    details_2 TEXT,
    newname_2 TEXT,
    hash_2 TEXT,
    configuration_2 TEXT,
    configurationfilehash_2 TEXT,
    pipename_2 TEXT,
    operation_2 TEXT,
    name_2 TEXT,
    query_2 TEXT,
    type_2 TEXT,
    destination_2 TEXT,
    consumer_2 TEXT,
    filter_2 TEXT,
    queryname_2 TEXT,
    querytype_2 TEXT,
    querystatus_2 TEXT,
    queryresults_2 TEXT,
    isexecutable_2 TEXT,
    archived_2 TEXT,
    session_2 TEXT,
    clientinfo_2 TEXT,
    parentuser_2 TEXT,
    rawaccessread_2 TEXT,
    eventnamespace_2 TEXT,
    
    -- Level 3: Security fields
    logontype_3 TEXT,
    targetusername_3 TEXT,
    ipaddress_3 TEXT,
    workstationname_3 TEXT,
    failurereason_3 TEXT,
    newprocessname_3 TEXT,
    subjectusername_3 TEXT,
    newprocessid_3 TEXT,
    taskname_3 TEXT,
    taskcontent_3 TEXT,
    servicename_3 TEXT,
    servicefilename_3 TEXT,
    servicetype_3 TEXT,
    imagepath_3 TEXT,
    accountname_3 TEXT,
    processname_3 TEXT,
    subjectlogonid_3 TEXT,
    privilegelist_3 TEXT,
    originalfilename_3 TEXT,
    status_3 TEXT,
    substatus_3 TEXT,
    callercomputername_3 TEXT,
    ticketencryptiontype_3 TEXT,
    certthumbprint_3 TEXT,
    authenticationpackagename_3 TEXT,
    logonprocessname_3 TEXT,
    sessionid_3 TEXT,
    clientname_3 TEXT,
    actionname_3 TEXT,
    service_3 TEXT,
    
    -- Level 5: Classification
    logsource_5 TEXT,
    eventcategory_5 TEXT
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_eventid ON security_events(eventid_0);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_mitre ON security_events(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_security_events_agent ON security_events(agent_host);
CREATE INDEX IF NOT EXISTS idx_security_events_logsource ON security_events(logsource_5);
CREATE INDEX IF NOT EXISTS idx_security_events_image ON security_events(image_2);
CREATE INDEX IF NOT EXISTS idx_security_events_destip ON security_events(destinationip_2);
`
	_, err := db.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	log.Println("Database schema initialized successfully")
	return nil
}
