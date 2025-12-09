package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	// For long_fields.json.
	_ "embed"

	. "github.com/efd6/dispear"
)

//go:embed long_fields.json
var longFieldsData []byte

func main() {
	DESCRIPTION("Pipeline for processing CrowdStrike sample logs")

	messageDecoding()

	BLANK()

	BLANK().COMMENT("Non-sensor Events")
	PIPELINE("data_protection_detection_summary").
		IF(`ctx.crowdstrike?.ExternalApiType == 'Event_DataProtectionDetectionSummaryEvent'`)
		//   # Non-sensor Events
		// - pipeline:
		//     name: '{{ IngestPipeline "data_protection_detection_summary" }}'
		//     tag: data_protection_detection_summary
		//     if: ctx.crowdstrike?.ExternalApiType == 'Event_DataProtectionDetectionSummaryEvent'

	BLANK()

	BLANK().COMMENT("Handle case changes.")
	for _, old := range []string{
		"crowdstrike.GrandParentCommandLine",
		"crowdstrike.GrandParentImageFileName",
		"crowdstrike.GrandParentImageFilePath",
	} {
		new := strings.ReplaceAll(old, "GrandParent", "Grandparent")
		RENAME(old, new).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)

	}

	BLANK()

	severityFields()

	BLANK()

	eppDetectionSummaryFields()

	BLANK()

	DATE("crowdstrike.FirstDiscoveredDate", "crowdstrike.FirstDiscoveredDate", "UNIX").
		COMMENT("Handle additional added fields.").
		IF(notNullEmpytOrNone("ctx.crowdstrike?.FirstDiscoveredDate"))
	for _, conv := range []struct{ field, typ, cond string }{
		{field: "crowdstrike.CurrentLocalIP", typ: "ip", cond: "ctx.crowdstrike?.CurrentLocalIP != null && ctx.crowdstrike?.CurrentLocalIP != ''"},
		{field: "crowdstrike.aipCount", typ: "integer", cond: "ctx.crowdstrike?.aipCount != null && ctx.crowdstrike?.aipCount != ''"},
		{field: "crowdstrike.discovererCount", typ: "integer", cond: "ctx.crowdstrike?.discovererCount != null && ctx.crowdstrike?.discovererCount != ''"},
		{field: "crowdstrike.localipCount", typ: "integer", cond: "ctx.crowdstrike?.localipCount != null && ctx.crowdstrike?.localipCount != ''"},
	} {
		CONVERT("", conv.field, conv.typ).IF(conv.cond)
	}

	BLANK()

	fingerPrinting()

	BLANK()
	PIPELINE("categorize").
		COMMENT("Categorization").
		IGNORE_MISSING(true)

	BLANK()
	BLANK().COMMENT("Cached event category for category-dependent processors")
	for _, typ := range []string{
		"File",
		"Library",
		"Network",
		"Process",
		"Driver",
	} {
		SET(fmt.Sprintf("_temp.is%s", typ)).
			IF(fmt.Sprintf("ctx.event?.category?.contains('%s') == true", strings.ToLower(typ))).
			VALUE(true)
	}

	BLANK()
	BLANK().COMMENT("Event fields.")
	SET("event.id").
		DESCRIPTION("Concat the fields used in fingerprint.").
		IF(`ctx.crowdstrike?.id != null || ctx.crowdstrike?.aid != null || ctx.crowdstrike?.cid != null`).
		VALUE(`{{{#crowdstrike.id}}}{{{ crowdstrike.id }}}{{{/crowdstrike.id}}}|{{{#crowdstrike.aid}}}{{{ crowdstrike.aid }}}{{{/crowdstrike.aid}}}|{{{#crowdstrike.cid}}}{{{ crowdstrike.cid }}}{{{/crowdstrike.cid}}}`)
	SET("message").
		TAG("construct_message_from_event_simpleName").
		COPY_FROM("crowdstrike.event_simpleName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.event_simpleName", "event.action").
		IGNORE_MISSING(true)

	BLANK()
	BLANK().COMMENT("Prepare data.")
	SCRIPT().
		TAG("convert count fields to long").
		DESCRIPTION("Convert all count fields to number.").
		SOURCE(`
          for (entry in ctx.crowdstrike.entrySet()) {
            def key = entry.getKey().toString();
            if (key.contains("Count") || key.contains("Port")) {
              try {
                ctx.crowdstrike[key] = Long.parseLong(entry.getValue().toString());
              } catch (Exception e) {
              }
            }
          }
		`)
	SCRIPT().
		TAG("remove empty hashes").
		DESCRIPTION("Remove all 0's hashes.").
		PARAMS(map[string]any{
			"MD5HashData":    "md5",
			"SHA1HashData":   "sha1",
			"SHA256HashData": "sha256",
		}).
		SOURCE(`
          def hashIsEmpty(String hash) {
            if (hash == null || hash == "") {
              return true;
            }

            Pattern emptyHashRegex = /^0*$/;
            def matcher = emptyHashRegex.matcher(hash);

            return matcher.matches();
          }

          def hashes = new HashMap();
          def related = [
            "hash": new ArrayList()
          ];
          for (entry in params.entrySet()) {
            def key = entry.getKey().toString();
            def value = ctx.crowdstrike[key];
            if (hashIsEmpty(value)) {
              ctx.crowdstrike.remove(key);
              continue;
            }

            hashes[entry.getValue().toString()] = value;
            related.hash.add(value);
          }

          ctx._temp = ctx._temp ?: [:];
          ctx._temp.hashes = hashes;
          if (related.hash.length > 0) {
            ctx.related = related;
          }
		`)

	BLANK()

	observerFields()

	BLANK()

	hostFields()

	BLANK()

	osFields()

	BLANK()

	serviceFields()

	BLANK()

	processFields()

	BLANK()

	libraryFields()

	BLANK()

	registryFields()

	BLANK()

	userFields()

	BLANK()

	networkFields()

	BLANK()

	urlFields()

	BLANK()

	ipGeolocationLookup()

	BLANK()

	autonomousSystemLookup()

	BLANK()

	dnsFields()

	BLANK()

	smbFields()

	BLANK()

	fileFields()

	BLANK()

	deviceFields()

	BLANK()

	crowdstrikeFields()

	BLANK()

	cleanup()

	Generate()
}

func messageDecoding() {
	BLANK().COMMENT("Message decoding.")

	REMOVE(
		"ecs.version",
		"event.dataset",
		"event.module",
		"observer.type",
		"observer.vendor",
	).TAG(
		"remove static constant keyword fields",
	).IGNORE_MISSING(true)

	REMOVE(
		"organization",
		"division",
		"team",
	).
		TAG("remove agentless metadata").
		IF("ctx.organization instanceof String && ctx.division instanceof String && ctx.team instanceof String").
		DESCRIPTION("Removes the fields added by Agentless as metadata, as they can collide with ECS fields.").
		IGNORE_MISSING(true)

	RENAME("message", "event.original").
		IF("ctx.event?.original == null").
		DESCRIPTION("Renames the original `message` field to `event.original` to store a copy of the original message. The `event.original` field is not touched if the document already has one; it may happen when Logstash sends the document.").
		IGNORE_MISSING(true)
	REMOVE("message").
		IF("ctx.event?.original != null").
		DESCRIPTION("The `message` field is no longer required if the document has an `event.original` field.").
		IGNORE_MISSING(true)
	JSON("crowdstrike", "event.original").
		ON_FAILURE(
			APPEND("error.message", "Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}"),
		)

	REMOVE(
		"metadata.host.aid",
		"metadata.user.UserSid_readable",
	).
		TAG("remove metadata host aid and user sid").
		IGNORE_MISSING(true)
	RENAME("metadata", "crowdstrike.info").
		IGNORE_MISSING(true).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)

	CONVERT("_temp.utc_timestamp", "crowdstrike.UTCTimestamp", "long").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "_temp.utc_timestamp", formats: []string{"UNIX"}, cond: "ctx._temp?.utc_timestamp instanceof long && ctx._temp.utc_timestamp < (long)1e10"},
		{field: "crowdstrike.UTCTimestamp", formats: []string{"UNIX_MS", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.UTCTimestamp")},
		{field: "crowdstrike.timestamp", formats: []string{"UNIX_MS", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.timestamp")},
		{field: "crowdstrike.CreationTimeStamp", formats: []string{"UNIX", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.CreationTimeStamp")},
		{field: "crowdstrike.Time", formats: []string{"ISO8601", "UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.Time")},
		{field: "crowdstrike._time", formats: []string{"ISO8601", "UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?._time")},
	} {

		DATE("event.created", src.field, src.formats...).
			IF("ctx.event?.created == null && " + src.cond).
			IGNORE_FAILURE(true)
	}
	SET("@timestamp").
		COPY_FROM("event.created").
		IF("ctx.event?.created != null")
	SET("@timestamp").
		COPY_FROM("_ingest.timestamp").
		IF(`ctx["@timestamp"] == null`)

	for _, src := range []struct {
		field string
		cond  string
	}{
		{field: "ContextTimeStamp", cond: `ctx.crowdstrike?.ContextTimeStamp != null && ctx.crowdstrike?.ContextTimeStamp != ""`},
		{field: "StartTime"},
		{field: "EndTime"},
	} {
		s := SCRIPT().
			DESCRIPTION(fmt.Sprintf("Conditionally convert %s from Windows NT timestamp format to UNIX", src.field)).
			TAG(fmt.Sprintf("script date %s from nt", src.field)).
			SOURCE(ntTimeToUnix(fmt.Sprintf("ctx.crowdstrike?.%s", src.field)))
		if src.cond != "" {
			s.IF(src.cond)
		}
		field := fmt.Sprintf("crowdstrike.%s", src.field)
		DATE(field, field, "UNIX").
			IF(notNullEmpytOrNone(fmt.Sprintf("ctx.crowdstrike?.%s", src.field)))
	}
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "crowdstrike.scores.modified_time", formats: []string{"ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.scores?.modified_time")},
		{field: "crowdstrike.ChangeTime", formats: []string{"UNIX"}, cond: "ctx.crowdstrike?.ChangeTime != null && ctx.crowdstrike.ChangeTime != ''"},
	} {
		DATE(src.field, src.field, src.formats...).
			IF(src.cond).
			ON_FAILURE(
				REMOVE(src.field),
				APPEND("error.message", errorMessage),
			)
	}

	RENAME("crowdstrike.message", "message").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.event_type", "crowdstrike.EventType").
		IF("ctx.crowdstrike?.EventType == null").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.host_hidden_status", "crowdstrike.HostHiddenStatus").
		IF("ctx.crowdstrike?.HostHiddenStatus == null").
		IGNORE_MISSING(true)

	for _, src := range []string{
		"crowdstrike.scores.os",
		"crowdstrike.scores.overall",
		"crowdstrike.scores.sensor",
	} {
		CONVERT("", src, "long").
			IGNORE_MISSING(true).
			ON_FAILURE(
				REMOVE(src).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
	}
}

func ntTimeToUnix(f string) string {
	const script = `
        if (%[1]s == null) {
          return;
        }
        long timestamp;
        if (%[2]s instanceof long) {
          timestamp = (long)%[2]s;
        } else if (%[2]s instanceof String) {
          if (!%[2]s.contains('.')) {
            timestamp = Long.parseLong(%[2]s);
          }
        }
        if (timestamp > 0x0100000000000000L) { // See https://devblogs.microsoft.com/oldnewthing/20030905-02/?p=42653 for constant.
          %[2]s = (timestamp / 10000000) - 11644473600L;
        }`
	return fmt.Sprintf(script, f, strings.ReplaceAll(f, "?", ""))
}

func severityFields() {
	BLANK().COMMENT(`Assign severities to conform to security rules values

21 = Low
47 = Medium
73 = High
99 = Critical

Leave crowdstrike values in place, since they have their own semantics.`)
	CONVERT("", "crowdstrike.alert.severity", "long").
		IF(`ctx.crowdstrike?.alert?.severity != null && !(ctx.crowdstrike.alert.severity instanceof long)`).
		ON_FAILURE(
			REMOVE("crowdstrike.alert.severity"),
			APPEND("error.message", errorMessage),
		)
	SCRIPT().
		DESCRIPTION("Script to set event.severity.").
		TAG("script set crowdstrike alert severity").
		IF("ctx.crowdstrike?.alert?.severity instanceof long && ctx.crowdstrike.alert.severityName == null").
		SOURCE(`
          long severity = ctx.crowdstrike.alert.severity;
          if (0 <= severity && severity < 20) {
            ctx.crowdstrike.alert.severityName = "info";
          } if (20 <= severity && severity < 40) {
            ctx.crowdstrike.alert.severityName = "low";
          } if (40 <= severity && severity < 60) {
            ctx.crowdstrike.alert.severityName = "medium";
          } if (60 <= severity && severity < 80) {
            ctx.crowdstrike.alert.severityName = "high";
          } if (80 <= severity && severity <= 100) {
            ctx.crowdstrike.alert.severityName = "critical";
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	SCRIPT().
		IF("ctx.crowdstrike?.SeverityName instanceof String").
		TAG("script set event severity").
		SOURCE(`
          ctx.event = ctx.event ?: [:];
          String name = ctx.crowdstrike.SeverityName;
          if (name.equalsIgnoreCase("low") || name.equalsIgnoreCase("info") || name.equalsIgnoreCase("informational")) {
            ctx.event.severity = 21;
          } else if (name.equalsIgnoreCase("medium")) {
            ctx.event.severity = 47;
          } else if (name.equalsIgnoreCase("high")) {
            ctx.event.severity = 73;
          } else if (name.equalsIgnoreCase("critical")) {
            ctx.event.severity = 99;
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func eppDetectionSummaryFields() {
	BLANK().COMMENT("EppDetectionSummaryEvent renames")
	for _, change := range []struct{ from, to string }{
		{from: "crowdstrike.Hostname", to: "crowdstrike.ComputerName"},
		{from: "crowdstrike.LogonDomain", to: "crowdstrike.MachineDomain"},
		{from: "crowdstrike.AgentId", to: "crowdstrike.SensorId"},
		{from: "crowdstrike.Name", to: "crowdstrike.DetectName"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}

	BLANK()

	CONVERT("", "crowdstrike.LocalIPv6", "ip").
		COMMENT("EppDetectionSummaryEvent converts").
		IF("ctx.crowdstrike?.LocalIPv6 != null && ctx.crowdstrike.LocalIPv6 != ''").
		ON_FAILURE(
			REMOVE("crowdstrike.LocalIPv6"),
			APPEND("error.message", errorMessage),
		)
	for _, src := range []struct {
		field string
		cond  string
	}{
		{field: "crowdstrike.FilesAccessed", cond: "ctx.crowdstrike?.FilesAccessed instanceof List"},
		{field: "crowdstrike.FilesWritten", cond: "ctx.crowdstrike?.FilesWritten instanceof List"},
	} {
		FOREACH(src.field,
			DATE("_ingest._value.Timestamp", "_ingest._value.Timestamp", "UNIX").
				ON_FAILURE(
					REMOVE("_ingest._value.Timestamp").IGNORE_FAILURE(true),
					APPEND("error.message", errorMessage),
				),
		).IF(src.cond)
	}
}

func fingerPrinting() {
	REMOVE("_id").COMMENT(`AWS S3 input does _id-Based Deduplication and generates "_id" by default.
When "Data Deduplication" is not enabled, this field must be removed.
https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3#_document_id_generation`).
		TAG("remove id based deduplication").
		DESCRIPTION("When data deduplication is disabled, even the _id-Based Deduplication needs to be removed.").
		IF("ctx._conf?.enable_deduplication == false").
		IGNORE_MISSING(true)

	BLANK()

	SCRIPT().
		TAG("script_data_type").
		IF("ctx.log?.file?.path != null && ctx.log.file.path != ''").
		SOURCE(`
          int lastSlash = ctx.log.file.path.lastIndexOf("/");
          if (lastSlash == -1) {
            return;
          }
          ctx._temp = ctx._temp ?: [:];
          ctx._temp.type = ctx.log.file.path.substring(lastSlash + 1);
          // aidmaster and userinfo are bucket keys we depend on, the data
          // path suffix is tested, but not depended on. So make sure this
          // is present for the fingerprint processor.
          if (ctx._temp.type != 'aidmaster' && ctx._temp.type != 'userinfo') {
            ctx._temp.type = 'data';
          }
		`)
	FINGERPRINT("_id",
		"@timestamp",
		"crowdstrike.id",
		"crowdstrike.aid",
		"crowdstrike.cid",
		"_temp.type",
	).
		TAG("fingerprint_crowdstrike_fdr").
		DESCRIPTION("When deduplication is enabled, fingerprint the a set of crowdstrike fields in attempt to prevent the same event from being indexed more than once.").
		IF("ctx._conf?.enable_deduplication == true").
		IGNORE_MISSING(true)
}

func observerFields() {
	BLANK().COMMENT("Observer fields.")

	SET("observer.serial_number").
		COPY_FROM("crowdstrike.aid").
		IGNORE_EMPTY(true)
	SPLIT("", "crowdstrike.aip", `\s+`).
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.aip", "ip").
		IGNORE_MISSING(true).
		ON_FAILURE(
			REMOVE("crowdstrike.aip"),
		)
	RENAME("crowdstrike.aip", "observer.ip").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SET("observer.address").
		COPY_FROM("observer.ip").
		IGNORE_EMPTY(true)
	for _, src := range []string{
		"crowdstrike.AgentVersion",
		"crowdstrike.ConfigBuild",
	} {
		RENAME(src, "observer.version").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	FOREACH("observer.ip",
		APPEND("related.ip",
			`{{{_ingest._value}}}`,
		).
			ALLOW_DUPLICATES(false),
	).IF(`ctx.observer?.ip != null && ctx.observer.ip instanceof List`)
}

func hostFields() {
	BLANK().COMMENT("Host fields.")

	RENAME("crowdstrike.aid", "host.id").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []string{
		"crowdstrike.ComputerName",
		"crowdstrike.hostname",
	} {
		RENAME(src, "host.hostname").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	SET("host.name").
		COPY_FROM("host.hostname").
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.info.host.ComputerName", "host.name").
		IF(`ctx.host?.name == null`).
		IGNORE_MISSING(true)
	for _, src := range []string{
		`{{{crowdstrike.info.host.ComputerName}}}`,
		`{{{host.name}}}`,
	} {
		APPEND("related.hosts", src).
			IF(`ctx.host?.name != null`).
			ALLOW_DUPLICATES(false)
	}
	for _, change := range []struct {
		from, to string
	}{
		{from: "crowdstrike.City", to: "host.geo.city_name"},
		{from: "crowdstrike.Continent", to: "host.geo.continent_name"},
		{from: "crowdstrike.Country", to: "host.geo.country_name"},
		{from: "crowdstrike.Timezone", to: "host.geo.timezone"},
		{from: "crowdstrike.MachineDomain", to: "host.domain"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	CONVERT("_temp.aip", "crowdstrike.info.host.aip", "ip").
		IF(`ctx.crowdstrike?.info?.host?.aip != null && ctx.crowdstrike.info.host.aip != ""`).
		IGNORE_FAILURE(true)
	REMOVE("crowdstrike.info.host.aip").
		IF(`ctx._temp?.aip != null`)
	for _, dst := range []string{
		"host.ip",
		"related.ip",
	} {
		APPEND(dst, `{{{_temp.aip}}}`).
			IF(`ctx._temp?.aip != null`).
			ALLOW_DUPLICATES(false)
	}
}

func osFields() {
	BLANK().COMMENT("OS fields.")

	for _, os := range []struct {
		typ           string
		eventPlatform string
	}{
		{typ: "linux", eventPlatform: "Lin"},
		{typ: "macos", eventPlatform: "Mac"},
		{typ: "windows", eventPlatform: "Win"},
		{typ: "ios", eventPlatform: "iOS"},
	} {
		SET("host.os.type").
			IF(fmt.Sprintf(`ctx.crowdstrike?.event_platform != null && ctx.crowdstrike.event_platform == %q`, os.eventPlatform)).
			VALUE(os.typ)
	}
	for _, src := range []string{
		"crowdstrike.OSVersionString",
		"crowdstrike.Version",
	} {
		RENAME(src, "host.os.version").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
}

func serviceFields() {
	BLANK().COMMENT("Service fields.")

	SET("service.name").
		IF(`ctx._temp?.isDriver == true`).
		COPY_FROM("crowdstrike.ServiceDisplayName").
		IGNORE_EMPTY(true)
}

func processFields() {
	BLANK().COMMENT("Process fields.")
	RENAME("crowdstrike.CommandLine", "process.command_line").
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("split command line").
		DESCRIPTION("Implements Windows-like SplitCommandLine").
		IF(`ctx.process?.command_line != null && ctx.process.command_line != "" && ctx.host?.os?.type != null`).
		SOURCE(`
            // appendBSBytes appends n '\\' bytes to b and returns the resulting slice.
            def appendBSBytes(StringBuilder b, int n) {
               for (; n > 0; n--) {
                 b.append('\\');
               }
               return b;
            }

            // readNextArg splits command line string into next
            // argument and command line remainder offset.
            def readNextArg(String line, int offset) {
              def b = new StringBuilder();
              boolean inquote;
              int nslash;
              for (; offset < line.length(); offset++) {
                def c = line.charAt(offset);
                if (c == (char)' ' || c == (char)0x09) {
                  if (!inquote) {
                    return [
                      "arg":  appendBSBytes(b, nslash).toString(),
                      "offset": offset+1
                    ];
                  }
                } else if (c == (char)'"') {
                  b = appendBSBytes(b, nslash/2);
                  if (nslash%2 == 0) {
                    // use "Prior to 2008" rule from
                    // http://daviddeley.com/autohotkey/parameters/parameters.htm
                    // section 5.2 to deal with double double quotes
                    if (inquote && offset+1 < line.length() && line.charAt(offset+1) == (char)'"') {
                      b.append(c);
                      offset++;
                    }
                    inquote = !inquote;
                  } else {
                    b.append(c);
                  }
                  nslash = 0;
                  continue;
                } else if (c == (char)'\\') {
                  nslash++;
                  continue;
                }
                b = appendBSBytes(b, nslash);
                nslash = 0;
                b.append(c);
              }
              return [
                "arg":  appendBSBytes(b, nslash).toString(),
                "offset": line.length()
              ];
            }

            // commandLineToArgv splits a command line into individual argument
            // strings, following the Windows conventions documented
            // at http://daviddeley.com/autohotkey/parameters/parameters.htm#WINARGV
            // Original implementation found at: https://github.com/golang/go/commit/39c8d2b7faed06b0e91a1ad7906231f53aab45d1
            def commandLineToArgv(String line) {
              def args = new ArrayList();
              for (int i = 0; i < line.length();) {
                if (line.charAt(i) == (char)' ' || line.charAt(i) == (char)0x09) {
                  i++;
                  continue;
                }
                def next = readNextArg(line, i);
                i = next.offset;
                if (next.arg == '') {
                  // Empty strings will be removed later so don't bother adding them.
                  continue;
                }
                args.add(next.arg);
              }
              return args;
            }

            ctx.process.args = commandLineToArgv(ctx.process.command_line);
            ctx.process.args_count = ctx.process.args.length;
		`)

	RENAME("crowdstrike.ImageFileName", "process.executable").
		IF(`ctx._temp?.isLibrary != true && ctx._temp?.isDriver != true`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("process name").
		DESCRIPTION("Calculate process.name").
		IF(`ctx.process?.executable != null && ctx.process.executable != ""`).
		SOURCE(`
          def executable = ctx.process.executable;
          def exe_arr = [];
          def name = executable;
          if(executable.substring(0,1) == "\\") {
            name = executable.splitOnToken("\\")[-1];
          } else if(executable.substring(0,1) == "/") {
            name = executable.splitOnToken("/")[-1];
          }
          ctx.process.put("name", name);
		`)

	BLANK()
	SCRIPT().
		COMMENT(`This handles a special case occurs in Linux-based containerized environments
when the "runc" process clones itself to get into its own namespace.
The child process would have its executable path set to "/"
and consequently, the process name would not be set.
For more details, see https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2021/12/28/runc-internals-3.`).
		TAG("parse process name from command line").
		DESCRIPTION("Extract process.name from command line if not already present.").
		IF(`
          ctx.process?.executable == '/' &&
          (ctx.process.name == null || ctx.process.name == '') &&
          (ctx.process.args instanceof List && ctx.process.args.length > 0)
		`).
		SOURCE(`
          ctx.process.name = ctx.process.args[0];

          // Clean up path separators.
          int lastSlash = ctx.process.name.lastIndexOf("/");
          if (lastSlash != -1) {
            ctx.process.name = ctx.process.name.substring(lastSlash + 1);
          }
		`)

	CONVERT("", "crowdstrike.ExitCode", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ExitCode", "process.exit_code").
		IGNORE_MISSING(true)
	for _, src := range []string{
		"crowdstrike.ProcessStartTime",
		"crowdstrike.ProcessEndTime",
	} {
		CONVERT("", src, "string").
			IGNORE_MISSING(true)
	}

	SCRIPT().
		TAG("process uptime").
		DESCRIPTION("Calculate process.uptime").
		IF(`
          ctx.crowdstrike?.ProcessStartTime != null && ctx.crowdstrike?.ProcessStartTime != "" &&
          ctx.crowdstrike?.ProcessEndTime != null && ctx.crowdstrike?.ProcessEndTime != ""
		`).
		SOURCE(`
          float s = Float.parseFloat(ctx.crowdstrike?.ProcessStartTime);
          float e = Float.parseFloat(ctx.crowdstrike?.ProcessEndTime);
          if (e >= s) {
            if (ctx.process == null) {
              ctx.process = [];
            }
            ctx.process.uptime = (long) ((e-s)/1000L);
          }
		`)
	SCRIPT().
		TAG("parse raw pids").
		DESCRIPTION("Parse raw process id's so that they roll over if out of 32-bit range").
		SOURCE(`
          def parsePid(String pid) {
            try {
              return Long.parseUnsignedLong(pid);
            } catch (Exception e) {
              return pid;
            }
          }
          if (ctx.crowdstrike?.RawProcessId != null) {
            ctx.crowdstrike.RawProcessId = parsePid(ctx.crowdstrike.RawProcessId);
          }
          if (ctx.crowdstrike?.EtwRawProcessId != null) {
            ctx.crowdstrike.EtwRawProcessId = parsePid(ctx.crowdstrike.EtwRawProcessId);
          }
		`)

	for _, timestamp := range []struct {
		name string
	}{
		{name: "Start"},
		{name: "End"},
	} {
		id := strings.ToLower(timestamp.name)
		field := fmt.Sprintf("crowdstrike.Process%sTime", timestamp.name)
		painField := fmt.Sprintf("ctx.crowdstrike?.Process%sTime", timestamp.name)
		DATE(field, field, "UNIX").
			TAG(fmt.Sprintf("date process %s time", id)).
			IF(notNullEmpytOrNone(painField))
		RENAME(field, fmt.Sprintf("process.%s", id)).
			IF(painField + ` != ""`).
			IGNORE_MISSING(true)
	}

	RENAME("crowdstrike.RawProcessId", "process.pid").
		IGNORE_MISSING(true)

	for _, change := range []struct {
		from string
		to   string
		cond string
	}{
		{
			from: "crowdstrike.TargetProcessId",
			to:   "process.entity_id",
			cond: `ctx.crowdstrike?.TargetProcessId != null && !(ctx.crowdstrike.TargetProcessId instanceof String)`,
		},
		{
			from: "crowdstrike.ParentProcessId",
			to:   "process.parent.entity_id",
			cond: `ctx.crowdstrike?.ParentProcessId != null && !(ctx.crowdstrike.ParentProcessId instanceof String)`,
		},
	} {
		CONVERT("", change.from, "string").
			IF(change.cond).
			IGNORE_MISSING(true)
		RENAME(change.from, change.to).
			IGNORE_MISSING(true)
	}

	SET("process.name").
		IF(`ctx._temp?.isNetwork == true`).
		COPY_FROM("crowdstrike.ContextBaseFileName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.ParentBaseFileName", "process.parent.name").
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.ProcessGroupId", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ProcessGroupId", "process.pgid").
		IGNORE_MISSING(true)
	SET("process.entity_id").
		IF(`ctx.process?.entity_id == null`).
		COPY_FROM("crowdstrike.ContextProcessId").
		IGNORE_EMPTY(true)
	CONVERT("", "crowdstrike.ContextThreadId", "long").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ContextThreadId", "process.thread.id").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.EtwRawProcessId", "process.pid").
		IF(`ctx.process?.pid == null`).
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.EtwRawThreadId", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.EtwRawThreadId", "process.thread.id").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true)

	RENAME("crowdstrike.ServiceDisplayName", "process.title").
		IGNORE_MISSING(true)
	RENAME("_temp.hashes", "process.hash").
		IF(`
          ctx.event?.action != null &&
          (ctx.event.action.contains("Process") || ctx.event.action.contains("Service")) &&
          ctx._temp?.hashes != null && ctx._temp?.hashes.size() > 0
		`)
	SCRIPT().
		TAG("integrity level").
		IF(`ctx.crowdstrike?.IntegrityLevel != null`).
		PARAMS(map[string]any{
			"levels": map[string]any{
				"0":     "UNTRUSTED",
				"4096":  "LOW",
				"8192":  "MEDIUM",
				"8448":  "MEDIUM_PLUS",
				"12288": "HIGH",
				"16384": "SYSTEM",
				"20480": "PROTECTED",
			},
		}).
		SOURCE(`
          String level = params.get('levels')[ctx.crowdstrike.IntegrityLevel];
          if (level != null) {
            ctx.process = ctx.process ?: [:];
            ctx.process.Ext = ctx.process.Ext ?: [:];
            ctx.process.Ext.token = ctx.process.Ext.token ?: [:];
            ctx.process.Ext.token.integrity_level_name = level;
          }
		`)
	SET("process.pe.original_file_name").
		IF(`ctx._temp?.isProcess == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	CONVERT("process.group_leader.entity_id", "process.pgid", "string").
		IF(`ctx._temp?.isProcess == true && ctx.host?.os?.type == 'linux'`).
		IGNORE_MISSING(true)

	for _, copy := range []struct {
		dst  string
		src  string
		cond string
	}{
		{dst: "process.real_user.id", src: "crowdstrike.RUID"},
		{dst: "user.Ext.real.id", src: "process.real_user.id"},
		{dst: "process.real_group.id", src: "crowdstrike.RGID", cond: `ctx.host?.os?.type == 'linux'`},
		{dst: "group.Ext.real.id", src: "process.real_group.id"},
		{dst: "process.group.id", src: "crowdstrike.GID", cond: `ctx.host?.os?.type == 'linux'`},
		{dst: "group.id", src: "process.group.id"},
	} {
		s := SET(copy.dst).COPY_FROM(copy.src).IGNORE_EMPTY(true)
		if copy.cond != "" {
			s.IF(copy.cond)
		}
	}
}

func libraryFields() {
	BLANK().COMMENT("Library fields.")

	SET("event.action").
		IF(`ctx._temp?.isDriver == true`).
		VALUE("load")
	SET("dll.pe.original_file_name").
		IF(`(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	for _, change := range []struct {
		from string
		to   string
		cond string
	}{
		{from: "process.name", to: "dll.name", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "process.executable", to: "dll.path", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.MD5HashData", to: "dll.hash.md5", cond: `(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.SHA1HashData", to: "dll.hash.sha1", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.SHA256HashData", to: "dll.hash.sha256", cond: `(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`},
	} {
		RENAME(change.from, change.to).
			IF(change.cond).
			IGNORE_MISSING(true)
	}
	CONVERT("dll.Ext.size", "crowdstrike.ModuleSize", "long").
		IF(`ctx.crowdstrike?.ModuleSize != '' && ctx.host?.os?.type == 'windows'`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SCRIPT().
		TAG(`script set dll name`).
		IF(`
           (ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) &&
           ctx.crowdstrike?.ImageFileName != null &&
           ctx.host?.os?.type == 'windows'
		`).
		SOURCE(`
           int idx = ctx.crowdstrike.ImageFileName.lastIndexOf('\\');
           if (idx >= 0) {
             ctx.dll = ctx.dll ?: [:];
             ctx.dll.name = ctx.crowdstrike.ImageFileName.substring(idx+1);
           }
		`).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.ImageFileName", "dll.path").
		IF(`
          (ctx.event?.action == 'ClassifiedModuleLoad' || ctx._temp?.isDriver == true) &&
          ctx.host?.os?.type == 'windows'
		`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG(`script set process name`).
		IF(`ctx._temp?.isLibrary == true && ctx.crowdstrike?.TargetImageFileName != null && ctx.host?.os?.type == 'windows'`).
		SOURCE(`
          int idx = ctx.crowdstrike.TargetImageFileName.lastIndexOf('\\');
          if (idx >= 0) {
            ctx.process = ctx.process ?: [:];
            ctx.process.name = ctx.crowdstrike.TargetImageFileName.substring(idx+1);
          }
		`).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.TargetImageFileName", "process.executable").
		IF(`ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG(`script set process name`).
		IF(`
          ctx.event?.action == 'ClassifiedModuleLoad' &&
          ctx.crowdstrike?.ImageSignatureLevel != null &&
          ctx.crowdstrike.ImageSignatureLevel != '' &&
          ctx.crowdstrike?.ImageSignatureType != null &&
          ctx.crowdstrike.ImageSignatureType != ''
		`).
		SOURCE(`
          long signatureLevel = Long.parseLong(ctx.crowdstrike.ImageSignatureLevel);
          long signatureType = Long.parseLong(ctx.crowdstrike.ImageSignatureType);
          ctx.dll = ctx.dll ?: [:];
          ctx.dll.code_signature = ctx.dll.code_signature ?: [:];
          if (signatureType == 0) {
            ctx.dll.code_signature.exists = false;
            ctx.dll.code_signature.trusted = false;
          } else if (signatureType >= 1 && (signatureLevel == 0 || signatureLevel == 1)) {
            ctx.dll.code_signature.exists = true;
            ctx.dll.code_signature.trusted = false;
          } else if (signatureType >= 1 && signatureLevel >= 2) {
            ctx.dll.code_signature.exists = true;
            ctx.dll.code_signature.trusted = true;
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	SET("dll.code_signature.subject_name").
		IF(`ctx._temp?.isDriver == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.CertificatePublisher").
		IGNORE_EMPTY(true)
}

func registryFields() {
	BLANK().COMMENT("Registry fields.")

	APPEND("registry.data.strings", `{{{crowdstrike.RegStringValue}}}`).
		IF(`ctx.crowdstrike?.RegStringValue != null && ctx.crowdstrike.RegStringValue != ''`).
		ALLOW_DUPLICATES(false)
	SET("registry.path").
		IF(`ctx.crowdstrike?.RegObjectName != null && ctx.crowdstrike.RegObjectName != '' && ctx.crowdstrike?.RegValueName != null && ctx.crowdstrike.RegValueName != ''`).
		VALUE(`{{{crowdstrike.RegObjectName}}}\{{{crowdstrike.RegValueName}}}`)
	SET("registry.path").
		IF(`ctx.crowdstrike?.RegValueName == null || ctx.crowdstrike.RegValueName == ''`).
		COPY_FROM("crowdstrike.RegObjectName").
		IGNORE_EMPTY(true)
	SET("registry.value").
		COPY_FROM("crowdstrike.RegValueName").
		IGNORE_EMPTY(true)
	GSUB("registry.key", "crowdstrike.RegObjectName", `^\\REGISTRY\\(?:USER|MACHINE)\\`, "").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)

	SCRIPT().
		TAG("script set event action and type").
		IF(`ctx.crowdstrike?.RegOperationType != null`).
		PARAMS(map[string]any{
			"op_types": map[string]any{
				"1": map[string]any{
					"type":   "change",
					"action": "modification",
				},
				"2": map[string]any{
					"type":   "deletion",
					"action": "deletion",
				},
				"3": map[string]any{
					"type":   "creation",
					"action": "creation",
				},
				"4": map[string]any{
					"type":   "deletion",
					"action": "deletion",
				},
				"5": map[string]any{
					"type":   "change",
					"action": "modification",
				},
				"6": map[string]any{
					"type":   "info",
					"action": "load",
				},
				"7": map[string]any{
					"type":   "change",
					"action": "modification",
				},
				"8": map[string]any{
					"type":   "access",
					"action": "open",
				},
				"9": map[string]any{
					"type":   "access",
					"action": "query",
				},
			}}).
		SOURCE(`
          def op = params.get('op_types')[ctx.crowdstrike.RegOperationType];
          if (op != null) {
            ctx.event = ctx.event ?: [:];
            ctx.event.type = [];
            ctx.event.type.add(op.type);
            ctx.event.action = op.action;
          }
		`)
	SCRIPT().
		TAG("script set registry data type").
		IF(`ctx.crowdstrike?.RegType != null`).
		PARAMS(map[string]any{
			"data_types": map[string]any{
				"0":  "REG_NONE",
				"1":  "REG_SZ",
				"2":  "REG_EXPAND_SZ",
				"3":  "REG_BINARY",
				"4":  "REG_DWORD",
				"5":  "REG_DWORD_BIG_ENDIAN",
				"6":  "REG_LINK",
				"7":  "REG_MULTI_SZ",
				"8":  "REG_RESOURCE_LIST",
				"9":  "REG_FULL_RESOURCE_DESCRIPTOR",
				"10": "REG_RESOURCE_REQUIREMENTS_LIST",
				"11": "REG_QWORD",
			}}).
		SOURCE(`
          String data_type = params.get('data_types')[ctx.crowdstrike.RegType];
          if (data_type != null) {
            ctx.registry = ctx.registry ?: [:];
            ctx.registry.data = ctx.registry.data ?: [:];
            ctx.registry.data.type = data_type;
          }
		`)
}

func userFields() {
	BLANK().COMMENT("User fields.")

	RENAME("crowdstrike.UID", "user.id").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.info.user.UserName", "user.name").
		IF(`ctx.crowdstrike?.info?.user?.UserName != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	SPLIT("_temp.info_user_parts", "crowdstrike.info.user.User", `\\{1,2}`).
		IF(`ctx.crowdstrike?.info?.user?.User != null`)
	SET("user.domain").
		IF(`ctx._temp?.info_user_parts != null && ctx._temp.info_user_parts.size() == 2`).
		VALUE(`{{{_temp.info_user_parts.0}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.info.user.User", "user.name").
		IF(`ctx.crowdstrike?.info?.user?.User != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.GID", "user.group.id").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.UserSid", "user.id").
		IF(`ctx.user?.id == null || ctx.user.id == ""`).
		IGNORE_MISSING(true)
	SET("user.id").
		IF(`ctx.user?.id == null && ctx._temp?.isFile == true`).
		COPY_FROM("crowdstrike.FileOperatorSid").
		IGNORE_EMPTY(true)
	APPEND("user.roles", "admin").
		IF(`ctx.crowdstrike?.UserIsAdmin == "1"`)
	RENAME("crowdstrike.User.Name", "user.name").
		IF(`ctx.crowdstrike?.User instanceof Map && ctx.crowdstrike.User.Name != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.UserName", "user.name").
		IF(`ctx.crowdstrike?.UserName != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.User", "user.name").
		IF(`ctx.crowdstrike?.User instanceof String && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	SPLIT("_temp.user_parts", "crowdstrike.UserPrincipal", "@").
		IF(`ctx.crowdstrike?.UserPrincipal != null`)
	RENAME("crowdstrike.UserPrincipal", "user.email").
		IGNORE_MISSING(true)
	SET("user.domain").
		IF(`ctx.user?.domain == null && ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2`).
		VALUE(`{{{_temp.user_parts.1}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	APPEND("user.domain", `{{{_temp.user_parts.1}}}`).
		IF(`ctx.user?.domain != null && ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2 && ctx.user.domain != ctx._temp.user_parts[0]`).
		ALLOW_DUPLICATES(false).
		IGNORE_FAILURE(true)
	SET("user.full_name").
		IF(`ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2`).
		VALUE(`{{{_temp.user_parts.0}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	SET("user.name").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('ActiveDirectory')`).
		COPY_FROM("crowdstrike.SourceAccountSamAccountName").
		IGNORE_EMPTY(true)
	SET("user.email").
		IF(`
          ctx.event?.action instanceof String && ctx.event.action.startsWith('ActiveDirectory') &&
          ctx.crowdstrike?.SourceAccountUserName instanceof String && ctx.crowdstrike.SourceAccountUserName.contains('@')
		`).
		COPY_FROM("crowdstrike.SourceAccountUserName").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('ActiveDirectory')`).
		COPY_FROM("crowdstrike.SourceEndpointAccountObjectSid").
		IGNORE_EMPTY(true)
	SET("user.domain").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('ActiveDirectory')`).
		COPY_FROM("crowdstrike.SourceAccountDomain").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.OriginalUserName").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.OriginalUserSid").
		IGNORE_EMPTY(true)
	SET("user.target.name").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.ImpersonatedUserName").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.OriginalUserName").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`(ctx.user?.name == null || ctx.user.name == '') && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE("root")
	SET("user.id").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.OriginalUserID").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx.user?.id == null && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE(0)
	SET("user.target.name").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.NewUsername").
		IGNORE_EMPTY(true)
	SET("user.target.name").
		IF(`(ctx.user?.target?.name == null || ctx.user.target.name == '') && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE("root")
	SET("user.target.id").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.NewUserID").
		IGNORE_EMPTY(true)
	SET("user.target.id").
		IF(`ctx.user?.target?.id == null && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE(0)
	for _, field := range []struct {
		cond  string
		value string
	}{
		{value: `{{{user.name}}}`, cond: `ctx.user?.name != null`},
		{value: `{{{crowdstrike.info.user.User}}}`, cond: `ctx.crowdstrike?.info?.user?.User != null`},
		{value: `{{{user.full_name}}}`, cond: `ctx.user?.full_name != null`},
		{value: `{{{user.target.name}}}`, cond: `ctx.user?.target?.name != null`},
		{value: `{{{user.email}}}`, cond: `ctx.user?.email != null`},
		{value: `{{{user.id}}}`, cond: `ctx.user?.id != null`},
	} {
		APPEND("related.user", field.value).
			IF(field.cond).
			ALLOW_DUPLICATES(false).
			IGNORE_FAILURE(true)
	}
}

func networkFields() {
	BLANK().COMMENT("Networking fields.")

	for i, dir := range []string{
		"outbound",
		"inbound",
	} {
		SET("network.direction").
			TAG(fmt.Sprintf("set network direction %s", dir)).
			IF(fmt.Sprintf(`ctx.crowdstrike?.ConnectionDirection == "%d"`, i)).
			VALUE(dir)
	}
	SET("network.direction").
		TAG("set network direction unknown").
		IF(`ctx.network?.direction == null && ctx.crowdstrike?.ConnectionDirection != null && ctx.crowdstrike.ConnectionDirection != ""`).
		VALUE("unknown")

	for _, v := range []int{4, 6} {
		local := fmt.Sprintf("crowdstrike.LocalAddressIP%d", v)
		isNonEmptyList := fmt.Sprintf(`ctx.crowdstrike?.LocalAddressIP%[1]d instanceof List && ctx.crowdstrike.LocalAddressIP%[1]d.length > 0`, v)
		SPLIT("", local, `\s+`).
			IF(fmt.Sprintf(`ctx.crowdstrike?.LocalAddressIP%d != null`, v))
		CONVERT("", local, "ip").
			IF(isNonEmptyList).
			ON_FAILURE(
				APPEND("error.message", errorMessage),
			)
		CONVERT("", fmt.Sprintf("crowdstrike.RemoteAddressIP%d", v), "ip").
			IGNORE_MISSING(true)
		FOREACH(local,
			APPEND("related.ip", `{{{_ingest._value}}}`).
				ALLOW_DUPLICATES(false),
		).IF(isNonEmptyList)
	}

	for _, pipe := range []struct {
		name    string
		cond    string
		comment string
	}{
		{
			name: "outbound_network",
			cond: `ctx.network?.direction != 'inbound'`,
			comment: `The condition for this processor is all non-inbound, but the pipeline operates assuming the
traffic is outbound. In cases where there is no information we make this assumption rather
than dropping the data on the floor.`,
		},
		{
			name: "inbound_network",
			cond: `ctx.network?.direction == 'inbound'`,
		},
	} {
		p := PIPELINE(pipe.name).
			IF(pipe.cond)
		if pipe.comment != "" {
			p.COMMENT(pipe.comment)
		}
	}

	RENAME("crowdstrike.Protocol", "network.iana_number").
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("network transport lookup").
		IF(`ctx.network?.iana_number != null`).
		SOURCE(`
          def iana_number = ctx.network.iana_number;
          if (iana_number == '0') {
              ctx.network.transport = 'hopopt';
          } else if (iana_number == '1') {
              ctx.network.transport = 'icmp';
          } else if (iana_number == '2') {
              ctx.network.transport = 'igmp';
          } else if (iana_number == '6') {
              ctx.network.transport = 'tcp';
          } else if (iana_number == '8') {
              ctx.network.transport = 'egp';
          } else if (iana_number == '17') {
              ctx.network.transport = 'udp';
          } else if (iana_number == '47') {
              ctx.network.transport = 'gre';
          } else if (iana_number == '50') {
              ctx.network.transport = 'esp';
          } else if (iana_number == '58') {
              ctx.network.transport = 'ipv6-icmp';
          } else if (iana_number == '112') {
              ctx.network.transport = 'vrrp';
          } else if (iana_number == '132') {
              ctx.network.transport = 'sctp';
          }
	`)

	COMMUNITY_ID("").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)

	for _, src := range []string{
		"source",
		"destination",
	} {
		APPEND("related.ip", fmt.Sprintf(`{{{%s.ip}}}`, src)).
			IF(fmt.Sprintf(`ctx.%[1]s?.ip != null && ctx.%[1]s.ip != ""`, src)).
			ALLOW_DUPLICATES(false)
	}

	RENAME("crowdstrike.MAC", "source.mac").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.PhysicalAddress", "source.mac").
		IF(`ctx.source?.mac == null`).
		IGNORE_MISSING(true)
	UPPERCASE("", "source.mac").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DownloadServer", "server.address").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DownloadPath", "url.path").
		IGNORE_MISSING(true)
}

func urlFields() {
	BLANK().COMMENT("URL fields.")

	SET("url.path").
		IF(`ctx.url?.path != null && !ctx.url.path.startsWith("/")`).
		VALUE(`/{{{url.path}}}`)
	REGISTERED_DOMAIN("server", "server.address").
		IGNORE_MISSING(true)
	for _, prot := range []struct {
		scheme string
		cond   string
	}{
		{scheme: "https", cond: `ctx.crowdstrike?.DownloadPort == 443`},
		{scheme: "http", cond: `ctx.crowdstrike?.DownloadPort != null && ctx.crowdstrike.DownloadPort != 443`},
	} {
		SET("url.scheme").
			IF(prot.cond).
			VALUE(prot.scheme)
	}
	SET("url.full").
		IF(`ctx.url?.scheme != null && ctx.server?.address != null && ctx.url?.path != null`).
		VALUE(`{{{url.scheme}}}://{{{server.address}}}{{{url.path}}}`)
	URI_PARTS("", "url.full").
		IF(`ctx.url?.full != null`)
	REGISTERED_DOMAIN("url", "url.domain").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
}

func ipGeolocationLookup() {
	BLANK().COMMENT("IP Geolocation Lookup.")

	for _, ip := range []struct {
		src       string
		firstOnly bool
	}{
		{src: "observer"},
		{src: "source", firstOnly: true},
		{src: "destination"},
	} {
		g := GEOIP(fmt.Sprintf("%s.geo", ip.src), fmt.Sprintf("%s.ip", ip.src)).
			IGNORE_MISSING(true)
		if ip.firstOnly {
			g.FIRST_ONLY(true)
		}
	}
}

func autonomousSystemLookup() {
	BLANK().COMMENT("IP Autonomous System (AS) Lookup")

	for _, ip := range []struct {
		src       string
		firstOnly bool
	}{
		{src: "source", firstOnly: true},
		{src: "destination"},
	} {
		g := GEOIP(ip.src+".as", ip.src+".ip").
			DATABASE_FILE("GeoLite2-ASN.mmdb").
			PROPERTIES("asn", "organization_name").
			IGNORE_MISSING(true)
		if ip.firstOnly {
			g.FIRST_ONLY(true)
		}
		RENAME(ip.src+".as.asn", ip.src+".as.number").
			IGNORE_MISSING(true)
		RENAME(ip.src+".as.organization_name", ip.src+".as.organization.name").
			IGNORE_MISSING(true)
	}
}

func dnsFields() {
	BLANK().COMMENT("DNS fields.")

	isDNS := `ctx.event?.action != null && ctx.event.action.contains("DnsRequest")`
	SET("dns.type").
		IF(isDNS).
		VALUE("query")
	SET("network.protocol").
		IF(isDNS).
		VALUE("dns")
	REGISTERED_DOMAIN("dns.question", "crowdstrike.DomainName").
		IF(isDNS).
		IGNORE_MISSING(true)
	RENAME("dns.question.domain", "dns.question.name").
		IF(isDNS).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DomainName", "dns.question.name").
		IF(`ctx.event?.action != null && ctx.dns?.question?.name == null && ctx.event.action.contains("DnsRequest")`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("dns request type to name").
		DESCRIPTION("Map decimal DNS request type to its name.").
		PARAMS(map[string]any{
			"1":     "A",
			"2":     "NS",
			"5":     "CNAME",
			"6":     "SOA",
			"12":    "PTR",
			"13":    "HINFO",
			"15":    "MX",
			"16":    "TXT",
			"17":    "RP",
			"18":    "AFSDB",
			"24":    "SIG",
			"25":    "KEY",
			"28":    "AAAA",
			"29":    "LOC",
			"33":    "SRV",
			"35":    "NAPTR",
			"36":    "KX",
			"37":    "CERT",
			"39":    "DNAME",
			"42":    "APL",
			"43":    "DS",
			"44":    "SSHFP",
			"45":    "IPSECKEY",
			"46":    "RRSIG",
			"47":    "NSEC",
			"48":    "DNSKEY",
			"49":    "DHCID",
			"50":    "NSEC3",
			"51":    "NSEC3PARAM",
			"52":    "TLSA",
			"53":    "SMIMEA",
			"55":    "HIP",
			"59":    "CDS",
			"60":    "CDNSKEY",
			"61":    "OPENPGPKEY",
			"62":    "CSYNC",
			"63":    "ZONEMD",
			"64":    "SVCB",
			"65":    "HTTPS",
			"108":   "EUI48",
			"109":   "EUI64",
			"249":   "TKEY",
			"250":   "TSIG",
			"256":   "URI",
			"257":   "CAA",
			"32768": "TA",
			"32769": "DLV",
		}).
		IF(`ctx.event?.action != null && ctx.crowdstrike?.RequestType != null && !ctx.crowdstrike.RequestType.isEmpty() && ctx.event.action.contains("DnsRequest")`).
		SOURCE(`
              def t = params[ctx.crowdstrike.RequestType];
              if (t != null) {
                if (ctx.dns?.question == null) {
                  ctx.dns.question = new HashMap();
                }
                ctx.dns.question.type = t;
                ctx.crowdstrike.remove("RequestType");
              }
			`)
}

func smbFields() {
	BLANK().COMMENT("SMB fields.")

	REGISTERED_DOMAIN("destination", "crowdstrike.DomainName").
		IF(`ctx.event?.action != null && ctx.event.action.contains("SmbServerShareOpenedEtw")`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DomainName", "destination.domain").
		IF(`ctx.event?.action != null && ctx.destination?.domain == null && ctx.event.action.contains("SmbServerShareOpenedEtw")`).
		IGNORE_MISSING(true)
}

func fileFields() {
	BLANK().COMMENT("File fields.")

	SET("file.pe.original_file_name").
		IF(`ctx._temp?.isFile == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	CONVERT("", "crowdstrike.Size", "long").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.Size", "file.size").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.FileIdentifier", "file.inode").
		IGNORE_MISSING(true)
	SET("file.Ext.original.path").
		IF(`ctx.event?.action == 'NewExecutableRenamed' || ctx.event?.action == 'FileRenameInfo'`).
		COPY_FROM("crowdstrike.SourceFileName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.SourceFileName", "file.path").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.TargetFileName", "file.path").
		IF(`ctx.file?.path == null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SET("file.path").
		IF(`ctx.event?.action == 'NewExecutableRenamed' || ctx.event?.action == 'FileRenameInfo'`).
		COPY_FROM("crowdstrike.TargetFileName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.DiskParentDeviceInstanceId", "file.device").
		IGNORE_MISSING(true)
	SET("file.type").
		IF(`ctx.file?.path != null && !ctx.event.action.contains("Directory")`).
		VALUE("file")
	SET("file.type").
		IF(`ctx.file?.path != null && (ctx.event.action.contains("Directory") || ctx.file.path.endsWith("\\") || ctx.file.path.endsWith("/"))`).
		VALUE("dir")
	SCRIPT().
		TAG("parse file path").
		DESCRIPTION("Adds file information.").
		IF(`ctx.file?.path != null && ctx.file.path.length() > 1`).
		SOURCE(`
          def removeSuffix(String s, String suffix) {
            if (s != null && suffix != null && s.endsWith(suffix)) {
              return s.substring(0, s.length() - suffix.length());
            }
            return s;
          }

          def path = removeSuffix(ctx.file.path, "/");
          path = removeSuffix(path, "\\");
          def idx = path.lastIndexOf("\\");
          if (idx == -1) {
            idx = path.lastIndexOf("/");
          }
          if (idx > -1) {
            if (ctx.file == null) {
                ctx.file = new HashMap();
            }
            ctx.file.name = path.substring(idx+1);
            ctx.file.directory = path.substring(0, idx);

            def extIdx = ctx.file.name.lastIndexOf(".");
            if (extIdx > -1 && ctx.file.type == "file") {
              ctx.file.extension = ctx.file.name.substring(extIdx+1);
            }
          }
          if (path.indexOf(':') == 1) {
            ctx.file.drive_letter = path.substring(0, 1).toUpperCase();
          }
		`)
	SCRIPT().
		TAG("parse file ext original path").
		DESCRIPTION("Adds file.Ext.original.* information.").
		IF(`ctx.file?.Ext?.original?.path != null && ctx.file.Ext.original.path.length() > 1`).
		SOURCE(`
          def removeSuffix(String s, String suffix) {
            if (s != null && suffix != null && s.endsWith(suffix)) {
              return s.substring(0, s.length() - suffix.length());
            }
            return s;
          }

          def path = removeSuffix(ctx.file.Ext.original.path, "/");
          path = removeSuffix(path, "\\");
          def idx = path.lastIndexOf("\\");
          if (idx == -1) {
            idx = path.lastIndexOf("/");
          }
          if (idx > -1) {
            ctx.file.Ext.original.name = path.substring(idx+1);
          }
		`)
	RENAME("_temp.hashes", "file.hash").
		IF(`ctx.event?.action != null && (ctx.event.action.contains("File") || ctx.event.action.contains("Directory") || ctx.event.action.contains("Executable")) && ctx._temp?.hashes != null && ctx._temp?.hashes.size() > 0`)
	SET("process.name").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written')`).
		COPY_FROM("crowdstrike.ContextBaseFileName").
		IGNORE_EMPTY(true)
	SET("process.executable").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.ContextImageFileName").
		IGNORE_EMPTY(true)
	SET("process.entity_id").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'linux'`).
		COPY_FROM("crowdstrike.ContextProcessId").
		IGNORE_EMPTY(true)
	SET("file.hash.sha256").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'linux'`).
		COPY_FROM("crowdstrike.SHA256HashData").
		IGNORE_EMPTY(true)
	SET("event.action").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'windows'`).
		VALUE("creation")
}

func deviceFields() {
	BLANK().COMMENT("Device Fields.")

	for i, src := range []string{
		"crowdstrike.SensorId",
		"crowdstrike.DeviceId",
		"observer.serial_number",
	} {
		s := SET("device.id").
			TAG(fmt.Sprintf("set device id from %s", src)).
			COPY_FROM(src).
			IGNORE_EMPTY(true)
		if i != 0 {
			s.IF(`ctx.device?.id == null`)
		}
	}
}

func crowdstrikeFields() {
	BLANK().COMMENT("Crowdstrike fields.")

	JSON("", "crowdstrike.ResourceAttributes").
		IF(`ctx.crowdstrike?.ResourceAttributes instanceof String`).
		ON_FAILURE(
			REMOVE("crowdstrike.ResourceAttributes").
				IGNORE_MISSING(true),
		)
	for _, src := range []string{
		"crowdstrike.FalconGroupingTags",
		"crowdstrike.SensorGroupingTags",
	} {
		SPLIT("", src, `,\s?`).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	SCRIPT().
		TAG("convert Tags").
		DESCRIPTION("Convert tags for indexing as keyword.").
		IF(`ctx.crowdstrike?.Tags != null`).
		SOURCE(`
          def result = [];

          if (ctx.crowdstrike.Tags instanceof String) {
            def parts = ctx.crowdstrike.Tags.splitOnToken(",");
            for (def part : parts) {
              def trimmed = part.trim();
              if (trimmed != "") {
                result.add(trimmed);
              }
            }
          } else if (ctx.crowdstrike.Tags instanceof Map) {
            for (def entry : ctx.crowdstrike.Tags.entrySet()) {
              result.add(entry.getKey() + ":" + entry.getValue());
            }
          } else if (ctx.crowdstrike.Tags instanceof List) {
            for (def tag : ctx.crowdstrike.Tags) {
              if (tag instanceof Map) {
                // this format is seen in the falcon data stream
                result.add(tag["Key"] + ":" + tag["ValueString"]);
              } else if (tag instanceof String) {
                // this isn't expected but avoid throwing away indexable data
                result.add(tag);
              }
            }
          }

          ctx.crowdstrike.Tags = result;
		`)
	SPLIT("", "crowdstrike.CallStackModuleNames", `\|`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []string{
		"crowdstrike.UserTime",
		"crowdstrike.KernelTime",
		"crowdstrike.CycleTime",
	} {
		CONVERT("", src, "long").
			IGNORE_MISSING(true)
	}
	APPEND("related.hash", `{{{crowdstrike.ConfigStateHash}}}`).
		IF(`ctx.crowdstrike?.ConfigStateHash != null && ctx.crowdstrike.ConfigStateHash != ""`).
		ALLOW_DUPLICATES(false).
		IGNORE_FAILURE(true)
	TRIM("", "crowdstrike.BootArgs").
		IGNORE_MISSING(true)
	SPLIT("", "crowdstrike.BootArgs", `\s+`).
		IGNORE_MISSING(true)
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "crowdstrike.LogonTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.LogonTime")},
		{field: "crowdstrike.LogoffTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.LogoffTime")},
		{field: "crowdstrike.ConnectTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.ConnectTime")},
		{field: "crowdstrike.PreviousConnectTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.PreviousConnectTime")},
		{field: "crowdstrike.AgentLocalTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.AgentLocalTime")},
		{field: "crowdstrike.FirstSeen", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.FirstSeen")},
		{field: "crowdstrike.BiosReleaseDate", formats: []string{"MM/dd/yyyy", "strict_date_optional_time"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.BiosReleaseDate")},
	} {

		DATE(src.field, src.field, src.formats...).
			IF(src.cond).
			IGNORE_FAILURE(true)
	}
	for _, conv := range []struct {
		src string
		typ string
	}{
		{src: "crowdstrike.AgentTimeOffset", typ: "float"},
		{src: "crowdstrike.Timeout", typ: "long"},
		{src: "crowdstrike.PhysicalAddressLength", typ: "long"},
		{src: "crowdstrike.InterfaceIndex", typ: "long"},
		{src: "crowdstrike.NetLuidIndex", typ: "long"},
		{src: "crowdstrike.AttemptNumber", typ: "long"},
		{src: "crowdstrike.SystemTableIndex", typ: "long"},
	} {
		CONVERT("", conv.src, conv.typ).
			IGNORE_MISSING(true)
	}
	for _, src := range []string{
		"crowdstrike.NeighborList",
		"crowdstrike.ConfigStateData",
	} {
		SPLIT("", src, `\|`).
			IGNORE_MISSING(true)
	}
	for _, src := range []struct {
		value string
		cond  string
	}{
		{value: `{{{crowdstrike.LogonServer}}}`, cond: `ctx.crowdstrike?.LogonServer != null`},
		{value: `{{{crowdstrike.ClientComputerName}}}`, cond: `ctx.crowdstrike?.ClientComputerName != null`},
		{value: `{{{crowdstrike.info.user.LastLoggedOnHost}}}`, cond: `ctx.crowdstrike?.info?.user?.LastLoggedOnHost != null`},
	} {
		APPEND("related.hosts", src.value).
			IF(src.cond).
			ALLOW_DUPLICATES(false)
	}

	BLANK()
	var longFields []string
	err := json.Unmarshal(longFieldsData, &longFields)
	if err != nil {
		log.Fatal(err)
	}
	SCRIPT().
		DESCRIPTION("Remove long fields based on user input stored in _conf.long_fields*.").
		TAG("script remove long fields").
		IF("ctx._conf?.long_fields == 'delete_long_fields' && ctx._conf?.long_fields_max_length != null").
		PARAMS(map[string]any{
			"potential_long_fields": longFields,
		}).
		SOURCE(`
          for (String field: params.potential_long_fields) {
            if (ctx.crowdstrike.get(field) != null && ctx.crowdstrike[field].length() > ctx._conf.long_fields_max_length) {
              ctx.crowdstrike.remove(field);
            }
          }
		`)
}

func cleanup() {
	BLANK().COMMENT("Cleanup.")

	REMOVE("crowdstrike.event_platform").
		IF(`ctx.host?.os?.type != null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"log.file.path",
		"log.offset",
	).
		IF(`ctx.aws?.s3?.bucket != null && ctx.aws.s3.object != null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"agent.ephemeral_id",
		"event.timezone",
		"log.offset",
	).
		IF(`ctx._conf?.prune_fields == true`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"_temp",
		"crowdstrike.timestamp",
		"crowdstrike._time",
		"crowdstrike.Time",
		"crowdstrike.CreationTimeStamp",
		"crowdstrike.DomainName",
		"crowdstrike.ConnectionDirection",
		"crowdstrike.UserIsAdmin",
		"crowdstrike.UTCTimestamp",
		"crowdstrike.TargetDirectoryName",
		"_conf",
	).IGNORE_MISSING(true)
	SCRIPT().
		TAG("remove nulls").
		DESCRIPTION("This script processor iterates over the whole document to remove fields with null values.").
		SOURCE(`
          void handleMap(Map map) {
            map.values().removeIf(v -> {
              if (v instanceof Map) {
                  handleMap(v);
              } else if (v instanceof List) {
                  handleList(v);
              }
              return v == null || v == '' || v == '-' || v == 'none' || (v instanceof Map && v.size() == 0) || (v instanceof List && v.size() == 0)
            });
          }
          void handleList(List list) {
            list.removeIf(v -> {
              if (v instanceof Map) {
                  handleMap(v);
              } else if (v instanceof List) {
                  handleList(v);
              }
              return v == null || v == '' || v == '-' || v == 'none' || (v instanceof Map && v.size() == 0) || (v instanceof List && v.size() == 0)
            });
          }
          handleMap(ctx);
		`)

	BLANK()

	BLANK().COMMENT("error handling")

	SET("event.kind").
		TAG("set pipeline error into event.kind").
		IF(`ctx.error?.message != null`).
		VALUE("pipeline_error")
	APPEND("event.kind", "preserve_original_event").
		TAG("append preserve_original_event into event.kind").
		IF(`ctx.error?.message != null`).
		ALLOW_DUPLICATES(false)

	ON_FAILURE(
		SET("event.kind").VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").ALLOW_DUPLICATES(false),
		APPEND("error.message", errorMessage),
	)
}

func notNullEmpytOrNone(f string) string {
	return fmt.Sprintf("%[1]s != null && %[2]s != '' && %[2]s != 'none'", f, strings.ReplaceAll(f, "?", ""))
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
