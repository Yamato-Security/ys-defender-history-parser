//! Orange Cyberdefense's sample (`tests/fixtures/orange/original/`) and three copies with values
//! edited (`action_id/`, `search_threat_id/`, `ts_modified/`), read as Defender itself gave them
//! through WMI (`Get-WmiObject -Namespace root\Microsoft\Windows\Defender -Class
//! MSFT_MpThreatDetection`, in Orange's `samples/*/note.md` and `doc.md`; see
//! `tests/fixtures/orange/README.md`): what each named value is, shown by WMI changing with it.

use defender::Detection;

const NAME: &str = "94BBE9CF-CDEB-4885-9178-CC93FB10822D";

fn sample(folder: &str) -> Detection {
    let path = format!(
        "{}/tests/fixtures/orange/{folder}/{NAME}",
        env!("CARGO_MANIFEST_DIR")
    );
    let detection = defender::read(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(detection.problems, Vec::<String>::new(), "{folder}");
    detection
}

/// WMI's properties for a sample, the ones the file holds.
struct Wmi {
    action_success: bool,
    cleaning_action_id: u32,
    execution_status_id: u32,
    status_error_code: i64,
    threat_status_id: u32,
    remediation: &'static str,
}

/// What every sample has: WMI's values, its times in UTC to the millisecond.
fn common(detection: &Detection) {
    assert_eq!(detection.id.as_deref(), Some(NAME));
    assert_eq!(detection.threat_id, Some(2_147_686_744));
    assert_eq!(detection.source_type_id, Some(3));
    assert_eq!(detection.source_type_name(), Some("Real-time"));
    assert_eq!(
        detection.user.as_deref(),
        Some(r"DESKTOP-O8964S4\RaptorSniper")
    );
    assert_eq!(
        detection.process.as_deref(),
        Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    );
    let ms = |t: Option<defender::Time>| t.unwrap().to_iso8601()[..23].to_owned();
    assert_eq!(ms(detection.initial_detection), "2025-01-28T16:44:51.243");
    assert_eq!(ms(detection.status_changed), "2025-01-28T16:45:06.220");
    // Resources: {file:_C:\Users\RaptorSniper\Downloads\a.zip}
    let resources: Vec<String> = detection
        .resources
        .iter()
        .map(|r| format!("{}:_{}", r.kind, r.location))
        .collect();
    assert_eq!(resources, [r"file:_C:\Users\RaptorSniper\Downloads\a.zip"]);
}

fn check(folder: &str, wmi: &Wmi) {
    let detection = sample(folder);
    common(&detection);
    assert_eq!(
        detection.action_success(),
        Some(wmi.action_success),
        "{folder}"
    );
    assert_eq!(
        detection.cleaning_action_id(),
        Some(wmi.cleaning_action_id),
        "{folder}"
    );
    assert_eq!(
        detection.execution_status_id,
        Some(wmi.execution_status_id),
        "{folder}"
    );
    assert_eq!(
        detection.status_error_code,
        Some(wmi.status_error_code),
        "{folder}"
    );
    assert_eq!(
        detection.threat_status_id,
        Some(wmi.threat_status_id),
        "{folder}"
    );
    assert_eq!(
        &detection.remediation.unwrap().to_iso8601()[..23],
        wmi.remediation,
        "{folder}"
    );
}

const ORIGINAL: Wmi = Wmi {
    action_success: true,
    cleaning_action_id: 2,
    execution_status_id: 1,
    status_error_code: 0,
    threat_status_id: 3,
    remediation: "2025-01-28T16:45:06.220",
};

#[test]
fn original() {
    check("original", &ORIGINAL);
    let detection = sample("original");
    assert_eq!(detection.threat_status_name(), Some("Quarantined"));
    assert_eq!(detection.execution_status_name(), Some("Blocked"));
}

#[test]
fn action_success_execution_status_and_error_code() {
    check(
        "action_id",
        &Wmi {
            action_success: false,
            execution_status_id: 5,
            status_error_code: 7,
            ..ORIGINAL
        },
    );
}

#[test]
fn cleaning_action_and_status() {
    check(
        "search_threat_id",
        &Wmi {
            cleaning_action_id: 9,
            threat_status_id: 18,
            ..ORIGINAL
        },
    );
}

#[test]
fn remediation_time() {
    check(
        "ts_modified",
        &Wmi {
            remediation: "2025-01-28T16:52:16.241",
            ..ORIGINAL
        },
    );
}
