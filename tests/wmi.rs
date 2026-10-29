//! Orange Cyberdefense's sample (`tests/fixtures/orange/original/`) and three copies with values
//! edited (`action_id/`, `search_threat_id/`, `ts_modified/`), read as Defender itself gave them
//! through WMI (`Get-WmiObject -Namespace root\Microsoft\Windows\Defender -Class
//! MSFT_MpThreatDetection`, in Orange's `samples/*/note.md` and `doc.md`; see
//! `tests/fixtures/orange/README.md`): what each named value is, shown by WMI changing with it.
//!
//! WMI's `CleaningActionID` (2 → 9) and `ActionSuccess` (true → false) changed too, but in copies
//! with two values edited at once (the action with the status, section 6's first value with the
//! error code), so which value of the file each comes from isn't known: those values are kept as
//! unknown (`2.4`, `6.0`), and checked here as stored.

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

/// WMI's properties for a sample, the ones the file holds, and the two values edited with them.
struct Wmi {
    execution_status_id: u32,
    status_error_code: i64,
    threat_status_id: u32,
    remediation: &'static str,
    /// `2.4`, edited with the status (WMI's `CleaningActionID` 2 → 9).
    stored_2_4: u64,
    /// `6.0`, edited with the error code (WMI's `ActionSuccess` true → false).
    stored_6_0: u64,
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
    let unknown = |key: &str| {
        detection
            .unknown
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_u64())
    };
    assert_eq!(unknown("2.4"), Some(wmi.stored_2_4), "{folder}");
    assert_eq!(unknown("6.0"), Some(wmi.stored_6_0), "{folder}");
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
    execution_status_id: 1,
    status_error_code: 0,
    threat_status_id: 3,
    remediation: "2025-01-28T16:45:06.220",
    stored_2_4: 4,
    stored_6_0: 2,
};

#[test]
fn original() {
    check("original", &ORIGINAL);
    let detection = sample("original");
    assert_eq!(detection.threat_status_name(), Some("Quarantined"));
    assert_eq!(detection.execution_status_name(), Some("Blocked"));
}

#[test]
fn execution_status_and_error_code() {
    check(
        "action_id",
        &Wmi {
            execution_status_id: 5,
            status_error_code: 7,
            stored_6_0: 3,
            ..ORIGINAL
        },
    );
}

#[test]
fn status() {
    check(
        "search_threat_id",
        &Wmi {
            threat_status_id: 18,
            stored_2_4: 16,
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
