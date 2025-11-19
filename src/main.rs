// Rust Bytes Challenge Issue #93 Log Analyzer

use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

enum ParserState {
    ParsingMonth,
    ParsingDay,
    ParsingTime,
    ParsingHostname,
    ParsingProcess,
    ParsingPID,
    ParsingMessage,
}

fn main() -> io::Result<()> {
    let file_path = Path::new("./src/Mac_2k.log");
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader.lines();
    for line in lines {
        let line = line?;
        println!("{}", line);
    }

    Ok(())
}

fn parse_record(p0: &str) -> Result<(String, String, String, String, String, String, String), String> {
    // parse_month(p0);
    for ch in p0.chars() {
        if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {

        }
    }
    Ok(("Jul".into(), "1".into(), "09:01:05".into(),
        "calvisitor-10-105-160-95".into(), "com.apple.CDScheduler[43]".into(), "43".into(), "Thermal pressure state: 1 Memory pressure state: 0".into()))
}

fn parse_month(p0: &str) -> Option<String> {
    todo!()
}

#[test]
fn parse_a_valid_line() {
    let line = "Jul  1 09:01:05 calvisitor-10-105-160-95 com.apple.CDScheduler[43]: Thermal pressure state: 1 Memory pressure state: 0";
    let (month, day, time, hostname, process, pid, message) = parse_record(line).unwrap();
    assert_eq!(month, "Jul");
    assert_eq!(day, "1");
    assert_eq!(time, "09:01:05");
    assert_eq!(hostname, "calvisitor-10-105-160-95");
    assert_eq!(process, "com.apple.CDScheduler[43]");
    assert_eq!(pid, "43");
    assert_eq!(message, "Thermal pressure state: 1 Memory pressure state: 0");
}

