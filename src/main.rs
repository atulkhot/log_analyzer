// Rust Bytes Challenge Issue #93 Log Analyzer

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

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

fn parse_record(
    input_record: &str,
) -> Result<(String, String, String, String, String, String, String), String> {
    let (month_str, day_str, time_str, hostname_str, process_str, pid_str, message_str) =
        split_into_flds_str(input_record)?;
    Ok((
        month_str,
        day_str,
        time_str,
        hostname_str,
        process_str,
        pid_str,
        message_str
    ))
}

fn split_into_flds_str(
    input_record: &str,
) -> Result<(String, String, String, String, String, String, String), String> {
    let mut parts = input_record.split_whitespace();
    let month_str = parts
        .next()
        .ok_or("No month found".to_string())
        .and_then(|m_str| parse_month(m_str))?;
    let day_str = parts
        .next()
        .ok_or("No day found".to_string())
        .and_then(|d_str| parse_day(d_str))?;
    let time_str = parts
        .next()
        .ok_or("No time found".to_string())
        .and_then(|t_str| parse_time(t_str))?;
    let hostname_str = parts
        .next()
        .ok_or("No hostname found".to_string())
        .and_then(|h_str| Ok(h_str.to_string()))?;
    let (process_name_str, pid_str) = parts
        .next()
        .ok_or("No process found".to_string())
        .and_then(|p| parse_process_name_and_pid(p))?;
    let message_str = parts.collect::<Vec<_>>().join(" ");
    Ok((
        month_str,
        day_str,
        time_str,
        hostname_str,
        process_name_str,
        pid_str,
        message_str,
    ))
}

fn parse_process_name_and_pid(process_name_str: &str) -> Result<(String, String), String> {
    let parts = process_name_str.split('[').collect::<Vec<_>>();
    if parts.len() == 2 {
        Ok((parts[0].into(), parts[1].strip_suffix("]:").get_or_insert_default().to_string()))
    } else {
        Err(format!("Invalid process string: {}", process_name_str))
    }
}

fn parse_time(timestamp_str: &str) -> Result<String, String> {
    let parts = timestamp_str.split(':').collect::<Vec<_>>();
    if parts.len() == 3 {
        for part in parts.iter() {
            if part.len() != 2 {
                return Err(format!("Invalid time format: {}", timestamp_str));
            }
            if part.parse::<u32>().is_err() {
                return Err(format!("Invalid time - not a number: {}", timestamp_str));
            }
        }
        Ok(format!("{}:{}:{}", parts[0], parts[1], parts[2]))
    } else {
        Err(format!("Invalid time: {}", timestamp_str))
    }
}

fn parse_month(month_str: &str) -> Result<String, String> {
    let set_of_months = HashSet::from([
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]);
    if set_of_months.contains(month_str.to_lowercase().as_str()) {
        Ok(month_str.into())
    } else {
        Err(format!("Invalid month: {}", month_str))
    }
}

fn parse_day(day_str: &str) -> Result<String, String> {
    let day = day_str
        .parse::<u32>()
        .map_err(|_| format!("Invalid day: {}", day_str))?;
    if day > 0 && day <= 31 {
        Ok(day.to_string())
    } else {
        Err(format!("Invalid day: {}", day_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_a_valid_month() {
        assert_eq!(parse_month("Jul").unwrap(), "Jul".to_string());
    }

    #[test]
    fn parse_an_invalid_month() {
        assert!(parse_month("xxx").is_err());
    }

    #[test]
    fn parse_a_valid_day() {
        assert_eq!(parse_day("1").unwrap(), "1".to_string());
    }

    #[test]
    fn parse_an_invalid_day() {
        assert!(parse_day("0").is_err());
    }

    #[test]
    fn parse_a_valid_process_name() {
        assert_eq!(parse_process_name_and_pid("com.apple.CDScheduler[43]:").unwrap(), ("com.apple.CDScheduler".to_string(), "43".to_string()));
    }


    #[test]
    fn parse_a_valid_line() {
        let line = "Jul  1 09:01:05 calvisitor-10-105-160-95 com.apple.CDScheduler[43]: Thermal pressure state: 1 Memory pressure state: 0";
        let (month,
            day,
            time,
            hostname,
            process,
            pid,
            message) = parse_record(line).unwrap();
        assert_eq!(month, "Jul");
        assert_eq!(day, "1");
        assert_eq!(time, "09:01:05");
        assert_eq!(hostname, "calvisitor-10-105-160-95");
        assert_eq!(process, "com.apple.CDScheduler");
        assert_eq!(pid, "43");
        assert_eq!(
            message,
            "Thermal pressure state: 1 Memory pressure state: 0"
        );
    }

    #[test]
    fn parse_another_valid_line() {
        let line = "Jul  8 06:11:46 calvisitor-10-105-162-124 WindowServer[184]: send_datagram_available_ping: pid 445 failed to act on a ping it dequeued before timing out.
";
        let (month,
            day,
            time,
            hostname,
            process,
            pid,
            message) = parse_record(line).unwrap();
        assert_eq!(month, "Jul");
        assert_eq!(day, "8");
        assert_eq!(time, "06:11:46");
        assert_eq!(hostname, "calvisitor-10-105-162-124");
        assert_eq!(process, "WindowServer");
        assert_eq!(pid, "184");
        assert_eq!(message, "send_datagram_available_ping: pid 445 failed to act on a ping it dequeued before timing out.");
    }

    #[test]
    fn test_split_into_flds_str() {
        let input_record = "Jul  1 09:01:05 calvisitor-10-105-160-95 com.apple.CDScheduler[43]: Thermal pressure state: 1 Memory pressure state: 0";
        let (month_str, day_str, time_str, hostname_str, process_str, pid_str, message_str) =
            split_into_flds_str(input_record).unwrap();
        assert_eq!(month_str, "Jul");
        assert_eq!(day_str, "1");
        assert_eq!(time_str, "09:01:05");
        assert_eq!(hostname_str, "calvisitor-10-105-160-95");
        assert_eq!(process_str, "com.apple.CDScheduler");
        assert_eq!(pid_str, "43");
        assert_eq!(
            message_str,
            "Thermal pressure state: 1 Memory pressure state: 0"
        );
    }
}
