// Rust Bytes Challenge Issue #93 Log Analyzer

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

#[derive(Debug)]
#[allow(dead_code)]
struct Summary {
    total_entries: usize,
    by_process: Vec<(String, usize)>,
    by_hostname: Vec<(String, usize)>,
    most_frequent_process: String,
    most_frequent_hostname: String,
    top_keywords: Vec<String>,
}

impl Summary {
    fn new(
        total_entries: usize,
        by_process: Vec<(String, usize)>,
        by_hostname: Vec<(String, usize)>,
        most_frequent_process: String,
        most_frequent_hostname: String,
        top_keywords: Vec<String>,
    ) -> Self {
        Self {
            total_entries: total_entries,
            by_process: by_process,
            by_hostname: by_hostname,
            most_frequent_process: most_frequent_process,
            most_frequent_hostname: most_frequent_hostname,
            top_keywords: top_keywords,
        }
    }
}

fn main() -> io::Result<()> {
    let file_path = Path::new("./src/Mac_2k.log");
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader.lines();
    let mut process_freq: HashMap<String, u32> = HashMap::new();
    let mut host_name_freq: HashMap<String, u32> = HashMap::new();
    let mut total_entries = 0;
    let mut most_freq_keywords: HashMap<String, u32> = HashMap::new();
    let stop_words: HashSet<String> = stopwords().iter().map(|x| x.to_string()).collect();

    for line in lines {
        let line = line?;
        total_entries += 1;
        if let Ok((_month_str, _day_str, _time_str, hostname_str, process_str, _pid_str, message_str)) =
            split_into_flds_str(line.as_str())
        {
            let process_score = process_freq.entry(process_str.to_string()).or_insert(0);
            *process_score += 1;
            let host_score = host_name_freq.entry(hostname_str.to_string()).or_insert(0);
            *host_score += 1;
            for keyword in message_str.split_whitespace() {
                if !stop_words.contains(keyword) {
                    let keyword_count =
                        most_freq_keywords.entry(keyword.to_string()).or_insert(1);
                    *keyword_count += 1;
                }
            }
        }
    }
    let mut sorted_processes_freq = process_freq.iter().collect::<Vec<_>>();
    sorted_processes_freq.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let top_processes = sorted_processes_freq.iter().take(3).collect::<Vec<_>>();

    let mut sorted_host_name_freq = host_name_freq.iter().collect::<Vec<_>>();
    sorted_host_name_freq.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let top_hosts = sorted_host_name_freq.iter().take(3).collect::<Vec<_>>();

    let mut sorted_total_keyword_freq = most_freq_keywords.iter().collect::<Vec<_>>();
    sorted_total_keyword_freq.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let top_keywords = sorted_total_keyword_freq.iter().take(3).collect::<Vec<_>>();

    let summary = Summary::new(
        total_entries,
        top_processes.iter().map(|&&(name, &count)| (name.clone(), count as usize)).collect(),
        top_hosts.iter().map(|&&(name, &count)| (name.clone(), count as usize)).collect(),
        top_processes.first().map(|&&(name, _)| name.clone()).unwrap_or_default(),
        top_hosts.first().map(|&&(name, _)| name.clone()).unwrap_or_default(),
        top_keywords.iter().map(|&&(name, _)| massage_keyword(name)).collect(),
    );

    println!("{:?}", summary);

    Ok(())
}

fn massage_keyword(keyword: &str) -> String {
    keyword.to_lowercase().chars().filter(|c| *c != ':').collect()
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
        message_str,
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
        Ok((
            parts[0].into(),
            parts[1]
                .strip_suffix("]:")
                .get_or_insert_default()
                .to_string(),
        ))
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

fn stopwords() -> Vec<&'static str> {
    vec![
        "0",
        "=",
        "-",
        "able",
        "about",
        "above",
        "abroad",
        "according",
        "accordingly",
        "across",
        "actually",
        "adj",
        "after",
        "afterwards",
        "again",
        "against",
        "ago",
        "ahead",
        "ain't",
        "all",
        "allow",
        "allows",
        "almost",
        "alone",
        "along",
        "alongside",
        "already",
        "also",
        "although",
        "always",
        "am",
        "amid",
        "amidst",
        "among",
        "amongst",
        "an",
        "and",
        "another",
        "any",
        "anybody",
        "anyhow",
        "anyone",
        "anything",
        "anyway",
        "anyways",
        "anywhere",
        "apart",
        "appear",
        "appreciate",
        "appropriate",
        "are",
        "aren't",
        "around",
        "as",
        "a's",
        "aside",
        "ask",
        "asking",
        "associated",
        "at",
        "available",
        "away",
        "awfully",
        "back",
        "backward",
        "backwards",
        "be",
        "became",
        "because",
        "become",
        "becomes",
        "becoming",
        "been",
        "before",
        "beforehand",
        "begin",
        "behind",
        "being",
        "believe",
        "below",
        "beside",
        "besides",
        "best",
        "better",
        "between",
        "beyond",
        "both",
        "brief",
        "but",
        "by",
        "came",
        "can",
        "cannot",
        "cant",
        "can't",
        "caption",
        "cause",
        "causes",
        "certain",
        "certainly",
        "changes",
        "clearly",
        "c'mon",
        "co",
        "co.",
        "com",
        "come",
        "comes",
        "concerning",
        "consequently",
        "consider",
        "considering",
        "contain",
        "containing",
        "contains",
        "corresponding",
        "could",
        "couldn't",
        "course",
        "c's",
        "currently",
        "dare",
        "daren't",
        "definitely",
        "described",
        "despite",
        "did",
        "didn't",
        "different",
        "directly",
        "do",
        "does",
        "doesn't",
        "doing",
        "done",
        "don't",
        "down",
        "downwards",
        "during",
        "each",
        "edu",
        "eg",
        "eight",
        "eighty",
        "either",
        "else",
        "elsewhere",
        "end",
        "ending",
        "enough",
        "entirely",
        "especially",
        "et",
        "etc",
        "even",
        "ever",
        "evermore",
        "every",
        "everybody",
        "everyone",
        "everything",
        "everywhere",
        "ex",
        "exactly",
        "example",
        "except",
        "fairly",
        "far",
        "farther",
        "few",
        "fewer",
        "fifth",
        "first",
        "five",
        "followed",
        "following",
        "follows",
        "for",
        "forever",
        "former",
        "formerly",
        "forth",
        "forward",
        "found",
        "four",
        "from",
        "further",
        "furthermore",
        "get",
        "gets",
        "getting",
        "given",
        "gives",
        "go",
        "goes",
        "going",
        "gone",
        "got",
        "gotten",
        "greetings",
        "had",
        "hadn't",
        "half",
        "happens",
        "hardly",
        "has",
        "hasn't",
        "have",
        "haven't",
        "having",
        "he",
        "he'd",
        "he'll",
        "hello",
        "help",
        "hence",
        "her",
        "here",
        "hereafter",
        "hereby",
        "herein",
        "here's",
        "hereupon",
        "hers",
        "herself",
        "he's",
        "hi",
        "him",
        "himself",
        "his",
        "hither",
        "hopefully",
        "how",
        "howbeit",
        "however",
        "hundred",
        "i'd",
        "ie",
        "if",
        "ignored",
        "i'll",
        "i'm",
        "immediate",
        "in",
        "inasmuch",
        "inc",
        "inc.",
        "indeed",
        "indicate",
        "indicated",
        "indicates",
        "inner",
        "inside",
        "insofar",
        "instead",
        "into",
        "inward",
        "is",
        "isn't",
        "it",
        "it'd",
        "it'll",
        "its",
        "it's",
        "itself",
        "i've",
        "just",
        "k",
        "keep",
        "keeps",
        "kept",
        "know",
        "known",
        "knows",
        "last",
        "lately",
        "later",
        "latter",
        "latterly",
        "least",
        "less",
        "lest",
        "let",
        "let's",
        "like",
        "liked",
        "likely",
        "likewise",
        "little",
        "look",
        "looking",
        "looks",
        "low",
        "lower",
        "ltd",
        "made",
        "mainly",
        "make",
        "makes",
        "many",
        "may",
        "maybe",
        "mayn't",
        "me",
        "mean",
        "meantime",
        "meanwhile",
        "merely",
        "might",
        "mightn't",
        "mine",
        "minus",
        "miss",
        "more",
        "moreover",
        "most",
        "mostly",
        "mr",
        "mrs",
        "much",
        "must",
        "mustn't",
        "my",
        "myself",
        "name",
        "namely",
        "nd",
        "near",
        "nearly",
        "necessary",
        "need",
        "needn't",
        "needs",
        "neither",
        "never",
        "neverf",
        "neverless",
        "nevertheless",
        "new",
        "next",
        "nine",
        "ninety",
        "no",
        "nobody",
        "non",
        "none",
        "nonetheless",
        "noone",
        "no-one",
        "nor",
        "normally",
        "not",
        "nothing",
        "notwithstanding",
        "novel",
        "now",
        "nowhere",
        "obviously",
        "of",
        "off",
        "often",
        "oh",
        "ok",
        "okay",
        "old",
        "on",
        "once",
        "one",
        "ones",
        "one's",
        "only",
        "onto",
        "opposite",
        "or",
        "other",
        "others",
        "otherwise",
        "ought",
        "oughtn't",
        "our",
        "ours",
        "ourselves",
        "out",
        "outside",
        "over",
        "overall",
        "own",
        "particular",
        "particularly",
        "past",
        "per",
        "perhaps",
        "placed",
        "please",
        "plus",
        "possible",
        "presumably",
        "probably",
        "provided",
        "provides",
        "que",
        "quite",
        "qv",
        "rather",
        "rd",
        "re",
        "really",
        "reasonably",
        "recent",
        "recently",
        "regarding",
        "regardless",
        "regards",
        "relatively",
        "respectively",
        "right",
        "round",
        "said",
        "same",
        "saw",
        "say",
        "saying",
        "says",
        "second",
        "secondly",
        "see",
        "seeing",
        "seem",
        "seemed",
        "seeming",
        "seems",
        "seen",
        "self",
        "selves",
        "sensible",
        "sent",
        "serious",
        "seriously",
        "seven",
        "several",
        "shall",
        "shan't",
        "she",
        "she'd",
        "she'll",
        "she's",
        "should",
        "shouldn't",
        "since",
        "six",
        "so",
        "some",
        "somebody",
        "someday",
        "somehow",
        "someone",
        "something",
        "sometime",
        "sometimes",
        "somewhat",
        "somewhere",
        "soon",
        "sorry",
        "specified",
        "specify",
        "specifying",
        "still",
        "sub",
        "such",
        "sup",
        "sure",
        "take",
        "taken",
        "taking",
        "tell",
        "tends",
        "th",
        "than",
        "thank",
        "thanks",
        "thanx",
        "that",
        "that'll",
        "thats",
        "that's",
        "that've",
        "the",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "thence",
        "there",
        "thereafter",
        "thereby",
        "there'd",
        "therefore",
        "therein",
        "there'll",
        "there're",
        "theres",
        "there's",
        "thereupon",
        "there've",
        "these",
        "they",
        "they'd",
        "they'll",
        "they're",
        "they've",
        "thing",
        "things",
        "think",
        "third",
        "thirty",
        "this",
        "thorough",
        "thoroughly",
        "those",
        "though",
        "three",
        "through",
        "throughout",
        "thru",
        "thus",
        "till",
        "to",
        "together",
        "too",
        "took",
        "toward",
        "towards",
        "tried",
        "tries",
        "truly",
        "try",
        "trying",
        "t's",
        "twice",
        "two",
        "un",
        "under",
        "underneath",
        "undoing",
        "unfortunately",
        "unless",
        "unlike",
        "unlikely",
        "until",
        "unto",
        "up",
        "upon",
        "upwards",
        "us",
        "use",
        "used",
        "useful",
        "uses",
        "using",
        "usually",
        "v",
        "value",
        "various",
        "versus",
        "very",
        "via",
        "viz",
        "vs",
        "want",
        "wants",
        "was",
        "wasn't",
        "way",
        "we",
        "we'd",
        "welcome",
        "well",
        "we'll",
        "went",
        "were",
        "we're",
        "weren't",
        "we've",
        "what",
        "whatever",
        "what'll",
        "what's",
        "what've",
        "when",
        "whence",
        "whenever",
        "where",
        "whereafter",
        "whereas",
        "whereby",
        "wherein",
        "where's",
        "whereupon",
        "wherever",
        "whether",
        "which",
        "whichever",
        "while",
        "whilst",
        "whither",
        "who",
        "who'd",
        "whoever",
        "whole",
        "who'll",
        "whom",
        "whomever",
        "who's",
        "whose",
        "why",
        "will",
        "willing",
        "wish",
        "with",
        "within",
        "without",
        "wonder",
        "won't",
        "would",
        "wouldn't",
        "yes",
        "yet",
        "you",
        "you'd",
        "you'll",
        "your",
        "you're",
        "yours",
        "yourself",
        "yourselves",
        "you've",
        "zero",
        "a",
        "how's",
        "i",
        "when's",
        "why's",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "j",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "uucp",
        "w",
        "x",
        "y",
        "z",
        "I",
        "www",
        "amount",
        "bill",
        "bottom",
        "call",
        "computer",
        "con",
        "couldnt",
        "cry",
        "de",
        "describe",
        "detail",
        "due",
        "eleven",
        "empty",
        "fifteen",
        "fifty",
        "fill",
        "find",
        "fire",
        "forty",
        "front",
        "full",
        "give",
        "hasnt",
        "herse",
        "himse",
        "interest",
        "itse”",
        "mill",
        "move",
        "myse”",
        "part",
        "put",
        "show",
        "side",
        "sincere",
        "sixty",
        "system",
        "ten",
        "thick",
        "thin",
        "top",
        "twelve",
        "twenty",
        "abst",
        "accordance",
        "act",
        "added",
        "adopted",
        "affected",
        "affecting",
        "affects",
        "ah",
        "announce",
        "anymore",
        "apparently",
        "approximately",
        "aren",
        "arent",
        "arise",
        "auth",
        "beginning",
        "beginnings",
        "begins",
        "biol",
        "briefly",
        "ca",
        "date",
        "ed",
        "effect",
        "et-al",
        "ff",
        "fix",
        "gave",
        "giving",
        "heres",
        "hes",
        "hid",
        "home",
        "id",
        "im",
        "immediately",
        "importance",
        "important",
        "index",
        "information",
        "invention",
        "itd",
        "keys",
        "kg",
        "km",
        "largely",
        "lets",
        "line",
        "'ll",
        "means",
        "mg",
        "million",
        "ml",
        "mug",
        "na",
        "nay",
        "necessarily",
        "nos",
        "noted",
        "obtain",
        "obtained",
        "omitted",
        "ord",
        "owing",
        "page",
        "pages",
        "poorly",
        "possibly",
        "potentially",
        "pp",
        "predominantly",
        "present",
        "previously",
        "primarily",
        "promptly",
        "proud",
        "quickly",
        "ran",
        "readily",
        "ref",
        "refs",
        "related",
        "research",
        "resulted",
        "resulting",
        "results",
        "run",
        "sec",
        "section",
        "shed",
        "shes",
        "showed",
        "shown",
        "showns",
        "shows",
        "significant",
        "significantly",
        "similar",
        "similarly",
        "slightly",
        "somethan",
        "specifically",
        "state",
        "states",
        "stop",
        "strongly",
        "substantially",
        "successfully",
        "sufficiently",
        "suggest",
        "thered",
        "thereof",
        "therere",
        "thereto",
        "theyd",
        "theyre",
        "thou",
        "thoughh",
        "thousand",
        "throug",
        "til",
        "tip",
        "ts",
        "ups",
        "usefully",
        "usefulness",
        "'ve",
        "vol",
        "vols",
        "wed",
        "whats",
        "wheres",
        "whim",
        "whod",
        "whos",
        "widely",
        "words",
        "world",
        "youd",
        "youre",
    ]
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
        assert_eq!(
            parse_process_name_and_pid("com.apple.CDScheduler[43]:").unwrap(),
            ("com.apple.CDScheduler".to_string(), "43".to_string())
        );
    }

    #[test]
    fn parse_a_valid_line() {
        let line = "Jul  1 09:01:05 calvisitor-10-105-160-95 com.apple.CDScheduler[43]: Thermal pressure state: 1 Memory pressure state: 0";
        let (month, day, time, hostname, process, pid, message) = parse_record(line).unwrap();
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
        let (month, day, time, hostname, process, pid, message) = parse_record(line).unwrap();
        assert_eq!(month, "Jul");
        assert_eq!(day, "8");
        assert_eq!(time, "06:11:46");
        assert_eq!(hostname, "calvisitor-10-105-162-124");
        assert_eq!(process, "WindowServer");
        assert_eq!(pid, "184");
        assert_eq!(
            message,
            "send_datagram_available_ping: pid 445 failed to act on a ping it dequeued before timing out."
        );
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
