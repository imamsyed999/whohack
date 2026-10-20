//! Finds the script file an interpreter process is executing, so a
//! downloaded script taints the interpreter running it.

use std::path::{Path, PathBuf};

/// Splits a command line into arguments, honoring double quotes and
/// backslash-escaped quotes (good enough for both POSIX-joined and Windows
/// command lines; exact Windows rules only matter for edge cases).
pub fn split_cmdline(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
                has_token = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// POSIX shells: first non-option argument; `-c` means inline code.
    Shell,
    /// Other scripting runtimes: first non-option argument.
    Generic,
    PowerShell,
    WindowsHost,
    Cmd,
    Java,
}

fn interpreter_kind(exe: &str) -> Option<Kind> {
    let base = exe
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(exe)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    // python3.12, perl5.36, etc.
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match stem {
        "bash" | "sh" | "dash" | "zsh" | "ksh" | "fish" => Some(Kind::Shell),
        "python" | "pythonw" | "perl" | "ruby" | "node" | "nodejs" | "php" | "osascript"
        | "lua" | "tclsh" => Some(Kind::Generic),
        "powershell" | "pwsh" | "powershell_ise" => Some(Kind::PowerShell),
        "wscript" | "cscript" | "mshta" => Some(Kind::WindowsHost),
        "cmd" => Some(Kind::Cmd),
        "java" | "javaw" => Some(Kind::Java),
        _ => None,
    }
}

/// Whether `exe` is a script interpreter (used for tagging as well).
pub fn is_interpreter(exe: &str) -> bool {
    interpreter_kind(exe).is_some()
}

/// Runtime options that take a value (the value is not the script).
const VALUE_OPTS: &[&str] = &["-W", "-X", "-I", "-r", "--require"];
/// Runtime options after which there is no script file (inline code / module).
const INLINE_OPTS: &[&str] = &["-c", "-m", "-e", "--eval", "-p", "--print"];
/// Shell options that take a value.
const SHELL_VALUE_OPTS: &[&str] = &["-o", "+o", "-O", "+O"];

/// First non-option argument, skipping options that take a value and
/// stopping at options that introduce inline code.
fn first_operand(args: &[String], inline: &[&str], with_value: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if inline.contains(&a) {
            return None;
        }
        if with_value.contains(&a) {
            i += 2;
            continue;
        }
        if a == "--" {
            return args.get(i + 1).cloned();
        }
        if !a.starts_with('-') && !a.starts_with('+') {
            return Some(a.to_string());
        }
        i += 1;
    }
    None
}

fn candidate(args: &[String], kind: Kind) -> Option<String> {
    match kind {
        Kind::Shell => return first_operand(args, &["-c"], SHELL_VALUE_OPTS),
        Kind::Generic => return first_operand(args, INLINE_OPTS, VALUE_OPTS),
        _ => {}
    }
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match kind {
            Kind::PowerShell => {
                let l = a.to_ascii_lowercase();
                if l == "-file" || l == "-f" {
                    return args.get(i + 1).cloned();
                }
                if l.starts_with("-command")
                    || l.starts_with("-encodedcommand")
                    || l == "-c"
                    || l == "-ec"
                {
                    return None;
                }
                if !a.starts_with('-') && !a.starts_with('/') {
                    return Some(a.clone());
                }
            }
            Kind::Cmd => {
                let l = a.to_ascii_lowercase();
                if l == "/c" || l == "/k" {
                    return args.get(i + 1).cloned();
                }
            }
            Kind::WindowsHost => {
                if !a.starts_with("//") && !a.starts_with('/') && !a.starts_with('-') {
                    return Some(a.clone());
                }
            }
            Kind::Java => {
                if a == "-jar" {
                    return args.get(i + 1).cloned();
                }
            }
            // Handled by `first_operand` above.
            Kind::Shell | Kind::Generic => return None,
        }
        i += 1;
    }
    None
}

/// Returns the script path an interpreter is running, if it names an
/// existing file. Relative paths are resolved against `cwd` when known.
pub fn script_target(exe: &str, cmdline: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let kind = interpreter_kind(exe)?;
    let args = split_cmdline(cmdline);
    let cand = candidate(args.get(1..)?, kind)?;
    let p = PathBuf::from(cand.trim_matches('"'));
    let resolved = if p.is_absolute() { p } else { cwd?.join(p) };
    resolved.is_file().then_some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting() {
        assert_eq!(split_cmdline(r#"a "b c" d"#), vec!["a", "b c", "d"]);
        assert_eq!(split_cmdline(r#"x "say \"hi\"""#), vec!["x", r#"say "hi""#]);
        assert_eq!(split_cmdline("  a   b "), vec!["a", "b"]);
        assert_eq!(split_cmdline(r#"a """#), vec!["a", ""]);
        assert!(split_cmdline("").is_empty());
    }

    fn cand(exe: &str, cmd: &str) -> Option<String> {
        let args = split_cmdline(cmd);
        candidate(&args[1..], interpreter_kind(exe)?)
    }

    #[test]
    fn candidates_per_interpreter() {
        assert_eq!(
            cand("/bin/bash", "/bin/bash /home/a/Downloads/x.sh arg").as_deref(),
            Some("/home/a/Downloads/x.sh")
        );
        assert_eq!(
            cand("/bin/sh", "sh -e ./run.sh").as_deref(),
            Some("./run.sh")
        );
        assert_eq!(cand("/bin/bash", "bash -c 'echo hi'"), None);
        assert_eq!(cand("/usr/bin/python3.12", "python3 -m http.server"), None);
        assert_eq!(
            cand("/usr/bin/python3.12", "python3 -W ignore tool.py").as_deref(),
            Some("tool.py")
        );
        assert_eq!(
            cand(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r#"powershell.exe -NoProfile -File "C:\Users\a\Downloads\x.ps1""#
            )
            .as_deref(),
            Some(r"C:\Users\a\Downloads\x.ps1")
        );
        assert_eq!(cand("powershell.exe", "powershell -Command Get-Date"), None);
        assert_eq!(
            cand("powershell.exe", "powershell -EncodedCommand AAAA"),
            None
        );
        assert_eq!(
            cand(
                "wscript.exe",
                r#"wscript.exe //B "C:\Users\a\Downloads\x.js""#
            )
            .as_deref(),
            Some(r"C:\Users\a\Downloads\x.js")
        );
        assert_eq!(
            cand("mshta.exe", r"mshta.exe C:\x\a.hta").as_deref(),
            Some(r"C:\x\a.hta")
        );
        assert_eq!(
            cand("cmd.exe", r#"cmd.exe /c "C:\x\run.bat""#).as_deref(),
            Some(r"C:\x\run.bat")
        );
        assert_eq!(
            cand("java", "java -Xmx1g -jar app.jar").as_deref(),
            Some("app.jar")
        );
        assert_eq!(
            cand("/usr/bin/curl", "curl http://x"),
            None,
            "not an interpreter"
        );
    }

    #[test]
    fn target_must_exist_and_relative_needs_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("run.sh");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        let cmd = format!("/bin/sh {}", script.display());
        assert_eq!(script_target("/bin/sh", &cmd, None), Some(script.clone()));
        assert_eq!(
            script_target("/bin/sh", "/bin/sh run.sh", Some(dir.path())),
            Some(dir.path().join("run.sh"))
        );
        assert_eq!(script_target("/bin/sh", "/bin/sh run.sh", None), None);
        assert_eq!(
            script_target("/bin/sh", "/bin/sh /no/such/file.sh", None),
            None
        );
        assert!(is_interpreter("/usr/bin/python3"));
        assert!(!is_interpreter("/usr/bin/firefox"));
    }
}
