use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Deserializer};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use url::Url;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use base64::Engine;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Convert Bugzilla bugs to Markdown summaries")]
struct Args {
    /// Bug number or full Bugzilla URL
    input: String,

    /// Bugzilla instance URL (defaults to Mozilla's)
    #[clap(short, long, default_value = "https://bugzilla.mozilla.org")]
    instance: String,

    /// Output directory for markdown file and attachments (default: current directory)
    #[clap(short, long)]
    output_dir: Option<PathBuf>,

    /// Download attachments to output directory
    #[clap(short = 'a', long)]
    download_attachments: bool,

    /// Print differential revisions (Dxxxx) from Phabricator
    #[clap(short = 'd', long)]
    print_diffs: bool,
}

#[derive(Debug, Deserialize)]
struct Comment {
    #[allow(dead_code)]
    id: u64,
    #[allow(dead_code)]
    bug_id: u64,
    count: u64,
    creator: String,
    #[allow(dead_code)]
    time: String,
    creation_time: String,
    is_private: bool,
    text: String,
    attachment_id: Option<u64>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CommentResponse {
    bugs: std::collections::HashMap<String, BugComments>,
}

#[derive(Debug, Deserialize)]
struct BugComments {
    comments: Vec<Comment>,
}

#[derive(Debug, Deserialize)]
struct Bug {
    id: u64,
    summary: String,
    status: String,
    resolution: Option<String>,
    severity: Option<String>,
    priority: Option<String>,
    product: String,
    component: String,
    assigned_to: String,
    creator: String,
    creation_time: String,
    last_change_time: String,
    keywords: Vec<String>,
    whiteboard: Option<String>,
    blocks: Option<Vec<u64>>,
    depends_on: Option<Vec<u64>>,
    see_also: Option<Vec<String>>,
    target_milestone: Option<String>,
    url: Option<String>,
    groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct BugzillaResponse {
    bugs: Vec<Bug>,
}

#[derive(Debug, Deserialize)]
struct Attachment {
    id: u64,
    #[allow(dead_code)]
    bug_id: u64,
    file_name: String,
    #[allow(dead_code)]
    summary: String,
    content_type: String,
    size: u64,
    #[allow(dead_code)]
    creator: String,
    #[allow(dead_code)]
    creation_time: String,
    #[allow(dead_code)]
    last_change_time: String,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    #[allow(dead_code)]
    is_private: bool,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    is_obsolete: bool,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    #[allow(dead_code)]
    is_patch: bool,
}

#[derive(Debug, Deserialize)]
struct AttachmentResponse {
    bugs: std::collections::HashMap<String, Vec<Attachment>>,
}

#[derive(Debug, Deserialize)]
struct Config {
    output_dir: Option<PathBuf>,
    api_key: Option<String>,
}

#[derive(Debug)]
struct DownloadSummary {
    file_name: String,
    size: u64,
    mime_type: String,
    decompressed: bool,
}

fn deserialize_bool_from_anything<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Bool(b) => Ok(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i != 0)
            } else {
                Err(D::Error::custom("Invalid number for boolean"))
            }
        }
        serde_json::Value::String(s) => match s.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(D::Error::custom("Invalid string for boolean")),
        },
        _ => Err(D::Error::custom("Invalid type for boolean")),
    }
}

fn read_api_key() -> Option<String> {
    if let Ok(env_key) = std::env::var("BMO_API_KEY") {
        if !env_key.is_empty() {
            return Some(env_key);
        }
    }
    
    if let Ok(config) = read_config() {
        if let Some(config_key) = config.api_key {
            if !config_key.is_empty() {
                return Some(config_key);
            }
        }
    }
    
    let api_key_path = Path::new(".bmo-api-key");
    if api_key_path.exists() {
        fs::read_to_string(api_key_path)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

fn read_config() -> Result<Config> {
    let config_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bmo-to-md")
        .join("config.toml");

    if config_path.exists() {
        let config_content =
            fs::read_to_string(&config_path).context("Failed to read config file")?;
        let config: Config =
            toml::from_str(&config_content).context("Failed to parse config file")?;
        Ok(config)
    } else {
        Ok(Config { 
            output_dir: None,
            api_key: None,
        })
    }
}

fn get_output_dir(args: &Args) -> Result<PathBuf> {
    if let Some(dir) = &args.output_dir {
        return Ok(dir.clone());
    }

    if let Ok(env_dir) = std::env::var("BMO_OUTPUT_DIR") {
        return Ok(PathBuf::from(env_dir));
    }

    let config = read_config()?;
    if let Some(dir) = config.output_dir {
        return Ok(dir);
    }

    Ok(PathBuf::from("."))
}

fn parse_bug_input(input: &str, instance: &str) -> Result<(String, u64)> {
    if let Ok(url) = Url::parse(input) {
        if let Some(query) = url.query() {
            for pair in query.split('&') {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 && parts[0] == "id" {
                    if let Ok(bug_id) = parts[1].parse::<u64>() {
                        return Ok((url.origin().ascii_serialization(), bug_id));
                    }
                }
            }
        }
    }

    if let Ok(bug_id) = input.parse::<u64>() {
        return Ok((instance.to_string(), bug_id));
    }

    anyhow::bail!("Invalid input: expected bug number or Bugzilla URL")
}

async fn fetch_comments(instance: &str, bug_id: u64) -> Result<Vec<Comment>> {
    let mut url = format!("{}/rest/bug/{}/comment", instance, bug_id);

    if let Some(api_key) = read_api_key() {
        url.push_str(&format!("?api_key={}", api_key));
    }

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .context("Failed to send request for comments to Bugzilla")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Bugzilla returned error for comments: {}",
            response.status()
        );
    }

    let comment_response: CommentResponse = response
        .json()
        .await
        .context("Failed to parse Bugzilla comment response")?;

    Ok(comment_response
        .bugs
        .into_iter()
        .next()
        .map(|(_, bug_comments)| bug_comments.comments)
        .unwrap_or_default())
}

async fn fetch_bug(instance: &str, bug_id: u64) -> Result<Bug> {
    let mut url = format!("{}/rest/bug/{}", instance, bug_id);

    if let Some(api_key) = read_api_key() {
        url.push_str(&format!("?api_key={}", api_key));
    }

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .context("Failed to send request to Bugzilla")?;

    if !response.status().is_success() {
        anyhow::bail!("Bugzilla returned error: {}", response.status());
    }

    let bugzilla_response: BugzillaResponse = response
        .json()
        .await
        .context("Failed to parse Bugzilla response")?;

    bugzilla_response
        .bugs
        .into_iter()
        .next()
        .context("No bug found with the given ID")
}

async fn fetch_attachments(instance: &str, bug_id: u64) -> Result<Vec<Attachment>> {
    let mut url = format!("{}/rest/bug/{}/attachment", instance, bug_id);

    if let Some(api_key) = read_api_key() {
        url.push_str(&format!("?api_key={}", api_key));
    }

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .context("Failed to send request for attachments to Bugzilla")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Bugzilla returned error for attachments: {}",
            response.status()
        );
    }

    let attachment_response: AttachmentResponse = response
        .json()
        .await
        .context("Failed to parse Bugzilla attachment response")?;

    Ok(attachment_response
        .bugs
        .into_iter()
        .next()
        .map(|(_, attachments)| attachments)
        .unwrap_or_default())
}

fn bug_to_markdown_with_diffs(bug: &Bug, comments: &[Comment], instance: &str, diffs: &[String]) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Bug {} - {}\n\n", bug.id, bug.summary));

    md.push_str(&format!(
        "**URL:** {}/show_bug.cgi?id={}\n\n",
        instance, bug.id
    ));

    if !diffs.is_empty() {
        md.push_str("## Differential Revisions\n\n");
        for diff in diffs {
            md.push_str(&format!("- {}\n", diff));
        }
        md.push_str("\n");
    }

    md.push_str("## Metadata\n\n");
    md.push_str(&format!("- **Status:** {}\n", bug.status));

    if let Some(resolution) = &bug.resolution {
        if !resolution.is_empty() {
            md.push_str(&format!("- **Resolution:** {}\n", resolution));
        }
    }

    if let Some(severity) = &bug.severity {
        md.push_str(&format!("- **Severity:** {}\n", severity));
    }

    if let Some(priority) = &bug.priority {
        md.push_str(&format!("- **Priority:** {}\n", priority));
    }

    md.push_str(&format!("- **Product:** {}\n", bug.product));
    md.push_str(&format!("- **Component:** {}\n", bug.component));
    md.push_str(&format!("- **Assignee:** {}\n", bug.assigned_to));
    md.push_str(&format!("- **Reporter:** {}\n", bug.creator));
    md.push_str(&format!("- **Created:** {}\n", bug.creation_time));
    md.push_str(&format!("- **Last Modified:** {}\n", bug.last_change_time));

    if let Some(target_milestone) = &bug.target_milestone {
        if !target_milestone.is_empty() && target_milestone != "---" {
            md.push_str(&format!("- **Target Milestone:** {}\n", target_milestone));
        }
    }

    if let Some(url) = &bug.url {
        if !url.is_empty() {
            md.push_str(&format!("- **URL Field:** {}\n", url));
        }
    }

    md.push('\n');

    if !bug.keywords.is_empty() {
        md.push_str("## Keywords\n\n");
        md.push_str(&bug.keywords.join(", "));
        md.push_str("\n\n");
    }

    if let Some(whiteboard) = &bug.whiteboard {
        if !whiteboard.is_empty() {
            md.push_str("## Whiteboard\n\n");
            md.push_str(whiteboard);
            md.push_str("\n\n");
        }
    }

    let mut has_dependencies = false;

    if let Some(blocks) = &bug.blocks {
        if !blocks.is_empty() {
            if !has_dependencies {
                md.push_str("## Dependencies\n\n");
                has_dependencies = true;
            }
            md.push_str("**Blocks:**\n");
            for block_id in blocks {
                md.push_str(&format!("- Bug {}\n", block_id));
            }
            md.push('\n');
        }
    }

    if let Some(depends_on) = &bug.depends_on {
        if !depends_on.is_empty() {
            if !has_dependencies {
                md.push_str("## Dependencies\n\n");
            }
            md.push_str("**Depends on:**\n");
            for dep_id in depends_on {
                md.push_str(&format!("- Bug {}\n", dep_id));
            }
            md.push('\n');
        }
    }

    if let Some(see_also) = &bug.see_also {
        if !see_also.is_empty() {
            md.push_str("## See Also\n\n");
            for link in see_also {
                md.push_str(&format!("- {}\n", link));
            }
            md.push('\n');
        }
    }

    if let Some(groups) = &bug.groups {
        if !groups.is_empty() {
            md.push_str("## Security Groups\n\n");
            for group in groups {
                md.push_str(&format!("- {}\n", group));
            }
            md.push('\n');
        }
    }

    if !comments.is_empty() {
        md.push_str("## Comments\n\n");
        for comment in comments {
            md.push_str(&format!(
                "### Comment {} by {} on {}\n\n",
                comment.count, comment.creator, comment.creation_time
            ));

            if comment.is_private {
                md.push_str("**[Private Comment]**\n\n");
            }

            if let Some(attachment_id) = comment.attachment_id {
                md.push_str(&format!("**[Attachment #{}]**\n\n", attachment_id));
            }

            let text = comment
                .text
                .lines()
                .map(|line| {
                    if line.starts_with("> ") {
                        line.to_string()
                    } else if line.starts_with("(In reply to") && line.ends_with(")") {
                        format!("*{}*", line)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");

            md.push_str(&text);
            md.push_str("\n\n");

            if let Some(tags) = &comment.tags {
                if !tags.is_empty() {
                    md.push_str(&format!("**Tags:** {}\n\n", tags.join(", ")));
                }
            }

            md.push_str("---\n\n");
        }
    }

    md
}

async fn download_attachment(
    instance: &str,
    attachment: &Attachment,
    output_dir: &Path,
) -> Result<DownloadSummary> {
    let mut url = format!("{}/rest/bug/attachment/{}", instance, attachment.id);

    if let Some(api_key) = read_api_key() {
        url.push_str(&format!("?api_key={}", api_key));
    }
    // Ask for the data field, which is base64-encoded
    if url.contains('?') {
        url.push_str("&include_fields=data");
    } else {
        url.push_str("?include_fields=data");
    }

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .context("Failed to download attachment")?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download attachment: {}", response.status());
    }

    let total_size = response.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_message(format!("Downloading {}", attachment.file_name));

    // If Bugzilla returns JSON, extract and decode base64 data; otherwise stream bytes.
    let ct = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Prefer metadata content-type for naming; otherwise fall back to response header
    let effective_mime = if !attachment.content_type.is_empty() {
        attachment.content_type.to_ascii_lowercase()
    } else if !ct.is_empty() {
        ct.clone()
    } else {
        String::new()
    };

    let saved_name = sanitize_filename_for_mime(&attachment.file_name, &effective_mime);
    let file_path = output_dir.join(&saved_name);

    if ct.contains("application/json") {
        let body_bytes = response.bytes().await?;
        pb.set_position(body_bytes.len() as u64);

        #[derive(Deserialize)]
        struct AttachmentDataEntry {
            #[allow(dead_code)]
            id: Option<u64>,
            data: Option<String>,
            #[allow(dead_code)]
            file_name: Option<String>,
            #[allow(dead_code)]
            content_type: Option<String>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum AttachmentDataResponse {
            Vec { attachments: Vec<AttachmentDataEntry> },
            Map { attachments: std::collections::HashMap<String, AttachmentDataEntry> },
        }

        let parsed: AttachmentDataResponse = serde_json::from_slice(&body_bytes)
            .context("Failed to parse attachment JSON (data)")?;
        let entry_opt = match parsed {
            AttachmentDataResponse::Vec { mut attachments } => attachments.pop(),
            AttachmentDataResponse::Map { attachments } => attachments.into_values().next(),
        };
        let entry = entry_opt.context("Missing attachment data in response")?;
        let b64 = entry.data.context("No data field found in attachment response")?;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .context("Failed to base64-decode attachment data")?;
        tokio::fs::write(&file_path, &decoded).await?;

        pb.finish_with_message(format!("Downloaded {}", attachment.file_name));
    } else {
        let mut file = File::create(&file_path).await?;
        let mut stream = response.bytes_stream();
        let mut downloaded = 0u64;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            pb.set_position(downloaded);
        }

        pb.finish_with_message(format!("Downloaded {}", attachment.file_name));
    }

    // Try to decompress based on extension and magic bytes for direct usability
    let decompressed = decompress_file(&file_path).await?;

    Ok(DownloadSummary {
        file_name: saved_name,
        size: attachment.size,
        mime_type: attachment.content_type.clone(),
        decompressed,
    })
}

async fn decompress_file(file_path: &Path) -> Result<bool> {
    let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if file_name.ends_with(".zst") || file_name.ends_with(".zstd") {
        decompress_zstd(file_path).await?;
        return Ok(true);
    } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        decompress_tar_gz(file_path).await?;
        return Ok(true);
    } else if file_name.ends_with(".gz") {
        decompress_gzip(file_path).await?;
        return Ok(true);
    } else if file_name.ends_with(".zip") {
        decompress_zip(file_path).await?;
        return Ok(true);
    }

    // Fallback: check magic bytes if no clear extension
    if detect_and_decompress_by_magic(file_path).await? {
        return Ok(true);
    }

    Ok(false)
}

async fn decompress_gzip(file_path: &Path) -> Result<()> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let file = std::fs::File::open(file_path)?;
    let mut decoder = GzDecoder::new(file);
    let mut contents = Vec::new();
    decoder.read_to_end(&mut contents)?;

    let output_path = file_path.with_extension("");
    tokio::fs::write(&output_path, contents).await?;

    Ok(())
}

async fn decompress_tar_gz(file_path: &Path) -> Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = std::fs::File::open(file_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let extract_dir = file_path.parent().unwrap();
    archive.unpack(extract_dir)?;

    Ok(())
}

async fn decompress_zip(file_path: &Path) -> Result<()> {
    use std::io::Read;

    let file = std::fs::File::open(file_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let extract_dir = file_path.parent().unwrap();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = extract_dir.join(file.name());

        if file.is_dir() {
            tokio::fs::create_dir_all(&outpath).await?;
        } else {
            if let Some(parent) = outpath.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut outfile = tokio::fs::File::create(&outpath).await?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;
            outfile.write_all(&contents).await?;
        }
    }

    Ok(())
}

async fn decompress_zstd(file_path: &Path) -> Result<()> {
    let file_contents = tokio::fs::read(file_path).await?;
    let decompressed = zstd::decode_all(&file_contents[..])?;

    let output_path = file_path.with_extension("");
    tokio::fs::write(&output_path, decompressed).await?;

    Ok(())
}

async fn detect_and_decompress_by_magic(file_path: &Path) -> Result<bool> {
    use tokio::io::AsyncReadExt;

    let mut f = tokio::fs::File::open(file_path).await?;
    let mut header = [0u8; 4];
    let n = f.read(&mut header).await?;
    if n < 2 {
        return Ok(false);
    }

    // gzip magic: 1F 8B
    if header[0] == 0x1F && header[1] == 0x8B {
        decompress_gzip(file_path).await?;
        return Ok(true);
    }
    // zstd magic: 28 B5 2F FD
    if n >= 4 && header == [0x28, 0xB5, 0x2F, 0xFD] {
        decompress_zstd(file_path).await?;
        return Ok(true);
    }
    // zip magic: PK\x03\x04, PK\x05\x06, PK\x07\x08
    if n >= 4 && ((&header == b"PK\x03\x04") || (&header == b"PK\x05\x06") || (&header == b"PK\x07\x08")) {
        decompress_zip(file_path).await?;
        return Ok(true);
    }

    Ok(false)
}

fn is_phabricator_link(attachment: &Attachment) -> bool {
    attachment.content_type == "text/x-phabricator-request"
}

fn extract_differential_revision(attachment: &Attachment) -> Option<String> {
    if !is_phabricator_link(attachment) {
        return None;
    }

    if let Some(caps) = attachment.file_name
        .strip_prefix("phabricator-D")
        .and_then(|s| s.split('-').next())
    {
        return Some(format!("D{}", caps));
    }

    if attachment.summary.starts_with("Bug ") {
        if let Some(d_idx) = attachment.summary.find(" - D") {
            let after_d = &attachment.summary[d_idx + 4..];
            if let Some(end) = after_d.find(|c: char| !c.is_ascii_digit()) {
                return Some(format!("D{}", &after_d[..end]));
            } else {
                return Some(format!("D{}", after_d));
            }
        }
    }

    None
}

fn sanitize_filename_for_mime(original: &str, mime: &str) -> String {
    // Ensure we only keep a filename (no directories or absolute paths)
    let mut safe_name = std::path::Path::new(original)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment")
        .to_string();

    // Basic sanitization: replace path separators and control characters
    safe_name = safe_name
        .chars()
        .map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c })
        .collect();

    let lower_mime = mime.to_ascii_lowercase();
    if lower_mime.starts_with("text/html") {
        let name = safe_name;
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".html") {
            let mut base = name[..name.len()-5].to_string();
            let mut lowered = base.to_ascii_lowercase();
            let suffixes = [".zip", ".gz", ".zst", ".tgz", ".tar", ".tar.gz"];
            let mut changed = true;
            while changed {
                changed = false;
                for suf in &suffixes {
                    if lowered.ends_with(suf) {
                        let new_len = base.len() - suf.len();
                        base.truncate(new_len);
                        lowered.truncate(new_len);
                        changed = true;
                    }
                }
            }
            if base.is_empty() { base = "attachment".to_string(); }
            return format!("{}.html", base);
        }
        let mut base = name.to_string();
        let mut lowered = base.to_ascii_lowercase();
        let suffixes = [".zip", ".gz", ".zst", ".tgz", ".tar", ".tar.gz"];
        let mut changed = true;
        while changed {
            changed = false;
            for suf in &suffixes {
                if lowered.ends_with(suf) {
                    let new_len = base.len() - suf.len();
                    base.truncate(new_len);
                    lowered.truncate(new_len);
                    changed = true;
                }
            }
        }
        if base.is_empty() { base = "attachment".to_string(); }
        return format!("{}.html", base);
    }
    safe_name
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (instance, bug_id) = parse_bug_input(&args.input, &args.instance)?;

    let bug = fetch_bug(&instance, bug_id).await?;
    let comments = fetch_comments(&instance, bug_id).await?;

    // Fetch differential revisions if needed
    let diffs = if args.print_diffs || args.output_dir.is_some() || args.download_attachments {
        let attachments = fetch_attachments(&instance, bug_id).await?;
        attachments
            .iter()
            .filter_map(extract_differential_revision)
            .collect()
    } else {
        Vec::new()
    };

    // Handle printing differential revisions
    if args.print_diffs {
        if !diffs.is_empty() {
            println!("Differential Revisions:");
            for diff in &diffs {
                println!("  {}", diff);
            }
            println!();
        } else {
            println!("No differential revisions found.");
            println!();
        }

        // If only printing diffs (not saving markdown), exit here
        if args.output_dir.is_none() && !args.download_attachments {
            return Ok(());
        }
    }

    let markdown = bug_to_markdown_with_diffs(&bug, &comments, &instance, &diffs);

    if args.output_dir.is_some() || args.download_attachments {
        let base_output_dir = get_output_dir(&args)?;
        let bug_dir = base_output_dir.join(format!("bmo-{}", bug_id));

        tokio::fs::create_dir_all(&bug_dir)
            .await
            .context("Failed to create output directory")?;

        let md_file = bug_dir.join(format!("bmo-{:06}-summary.md", bug_id));
        tokio::fs::write(&md_file, &markdown)
            .await
            .context("Failed to write markdown file")?;

        println!("Markdown written to: {}", md_file.display());

        if args.download_attachments {
            let attachments = fetch_attachments(&instance, bug_id).await?;

            if !attachments.is_empty() {
                let downloadable_count = attachments
                    .iter()
                    .filter(|a| !a.is_obsolete && !is_phabricator_link(a))
                    .count();

                if downloadable_count > 0 {
                    println!("\nDownloading {} attachments...", downloadable_count);
                }

                let mut summaries = Vec::new();
                for attachment in attachments {
                    if !attachment.is_obsolete && !is_phabricator_link(&attachment) {
                        match download_attachment(&instance, &attachment, &bug_dir).await {
                            Ok(summary) => summaries.push(summary),
                            Err(e) => {
                                eprintln!("Failed to download {}: {}", attachment.file_name, e)
                            }
                        }
                    }
                }

                if !summaries.is_empty() {
                    println!("\nDownload Summary:");
                    println!("================");
                    for summary in summaries {
                        println!("📄 {}", summary.file_name);
                        println!("   Size: {} bytes", summary.size);
                        println!("   MIME Type: {}", summary.mime_type);
                        if summary.decompressed {
                            println!("   ✅ Decompressed");
                        }
                        println!();
                    }
                }
            } else {
                println!("No attachments found.");
            }
        }
    } else {
        println!("{}", markdown);
    }

    Ok(())
}
