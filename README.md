# bmo-to-md

A command-line tool to fetch bug information from Bugzilla and output as Markdown.

## Installation

```bash
cargo install --path .
```

## API Key (Optional)

To access private bugs or avoid rate limits, you can provide your Bugzilla API
key through multiple methods:

### Method 1: Environment Variable (Recommended)
```bash
export BMO_API_KEY="your-api-key-here"
```

### Method 2: Config File
Create `~/.config/bmo-to-md/config.toml`:
```toml
api_key = "your-api-key-here"
```

### Method 3: Local File
Create a `.bmo-api-key` file in the project directory:
```bash
echo "your-api-key-here" > .bmo-api-key
```

**Priority:** Environment variable > Config file > Local file

The tool will automatically use the API key from the first available source.

## Usage

Fetch a bug by number (defaults to Mozilla's Bugzilla):
```bash
bmo-to-md 1234567
```

Fetch a bug using a full URL:
```bash
bmo-to-md "https://bugzilla.mozilla.org/show_bug.cgi?id=1234567"
```

Use a different Bugzilla instance:
```bash
bmo-to-md --instance https://bugs.webkit.org 123456
```

### Output to Directory

Save markdown to a structured directory with attachments:
```bash
bmo-to-md -o /tmp -a 1838735
```

This creates `/tmp/bmo-1838735/bmo-1838735-summary.md` and downloads all
attachments to the same directory.

### Configuration Options


**Command Line Flags:**
- `-o, --output-dir`: Specify output directory
- `-a, --download-attachments`: Download attachments with progress bars

**Environment Variables:**
```bash
export BMO_OUTPUT_DIR=/path/to/output
export BMO_API_KEY=your-api-key-here
bmo-to-md -a 1838735
```

**Config File:**
Create `~/.config/bmo-to-md/config.toml`:
```toml
output_dir = "/path/to/output"
api_key = "your-api-key-here"
```

Priority: Command line > Environment variable > Config file > Default (/tmp)

## Output

The tool outputs a Markdown summary including:
- Bug number and title
- Status and resolution
- Severity and priority
- Product and component
- Assignee and reporter
- Creation and modification dates
- Keywords and whiteboard
- Dependencies (blocks/depends on)
- See also links
- Security groups (if applicable)
- All comments with timestamps and authors

### Attachment Download Features

When using `-a/--download-attachments`:
- Progress bars for each download
- Download summary with file details (name, size, MIME type)
- Automatic decompression of `.gz`, `.tar.gz`, `.tgz`, `.zip`, `.zst`, and `.zstd` files
- Files are saved in the same directory as the markdown file
- Phabricator review links are automatically filtered out and not downloaded
