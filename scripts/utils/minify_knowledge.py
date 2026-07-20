import os
import glob
import re

KNOWLEDGE_DIR = "/home/ardnord/.hermes/skills/red-teaming/pentest-automation/merged_knowledge"

def read_files(pattern):
    content = []
    for f in glob.glob(os.path.join(KNOWLEDGE_DIR, pattern)):
        with open(f, 'r') as file:
            content.append(file.read())
    return "\n\n".join(content)

def minify_markdown(text):
    # Remove HTML comments
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    # Remove excessive blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)
    # Remove common filler phrases
    fillers = [
        r'This document explains.*?\.',
        r'Here is a list of.*?\:',
        r'In this section, we will.*?\.',
        r'The following payloads.*?\:'
    ]
    for filler in fillers:
        text = re.sub(filler, '', text, flags=re.IGNORECASE)
    return text.strip()

groups = {
    "payloads_master.md": ["payloads_*.md", "jailbreak-templates.md"],
    "laravel_cheatsheet.md": ["laravel*.md", "inertia*.md"],
    "codeigniter_cheatsheet.md": ["codeigniter*.md"],
    "bypass_cheatsheet.md": ["waf_bypass.md", "rate_limit*.md", "contact_form*.md", "cors_testing.md"],
    "pentest_methodology.md": ["SKILL_*.md", "bug_bounty_program_analysis.md", "environment_setup.md", "tool_installation.md"],
    "misc_cheatsheet.md": ["*mapping.md", "*integration.md", "burp_mcp_pentest.md", "hostinger*.md", "refusal*.md", "seclists_paths.md", "bugbounty_report_template.md"]
}

# Ensure all files are moved to processed_backups first
backup_dir = os.path.join(KNOWLEDGE_DIR, "backups")
os.makedirs(backup_dir, exist_ok=True)

# Generate new files
for new_file, patterns in groups.items():
    combined_content = ""
    for pattern in patterns:
        combined_content += read_files(pattern) + "\n\n"
    
    minified = minify_markdown(combined_content)
    
    with open(os.path.join(KNOWLEDGE_DIR, new_file), 'w') as f:
        f.write(f"# {new_file.replace('_', ' ').replace('.md', '').upper()}\n\n{minified}")

# Create INDEX.md
index_content = """# INDEX: PENTEST MASTER KNOWLEDGE BASE

| File | Content Description |
|------|---------------------|
| `payloads_master.md` | All attack payloads (SQLi, XSS, SSTI, LFI, CMDi, Jailbreak). |
| `bypass_cheatsheet.md` | WAF bypass, rate limit bypass, CORS, and logic flaws. |
| `laravel_cheatsheet.md` | Laravel & Inertia.js specific vulnerabilities and testing. |
| `codeigniter_cheatsheet.md` | CodeIgniter attack surface and specific CVEs/bypass. |
| `pentest_methodology.md` | Step-by-step methodologies from all tools and phases. |
| `misc_cheatsheet.md` | Tool mappings (NSE, MSF), integrations, templates. |

**AI INSTRUCTION**: READ ONLY THIS INDEX FIRST. Read specific `.md` files only if relevant to the current target/task.
"""

with open(os.path.join(KNOWLEDGE_DIR, "INDEX.md"), 'w') as f:
    f.write(index_content)

# Move old files
for f in glob.glob(os.path.join(KNOWLEDGE_DIR, "*.md")):
    basename = os.path.basename(f)
    if basename not in groups.keys() and basename != "INDEX.md":
        os.rename(f, os.path.join(backup_dir, basename))
        
print("Minification complete.")
