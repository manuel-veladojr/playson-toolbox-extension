#!/usr/bin/env python3
"""
Project Scanner – A multi-language, multi-tool project scanning and reporting utility.

This tool scans source files (Python, JavaScript/JSX/TSX, HTML, CSS) to extract metrics such as:
  - JavaScript function definitions (traditional, arrow, function expressions, and class methods)
  - Invocations of the discovered JavaScript functions
  - Cyclomatic complexity in Python files
  - Unused dependencies, security issues, and more

The final reports are generated in Markdown and HTML formats.
"""

import os
import re
import json
import subprocess
import sys
import time
import logging
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
try:
    from radon.complexity import cc_visit
except ImportError:
    import subprocess
    import sys
    print("[INFO] radon not found. Installing radon...")
    subprocess.run([sys.executable, "-m", "pip", "install", "radon"], check=True)
    from radon.complexity import cc_visit

try:
    from jinja2 import Template
except ImportError:
    import subprocess, sys
    print("[INFO] jinja2 not found. Installing jinja2...")
    subprocess.run([sys.executable, "-m", "pip", "install", "jinja2"], check=True)
    from jinja2 import Template


# For HTML templating via Jinja2
from jinja2 import Template

# For GUI (if requested)
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError:
    tk = None

# Ensure stdout uses UTF-8 (helpful on Windows)
sys.stdout.reconfigure(encoding='utf-8')

# ====================================
# User-Requested Settings (defaults)
# ====================================
DRY_RUN_DEFAULT = False
VERBOSE_DEFAULT = False
HIGH_COMPLEXITY_THRESHOLD_DEFAULT = 10

# ====================================
# Required Python Libraries for scanning
# ====================================
REQUIRED_LIBRARIES = [
    "radon",
    "bandit",
    "flake8",
    "sqlparse",
    "pipdeptree",
    "safety",
    "markdown",     # For converting Markdown to HTML
    "jsonschema",   # For validating manifest.json schema
    "jinja2",       # For HTML templating
    # pip-audit can also be installed: "pip_audit"
]

# Folders & files to exclude
EXCLUDED_FOLDERS = ["node_modules", "dist", "build", "venv", "__pycache__", "coverage", "logs"]
EXCLUDED_FILES = ["python_project_tree.py", "project_summary.py", "project_summary.html"]

# Known sensitive patterns
SENSITIVE_PATTERNS = [
    r"API_KEY\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
    r"SECRET_KEY\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
    r"PASSWORD\s*=\s*[\"'].*[\"']",
    r"DATABASE_URL\s*=\s*[\"']postgres://.*[\"']"
]

# Output filenames
SUMMARY_FILE = "project_summary.md"
SECURITY_REPORT = "security_report.md"
HTML_OUTPUT_FILE = "project_summary.html"
MANIFEST_FILE = "manifest.json"


def install_missing_libraries() -> None:
    """
    Ensure that all required libraries are installed.
    """
    for lib in REQUIRED_LIBRARIES:
        try:
            __import__(lib)
        except ImportError:
            print(f"[INFO] Installing missing package: {lib} ...")
            subprocess.run([sys.executable, "-m", "pip", "install", lib], check=False)


install_missing_libraries()


class ProjectScanner:
    """
    A class that encapsulates the logic for scanning a code project.
    """

    def __init__(self, directory: Path, dry_run: bool = False, verbose: bool = False, threshold: int = 10) -> None:
        self.directory = directory
        self.dry_run = dry_run
        self.verbose = verbose
        self.high_complexity_threshold = threshold
        # Added "CSS" category for plain CSS files.
        self.summary = {
            "Backend": [],
            "Frontend": [],
            "CSS": [],
            "API Routes": [],
            "Database Queries": [],
            "Environment Variables": [],
            "TailwindCSS": [],
            "Bootstrap": [],
            "Security Issues": [],
            "Complex Functions": {},
            "Unused Dependencies": {},
            "JS Functions": [],
            "JS Invocations": []
        }
        self.total_files_scanned = 0
        self.counter_lock = threading.Lock()

    def detect_project_languages(self) -> set:
        """
        Identify which languages are used in the project based on file extensions.
        """
        languages = set()
        ext_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "JavaScript",
            ".tsx": "JavaScript",
            ".go": "Go",
            ".rs": "Rust",
            ".php": "PHP",
            ".cs": "C#",
            ".java": "Java",
            ".css": "CSS"
        }
        for file in self.directory.rglob("*"):
            if file.is_file():
                if any(excl in file.parts for excl in EXCLUDED_FOLDERS):
                    continue
                ext = file.suffix
                if ext in ext_map:
                    languages.add(ext_map[ext])
        return languages

    def detect_unused_dependencies(self) -> dict:
        """
        Detect unused dependencies for Python and JavaScript using external tools.
        """
        result = {"Python": [], "JavaScript": [], "Bootstrap": []}
        try:
            py_cmd = subprocess.run(["pipdeptree"], capture_output=True, text=True, check=False)
            if py_cmd.stdout:
                for line in py_cmd.stdout.splitlines():
                    line = line.strip()
                    if line:
                        result["Python"].append(line)
        except Exception as e:
            if self.verbose:
                logging.error(f"detect_unused_dependencies (pipdeptree): {e}")
        try:
            js_cmd = subprocess.run(["depcheck"], capture_output=True, text=True, check=False)
            if js_cmd.stdout:
                result["JavaScript"] = [l.strip() for l in js_cmd.stdout.splitlines() if l.strip()]
        except Exception as e:
            if self.verbose:
                logging.error(f"detect_unused_dependencies (depcheck): {e}")
        return result

    def run_unused_deps_for_go(self) -> list:
        results = []
        try:
            cmd = subprocess.run(["go", "list", "-m", "all"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                results.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_unused_deps_for_go: {e}")
        return results

    def run_unused_deps_for_rust(self) -> list:
        results = []
        try:
            cmd = subprocess.run(["cargo", "tree"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                results.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_unused_deps_for_rust: {e}")
        return results

    def run_unused_deps_for_php(self) -> list:
        results = []
        try:
            cmd = subprocess.run(["composer", "show"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                results.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_unused_deps_for_php: {e}")
        return results

    def run_unused_deps_for_csharp(self) -> list:
        results = []
        try:
            cmd = subprocess.run(["dotnet", "list", "package"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                results.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_unused_deps_for_csharp: {e}")
        return results

    def run_unused_deps_for_java(self) -> list:
        results = []
        try:
            cmd = subprocess.run(["mvn", "dependency:analyze"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                results.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_unused_deps_for_java: {e}")
        return results

    def detect_all_unused_dependencies(self, languages_found: set) -> dict:
        """
        For each recognized language, run the relevant approach to gather unused dependencies.
        """
        all_unused = {}
        base_result = self.detect_unused_dependencies()
        for lang, deps in base_result.items():
            all_unused[lang] = deps
        if "Go" in languages_found:
            all_unused["Go"] = self.run_unused_deps_for_go()
        if "Rust" in languages_found:
            all_unused["Rust"] = self.run_unused_deps_for_rust()
        if "PHP" in languages_found:
            all_unused["PHP"] = self.run_unused_deps_for_php()
        if "C#" in languages_found:
            all_unused["C#"] = self.run_unused_deps_for_csharp()
        if "Java" in languages_found:
            all_unused["Java"] = self.run_unused_deps_for_java()
        return all_unused

    def run_pip_audit(self) -> list:
        """
        Run pip-audit to check for Python dependency vulnerabilities.
        """
        if self.verbose:
            logging.info("Running pip-audit for Python dependency vulnerabilities...")
        findings = []
        try:
            cmd = subprocess.run(["pip-audit", "--format", "json"],
                                 capture_output=True, text=True, check=False)
            if cmd.stdout:
                data = json.loads(cmd.stdout)
                for vuln in data:
                    for detail in vuln.get("vulns", []):
                        severity = detail.get("severity", "UNKNOWN")
                        advisory = detail.get("id", "")
                        message = detail.get("description", "")
                        findings.append(f"[{severity}] {advisory} in {vuln['name']}=={vuln['version']}: {message}")
        except Exception as e:
            if self.verbose:
                logging.error(f"pip-audit: {e}")
        return findings

    def run_npm_audit(self) -> list:
        """
        Run npm audit to check for JavaScript dependency vulnerabilities.
        """
        if self.verbose:
            logging.info("Running npm audit...")
        findings = []
        try:
            cmd = subprocess.run(["npm", "audit", "--json"],
                                 capture_output=True, text=True, check=False)
            if cmd.stdout:
                data = json.loads(cmd.stdout)
                if "advisories" in data:
                    for key, adv in data["advisories"].items():
                        severity = adv.get("severity", "UNKNOWN")
                        module_name = adv.get("module_name", "")
                        findings.append(f"[{severity}] {module_name} => {adv.get('title','')} : {adv.get('url','')}")
                elif "vulnerabilities" in data:
                    pass
        except Exception as e:
            if self.verbose:
                logging.error(f"npm_audit: {e}")
        return findings

    def scan_environment_vars(self) -> list:
        """
        Scan a .env file for potential sensitive environment variable entries.
        """
        findings = []
        env_file = Path(".env")
        if env_file.exists():
            try:
                with env_file.open("r", encoding="utf-8") as ef:
                    for line in ef.readlines():
                        line_strip = line.strip()
                        if line_strip and not line_strip.startswith("#"):
                            findings.append(f".env => {line_strip}")
            except Exception as e:
                if self.verbose:
                    logging.error(f"scan_environment_vars: {e}")
        return findings

    def run_eslint(self) -> list:
        """
        Run ESLint on the project.
        """
        if self.verbose:
            logging.info("Running ESLint...")
        issues = []
        try:
            cmd = subprocess.run(["eslint", "."], capture_output=True, text=True, check=False)
            if cmd.stdout:
                issues.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_eslint: {e}")
        return issues

    def run_stylelint(self) -> list:
        """
        Run Stylelint for CSS/SCSS files.
        """
        if self.verbose:
            logging.info("Running Stylelint...")
        issues = []
        try:
            cmd = subprocess.run(["stylelint", "**/*.css", "**/*.scss"], capture_output=True, text=True, check=False)
            if cmd.stdout:
                issues.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_stylelint: {e}")
        return issues

    def run_web_ext_lint(self) -> list:
        """
        Run web-ext lint (for browser extension projects).
        """
        if self.verbose:
            logging.info("Running web-ext lint...")
        issues = []
        try:
            cmd = subprocess.run(["web-ext", "lint", "--json"],
                                 capture_output=True, text=True, check=False)
            if cmd.stdout:
                issues.extend(cmd.stdout.strip().splitlines())
        except Exception as e:
            if self.verbose:
                logging.error(f"run_web_ext_lint: {e}")
        return issues

    def parse_manifest_for_permissions(self) -> list:
        """
        Parse manifest.json to check for suspicious permissions and missing CSP.
        """
        findings = []
        manifest_path = Path(MANIFEST_FILE)
        if not manifest_path.exists():
            return findings
        try:
            with manifest_path.open("r", encoding="utf-8") as mf:
                data = json.load(mf)
                perms = data.get("permissions", [])
                for p in perms:
                    if p == "*://*/*" or p == "management":
                        findings.append(f"Suspicious permission: '{p}' in {MANIFEST_FILE}")
                csp = data.get("content_security_policy", "")
                if not csp:
                    findings.append(f"No content_security_policy found in {MANIFEST_FILE}. Consider adding a robust CSP.")
        except Exception as e:
            findings.append(f"[ERROR] Could not parse {MANIFEST_FILE}: {e}")
        return findings

    def extract_sql_queries(self, lines: list) -> list:
        """
        Extract SQL queries from given lines.
        """
        sql_query = ""
        queries = []
        inside_query = False
        for line in lines:
            line_strip = line.strip()
            if re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s+", line_strip, re.IGNORECASE):
                inside_query = True
                sql_query += line_strip + " "
            elif inside_query:
                sql_query += line_strip + " "
                if line_strip.endswith(";"):
                    queries.append(sql_query.strip())
                    sql_query = ""
                    inside_query = False
        return queries

    def extract_tailwind_classes(self, line: str) -> list:
        """
        Extract Tailwind CSS classes from a line.
        """
        classes = []
        match = re.findall(r'className=["\'](.*?)["\']', line)
        for m in match:
            classes.extend(m.split())
        return classes

    def extract_bootstrap_classes(self, line: str) -> list:
        """
        Extract typical Bootstrap class names from a line.
        """
        classes = []
        match = re.findall(r'(?:class|className)\s*=\s*["\']([^"\']+)["\']', line)
        for m in match:
            for c in m.split():
                if re.search(r'^(container|row|col-|btn|table|active|disabled|danger|warning|success|info|navbar|dropdown)', c, re.IGNORECASE):
                    classes.append(c)
        return classes

    def extract_javascript_functions(self, lines: list) -> list:
        """
        Identify JavaScript function definitions in the provided file content.

        This method joins all lines into one string (with newlines) to allow multi-line matching.
        It detects:
          - Traditional function declarations: function myFunc(...) { ... }
          - Arrow functions: const myFunc = async () => { ... }
          - Function expressions: const myFunc = function(...) { ... }
          - Class methods (excluding constructors)
        
        Reserved keywords (e.g., if, else, for, etc.) are filtered out.
        """
        content = "\n".join(lines)
        js_funcs = []
        reserved = {"if", "else", "for", "while", "switch", "case", "try", "catch", "finally",
                    "return", "const", "let", "var", "function", "new", "class", "default",
                    "break", "continue", "do", "in", "of"}
        func_pat = re.compile(r'function\s+([\w$]+)\s*\((.*?)\)\s*\{?', re.MULTILINE)
        arrow_pat = re.compile(r'(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?\(?([^\)]*?)\)?\s*=>', re.DOTALL)
        func_expr_pat = re.compile(r'(?:const|let|var)\s+([\w$]+)\s*=\s*function\s*\((.*?)\)\s*\{?', re.MULTILINE)
        class_method_pat = re.compile(r'^\s*([\w$]+)\s*\((.*?)\)\s*\{', re.MULTILINE)

        for match in func_pat.finditer(content):
            name = match.group(1)
            if name not in reserved:
                js_funcs.append(f"function {name}({match.group(2)})")
        for match in arrow_pat.finditer(content):
            name = match.group(1)
            if name not in reserved:
                js_funcs.append(f"(arrow) {name}({match.group(2)})")
        for match in func_expr_pat.finditer(content):
            name = match.group(1)
            if name not in reserved:
                js_funcs.append(f"(function expression) {name}({match.group(2)})")
        for match in class_method_pat.finditer(content):
            name = match.group(1)
            if name != "constructor" and name not in reserved:
                js_funcs.append(f"(class method) {name}({match.group(2)})")
        return js_funcs

    def extract_javascript_invocations(self, lines: list, defined_funcs: list) -> list:
        """
        Detect JavaScript function calls based on the previously extracted definitions.

        This method joins the file content into a single string to allow matching across lines.
        It filters out reserved keywords so that only genuine function calls are returned.
        """
        content = "\n".join(lines)
        invocations = []
        func_short_names = set()
        reserved = {"if", "else", "for", "while", "switch", "case", "try", "catch", "finally",
                    "return", "const", "let", "var", "function", "new", "class", "default",
                    "break", "continue", "do", "in", "of"}
        def_name_pat = re.compile(r'(?:arrow\)|function|function expression\)|class method\))\s+([\w$]+)\s*\(')
        for definition in defined_funcs:
            match = def_name_pat.search(definition)
            if match:
                name = match.group(1)
                if name not in reserved:
                    func_short_names.add(name)
            else:
                simple = re.findall(r'([\w$]+)\s*\(', definition)
                if simple:
                    name = simple[0]
                    if name not in reserved:
                        func_short_names.add(name)
        for short_name in func_short_names:
            pattern = r'\b' + re.escape(short_name) + r'\s*\('
            if re.search(pattern, content):
                invocations.append(short_name)
        return list(dict.fromkeys(invocations))

    def analyze_complexity(self, file_path: Path) -> dict:
        """
        Analyze the cyclomatic complexity of the given Python file.
        """
        complexity_results = {}
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            for item in cc_visit(code):
                cscore = item.complexity
                if cscore <= 5:
                    lvl = "🟢 Low Complexity"
                elif cscore <= 10:
                    lvl = "🟠 Medium Complexity"
                else:
                    lvl = "🔴 High Complexity (Needs Refactoring)"
                complexity_results[item.name] = f"Score: {cscore} ({lvl})"
        except Exception as e:
            if self.verbose:
                logging.error(f"analyze_complexity: {e}")
        return complexity_results

    def convert_markdown_to_html(self, md_content: str) -> str:
        """
        Convert markdown content to HTML.
        """
        try:
            import markdown
            return markdown.markdown(md_content)
        except ImportError as e:
            if self.verbose:
                logging.error(f"convert_markdown_to_html: {e}")
            return md_content

    def generate_html_output(self) -> None:
        """
        Generate an HTML report using Jinja2 templating.
        The report preserves the emoji-rich design, has all markers expanded by default,
        and includes global Expand/Collapse buttons.
        """
        scan_date = time.strftime("%Y-%m-%d %H:%M:%S")
        metadata = {
            "scan_date": scan_date,
            "scanned_directory": str(self.directory),
            "total_files_processed": self.total_files_scanned
        }
        overall_security = "Excellent" if not self.summary.get("Security Issues") else f"Issues Detected: {len(self.summary.get('Security Issues'))}"
        security_data = {
            "security_issues": self.summary.get("Security Issues", []),
            "env_vars": self.scan_environment_vars(),
            "manifest": self.parse_manifest_for_permissions(),
            "eslint": self.run_eslint() or ["✅ ESLint ran and found no issues."],
            "stylelint": self.run_stylelint() or ["✅ Stylelint ran and found no issues."],
            "webext": self.run_web_ext_lint() or ["✅ web-ext lint ran and found no issues."],
            "pip_audit": self.run_pip_audit() or ["✅ pip-audit ran and found no issues."],
            "npm_audit": self.run_npm_audit() or ["✅ npm audit ran and found no issues."]
        }
        html_template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🚀 Project Summary HTML Report</title>
    <style>
        details { margin-bottom: 1em; }
        summary { font-weight: bold; font-size: 1.2em; cursor: pointer; }
        body { font-family: Arial, sans-serif; }
        button { margin: 0.5em; padding: 0.5em 1em; font-size: 1em; }
        ul { list-style: none; padding-left: 0; }
    </style>
    <script>
        function toggleAllDetails(expand) {
            var details = document.getElementsByTagName("details");
            for (var i = 0; i < details.length; i++) {
                if(expand) {
                    details[i].setAttribute("open", "true");
                } else {
                    details[i].removeAttribute("open");
                }
            }
        }
    </script>
</head>
<body>
    <h1>🚀 Project Summary HTML Report</h1>
    <button onclick="toggleAllDetails(true)">Expand All</button>
    <button onclick="toggleAllDetails(false)">Collapse All</button>
    <h2>Scan Metadata</h2>
    <ul>
        <li><strong>Scan Date:</strong> {{ metadata.scan_date }}</li>
        <li><strong>Scanned Directory:</strong> {{ metadata.scanned_directory }}</li>
        <li><strong>Total Files Processed:</strong> {{ metadata.total_files_processed }}</li>
    </ul>
    <h2>📊 Summary Dashboard</h2>
    <ul>
        <li><strong>🟢 Backend Files:</strong> {{ summary.Backend|length }}</li>
        <li><strong>🟡 Frontend Files:</strong> {{ summary.Frontend|length }}</li>
        <li><strong>🎨 CSS Files:</strong> {{ summary.CSS|length }}</li>
        <li><strong>🔵 API Routes Detected:</strong> {% if summary["API Routes"]|length > 0 %}{{ summary["API Routes"]|length }}{% else %}✅ No API routes detected{% endif %}</li>
        <li><strong>🔶 Database Queries Detected:</strong> {% if summary["Database Queries"]|length > 0 %}{{ summary["Database Queries"]|length }}{% else %}✅ No Database queries detected{% endif %}</li>
        <li><strong>🟠 Complex Functions:</strong> {{ summary["Complex Functions"]|length }}</li>
        <li><strong>🔴 Security Warnings:</strong> {{ summary["Security Issues"]|length }}</li>
        <li><strong>📦 Unused Dependencies:</strong>
        {% for lang, deps in summary["Unused Dependencies"].items() %}
          {{ lang }} ({{ deps|length }}){% if not loop.last %}, {% endif %}
        {% endfor %}
        </li>
        <li><strong>🎨 TailwindCSS Classes:</strong> {{ summary["TailwindCSS"]|length }}</li>
        <li><strong>💠 Bootstrap Classes:</strong> {{ summary["Bootstrap"]|length }}</li>
        <li><strong>⚙️ JavaScript Functions:</strong> {{ summary["JS Functions"]|length }}</li>
        <li><strong>📞 JavaScript Function Calls:</strong> {{ summary["JS Invocations"]|length }}</li>
    </ul>
    <h2>Detailed Reports</h2>
    {% for section, items in summary.items() %}
    {% if section == "Unused Dependencies" %}
        <details open>
            <summary>🔹 {{ section }}</summary>
            <ul>
                {% for lang, deps in items.items() %}
                    <li><strong>{{ lang }}</strong>:
                        {% if deps %}
                            <ul>
                                {% for dep in deps %}
                                    <li>{{ dep }}</li>
                                {% endfor %}
                            </ul>
                        {% else %}
                            ✅ No unused dependencies found!
                        {% endif %}
                    </li>
                {% endfor %}
            </ul>
        </details>
    {% elif section != "Environment Variables" %}
        <details open>
            <summary>🔹 {{ section }}</summary>
            {% if section == "Complex Functions" %}
                <ul>
                {% for func, score in items.items() %}
                    <li>{{ func }} => {{ score }}</li>
                {% endfor %}
                </ul>
            {% elif section == "JS Functions" or section == "JS Invocations" %}
                <ul>
                {% for item in items %}
                    <li>{{ item }}</li>
                {% endfor %}
                </ul>
            {% else %}
                <ul>
                {% for item in items %}
                    <li>{{ item }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        </details>
    {% endif %}
{% endfor %}
    <h2>🔒 Security Report</h2>
    <details open>
      <summary>Security & Code Complexity Report</summary>
      <p><strong>Overall Security Posture:</strong> {{ overall_security }}</p>
      <h3>❗ Security Issues</h3>
      <ul>
        {% if security_data.security_issues %}
          {% for issue in security_data.security_issues %}
            <li>{{ issue }}</li>
          {% endfor %}
        {% else %}
          <li>✅ No security vulnerabilities found via pattern checks!</li>
        {% endif %}
      </ul>
      <h3>🌐 Environment Variables</h3>
      <ul>
        {% if security_data.env_vars %}
          {% for ev in security_data.env_vars %}
            <li>{{ ev }}</li>
          {% endfor %}
        {% else %}
          <li>✅ No suspicious .env entries found.</li>
        {% endif %}
      </ul>
      <h3>📄 Manifest & Permissions</h3>
      <ul>
        {% if security_data.manifest %}
          {% for m in security_data.manifest %}
            <li>{{ m }}</li>
          {% endfor %}
        {% else %}
          <li>✅ Manifest permissions look minimal or no manifest.json found!</li>
        {% endif %}
      </ul>
      <h3>🏷 ESLint</h3>
      <ul>
        {% for e in security_data.eslint %}
          <li>{{ e }}</li>
        {% endfor %}
      </ul>
      <h3>🎨 Stylelint</h3>
      <ul>
        {% for s in security_data.stylelint %}
          <li>{{ s }}</li>
        {% endfor %}
      </ul>
      <h3>🦊 web-ext lint</h3>
      <ul>
        {% for w in security_data.webext %}
          <li>{{ w }}</li>
        {% endfor %}
      </ul>
      <h3>🐍 pip-audit</h3>
      <ul>
        {% for p in security_data.pip_audit %}
          <li>{{ p }}</li>
        {% endfor %}
      </ul>
      <h3>📦 npm audit</h3>
      <ul>
        {% for n in security_data.npm_audit %}
          <li>{{ n }}</li>
        {% endfor %}
      </ul>
    </details>
</body>
</html>
""")
        rendered_html = html_template.render(
            metadata=metadata,
            summary=self.summary,
            overall_security=overall_security,
            security_data=security_data
        )
        try:
            with open(HTML_OUTPUT_FILE, "w", encoding="utf-8") as hf:
                hf.write(rendered_html)
        except Exception as e:
            if self.verbose:
                logging.error(f"Error writing HTML report: {e}")

    def generate_markdown_summary(self) -> None:
        """
        Generate a markdown summary report of the scan.
        """
        scan_date = time.strftime("%Y-%m-%d %H:%M:%S")
        metadata = (
            f"**Scan Metadata:**\n"
            f"- **Scan Date:** {scan_date}\n"
            f"- **Scanned Directory:** {self.directory}\n"
            f"- **Total Files Processed:** {self.total_files_scanned}\n\n"
        )

        try:
            with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
                f.write("# 🚀 **Project Summary Report**\n\n")
                f.write(metadata)
                f.write("## 📊 **Summary Dashboard**\n")
                backend_count = len(self.summary.get("Backend", []))
                frontend_count = len(self.summary.get("Frontend", []))
                css_count = len(self.summary.get("CSS", []))
                f.write(f"- 🟢 **Backend Files:** {backend_count}\n")
                f.write(f"- 🟡 **Frontend Files:** {frontend_count}\n")
                f.write(f"- 🎨 **CSS Files:** {css_count}\n")
                api_count = len(self.summary.get("API Routes", []))
                if api_count > 0:
                    f.write(f"- 🔵 **API Routes Detected:** {api_count}\n")
                else:
                    f.write("- 🔵 **API Routes Detected:** ✅ No API routes detected!\n")
                db_count = len(self.summary.get("Database Queries", []))
                if db_count > 0:
                    f.write(f"- 🔶 **Database Queries Detected:** {db_count}\n")
                else:
                    f.write("- 🔶 **Database Queries Detected:** ✅ No Database queries detected!\n")
                cplx_count = len(self.summary.get("Complex Functions", {}))
                f.write(f"- 🟠 **Complex Functions:** {cplx_count}\n")
                sec_count = len(self.summary.get("Security Issues", []))
                f.write(f"- 🔴 **Security Warnings:** {sec_count}\n")
                all_unused_deps = self.summary.get("Unused Dependencies", {})
                f.write("- 📦 **Unused Dependencies:**\n")
                if not all_unused_deps:
                    f.write("  - ✅ No recognized languages or no dependencies found!\n")
                else:
                    for lang_name, dep_list in all_unused_deps.items():
                        if dep_list:
                            f.write(f"  - **{lang_name}**:\n")
                            for dep in dep_list:
                                f.write(f"    - {dep}\n")
                        else:
                            f.write(f"  - **{lang_name}**: ✅ No unused dependencies found!\n")
                tw_count = len(self.summary.get("TailwindCSS", []))
                if tw_count == 0:
                    f.write("- 🎨 **TailwindCSS Classes:** ✅ No TailwindCSS classes detected!\n")
                else:
                    f.write(f"- 🎨 **TailwindCSS Classes:** {tw_count} classes detected!\n")
                bs_count = len(self.summary.get("Bootstrap", []))
                if bs_count == 0:
                    f.write("- 💠 **Bootstrap Classes:** ✅ No Bootstrap classes detected!\n")
                else:
                    f.write(f"- 💠 **Bootstrap Classes:** {bs_count} classes detected!\n")
                jsf_count = len(self.summary.get("JS Functions", []))
                if jsf_count > 0:
                    f.write(f"- ⚙️ **JavaScript Functions:** {jsf_count} found!\n")
                else:
                    f.write("- ⚙️ **JavaScript Functions:** ✅ None found!\n")
                jsi_count = len(self.summary.get("JS Invocations", []))
                if jsi_count > 0:
                    f.write(f"- 📞 **JavaScript Function Calls:** {jsi_count} found!\n")
                else:
                    f.write("- 📞 **JavaScript Function Calls:** ✅ None found!\n")
                f.write("\n---\n")
                for category, items in self.summary.items():
                    if category in ["Unused Dependencies", "Environment Variables"]:
                        continue
                    if items:
                        f.write(f"## 🔹 {category}\n\n")
                        if category == "Complex Functions":
                            for func, score in items.items():
                                match = re.search(r"Score:\s*(\d+)", score)
                                if match:
                                    c_val = int(match.group(1))
                                    if c_val > self.high_complexity_threshold:
                                        f.write(f"- ❌ [HIGH] {func} => {score}\n")
                                    else:
                                        f.write(f"- {func} => {score}\n")
                                else:
                                    f.write(f"- {func} => {score}\n")
                        elif category in ["Backend", "Frontend", "CSS"]:
                            for item in items:
                                f.write(f"- {item}\n")
                        elif category == "API Routes":
                            for route in items:
                                f.write(f"- {route}\n")
                        elif category == "Database Queries":
                            f.write("```sql\n")
                            for query in items:
                                f.write(f"{query}\n")
                            f.write("```\n\n")
                        elif category == "TailwindCSS":
                            f.write("- Detected TailwindCSS classes:\n")
                            for cls in items:
                                f.write(f"  - {cls}\n")
                        elif category == "Bootstrap":
                            f.write("- Detected Bootstrap classes:\n")
                            for cls in items:
                                f.write(f"  - {cls}\n")
                        elif category == "JS Functions":
                            f.write("- Detected JavaScript functions:\n")
                            for fn in items:
                                f.write(f"  - {fn}\n")
                        elif category == "JS Invocations":
                            f.write("- Detected JavaScript function calls:\n")
                            for fncall in items:
                                f.write(f"  - {fncall}\n")
                        elif category == "Security Issues":
                            for issue in items:
                                f.write(f"**[⚠️ SECURITY WARNING]** {issue}\n")
                        else:
                            for item in items:
                                f.write(f"- {item}\n")
                        f.write("\n---\n")
        except Exception as e:
            if self.verbose:
                logging.error(f"generate_markdown_summary: {e}")

    def generate_security_report(self,
                                 manifest_findings: list,
                                 eslint_issues: list,
                                 stylelint_issues: list,
                                 webext_issues: list,
                                 pip_audit_findings: list,
                                 npm_audit_findings: list,
                                 env_var_findings: list) -> None:
        """
        Generate a markdown security report based on various audit findings.
        """
        scan_date = time.strftime("%Y-%m-%d %H:%M:%S")
        metadata = (
            f"**Scan Metadata:**\n"
            f"- **Scan Date:** {scan_date}\n"
            f"- **Scanned Directory:** {self.directory}\n\n"
        )
        overall_security = "Excellent" if not self.summary.get("Security Issues") else f"Issues Detected: {len(self.summary.get('Security Issues'))}"
        try:
            with open(SECURITY_REPORT, "w", encoding="utf-8") as f:
                f.write("# 🔒 **Security & Code Complexity Report**\n\n")
                f.write(metadata)
                f.write(f"**Overall Security Posture:** {overall_security}\n\n")
                f.write("## ❗ **Security Issues**\n")
                if self.summary.get("Security Issues"):
                    for issue in self.summary["Security Issues"]:
                        f.write(f"❌ {issue}\n")
                else:
                    f.write("✅ No security vulnerabilities found via pattern checks!\n")
                f.write("\n---\n")
                f.write("## 🌐 **Environment Variable Findings**\n")
                if env_var_findings:
                    for envline in env_var_findings:
                        f.write(f"❌ {envline}\n")
                else:
                    f.write("✅ No suspicious .env entries found.\n")
                f.write("\n---\n")
                f.write("## 📄 **Manifest & Permissions Audit**\n")
                if manifest_findings:
                    for mf in manifest_findings:
                        f.write(f"❌ {mf}\n")
                else:
                    f.write("✅ Manifest permissions look minimal or no manifest.json found!\n")
                f.write("\n---\n")
                f.write("## 🏷 **ESLint Findings** (React + Hooks)\n")
                if eslint_issues:
                    for eissue in eslint_issues:
                        f.write(f"{eissue}\n")
                else:
                    f.write("✅ ESLint ran and found no issues.\n")
                f.write("\n---\n")
                f.write("## 🎨 **Stylelint Findings** (Tailwind/CSS)\n")
                if stylelint_issues:
                    for sissue in stylelint_issues:
                        f.write(f"{sissue}\n")
                else:
                    f.write("✅ Stylelint ran and found no issues.\n")
                f.write("\n---\n")
                f.write("## 🦊 **web-ext lint** (Browser Extension check)\n")
                if webext_issues:
                    for wissue in webext_issues:
                        f.write(f"{wissue}\n")
                else:
                    f.write("✅ web-ext lint ran and found no issues.\n")
                f.write("\n---\n")
                f.write("## 🐍 **pip-audit Findings**\n")
                if pip_audit_findings:
                    for pa in pip_audit_findings:
                        f.write(f"❌ {pa}\n")
                else:
                    f.write("✅ pip-audit ran and found no issues.\n")
                f.write("\n---\n")
                f.write("## 📦 **npm audit Findings**\n")
                if npm_audit_findings:
                    for na in npm_audit_findings:
                        f.write(f"❌ {na}\n")
                else:
                    f.write("✅ npm audit ran and found no issues.\n")
                f.write("\n---\n")
                f.write("## ⚙️ **Complex Functions**\n")
                if self.summary.get("Complex Functions"):
                    for func, score in self.summary["Complex Functions"].items():
                        if "High Complexity" in score:
                            f.write(f"❌ {func} → {score}\n")
                        else:
                            f.write(f"- {func} → {score}\n")
                else:
                    f.write("✅ No complex functions detected!\n")
                f.write("\n---\n")
        except Exception as e:
            if self.verbose:
                logging.error(f"generate_security_report: {e}")

    def process_file(self, file_path: Path) -> None:
        """
        Process an individual file, categorizing its content and extracting metrics.
        """
        if file_path.name in EXCLUDED_FILES:
            if self.verbose:
                logging.debug(f"Excluding file: {file_path}")
            return
        if self.dry_run:
            logging.info(f"[DRY RUN] Would parse {file_path}")
            return
        category = None
        js_funcs = []
        try:
            if file_path.suffix == ".py":
                complexity = self.analyze_complexity(file_path)
                for func, cscore in complexity.items():
                    self.summary["Complex Functions"][func] = cscore
                category = "Backend"
            elif file_path.suffix in [".js", ".jsx", ".tsx"]:
                category = "Frontend"
            elif file_path.suffix == ".css":
                category = "CSS"
            elif file_path.suffix == ".html":
                category = "Frontend"
            else:
                return

            self.summary[category].append(f"{file_path.name} (Path: {file_path.parent})")

            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception as e:
                if self.verbose:
                    logging.error(f"Error reading file {file_path}: {e}")
                return

            with self.counter_lock:
                self.total_files_scanned += 1

            db_queries = self.extract_sql_queries(lines)
            if db_queries:
                self.summary["Database Queries"].extend(db_queries)

            if file_path.suffix in [".js", ".jsx", ".tsx"]:
                js_funcs = self.extract_javascript_functions(lines)
                if js_funcs:
                    for func in js_funcs:
                        self.summary["JS Functions"].append(f"{func} (Found in: {file_path})")

            for line in lines:
                line_strip = line.strip()
                if line_strip.startswith("/api"):
                    self.summary["API Routes"].append(line_strip)
                if "className=" in line_strip:
                    tw = self.extract_tailwind_classes(line_strip)
                    self.summary["TailwindCSS"].extend(tw)
                bs = self.extract_bootstrap_classes(line_strip)
                if bs:
                    self.summary["Bootstrap"].extend(bs)
                for patt in SENSITIVE_PATTERNS:
                    if re.search(patt, line_strip):
                        self.summary["Security Issues"].append(f"Sensitive Data Found in {file_path.name}: {line_strip}")
                if "dangerouslySetInnerHTML" in line_strip or ".innerHTML" in line_strip:
                    self.summary["Security Issues"].append(f"Possible DOM-based XSS usage in {file_path.name}: {line_strip}")

            if file_path.suffix in [".js", ".jsx", ".tsx"] and js_funcs:
                calls = self.extract_javascript_invocations(lines, js_funcs)
                if calls:
                    for call in calls:
                        self.summary["JS Invocations"].append(f"{call} (Found in: {file_path})")
        except Exception as e:
            if self.verbose:
                logging.error(f"process_file error in {file_path}: {e}")

    def scan_project(self) -> None:
        """
        The main scanning function that orchestrates the project scan.
        """
        start_time = time.time()
        if self.dry_run:
            logging.info("[DRY RUN] Will not parse. Only listing potential files/folders...\n")

        languages_found = self.detect_project_languages()
        if not self.dry_run:
            all_unused = self.detect_all_unused_dependencies(languages_found)
            self.summary["Unused Dependencies"] = all_unused

        manifest_findings = self.parse_manifest_for_permissions()

        if not self.dry_run:
            eslint_issues = self.run_eslint()
            stylelint_issues = self.run_stylelint()
            webext_issues = self.run_web_ext_lint()
            pip_audit_findings = self.run_pip_audit()
            npm_audit_findings = self.run_npm_audit()
            env_var_findings = self.scan_environment_vars()
        else:
            eslint_issues = stylelint_issues = webext_issues = pip_audit_findings = npm_audit_findings = env_var_findings = []

        with ThreadPoolExecutor() as executor:
            for file_path in self.directory.rglob("*"):
                if file_path.is_file():
                    if any(excl in file_path.parts for excl in EXCLUDED_FOLDERS):
                        continue
                    executor.submit(self.process_file, file_path)

        if not self.dry_run:
            self.generate_markdown_summary()
            self.generate_security_report(
                manifest_findings,
                eslint_issues,
                stylelint_issues,
                webext_issues,
                pip_audit_findings,
                npm_audit_findings,
                env_var_findings
            )
            self.generate_html_output()
            elapsed = time.time() - start_time
            if self.verbose:
                logging.info(f"Scan completed in {elapsed:.2f}s")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Scan and analyze a code project.\n\n"
                    "This tool supports scanning Python, JavaScript, HTML, CSS files and more. "
                    "It generates reports in Markdown and HTML (with interactive, emoji-rich sections).\n\n"
                    "Options:\n"
                    "  --gui    Launch a simple GUI for non-technical users.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without modifications")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--threshold", type=int, default=HIGH_COMPLEXITY_THRESHOLD_DEFAULT,
                        help="Cyclomatic complexity threshold")
    parser.add_argument("--directory", type=str, default=".", help="Directory to scan")
    parser.add_argument("--gui", action="store_true", help="Launch a simple GUI instead of command-line interface")
    return parser.parse_args()


def run_gui():
    if not tk:
        print("Tkinter is not available on this system.")
        return

    def select_directory():
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            dir_var.set(selected_dir)

    def start_scan():
        directory = Path(dir_var.get())
        if not directory.exists():
            messagebox.showerror("Error", "Directory does not exist.")
            return
        scanner = ProjectScanner(directory, dry_run=False, verbose=True, threshold=HIGH_COMPLEXITY_THRESHOLD_DEFAULT)
        scanner.scan_project()
        messagebox.showinfo("Scan Complete", f"Scan completed.\nReports generated: {SUMMARY_FILE}, {SECURITY_REPORT}, {HTML_OUTPUT_FILE}")

    root = tk.Tk()
    root.title("Project Scanner")
    tk.Label(root, text="Select Directory to Scan:").pack(padx=10, pady=5)
    dir_var = tk.StringVar()
    tk.Entry(root, textvariable=dir_var, width=50).pack(padx=10, pady=5)
    tk.Button(root, text="Browse...", command=select_directory).pack(padx=10, pady=5)
    tk.Button(root, text="Start Scan", command=start_scan).pack(padx=10, pady=10)
    root.mainloop()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    if args.gui:
        run_gui()
    else:
        project_dir = Path(args.directory).resolve()
        scanner = ProjectScanner(project_dir, dry_run=args.dry_run, verbose=args.verbose, threshold=args.threshold)
        scanner.scan_project()


if __name__ == "__main__":
    main()