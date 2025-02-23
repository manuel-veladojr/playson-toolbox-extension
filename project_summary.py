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

# Ensure stdout uses UTF-8 (helpful on Windows)
sys.stdout.reconfigure(encoding='utf-8')

# ====================================
# 🚀 Required Python Libraries
# ====================================
REQUIRED_LIBRARIES = [
    "radon",
    "bandit",
    "flake8",
    "sqlparse",
    "pipdeptree",
    "safety",
    "markdown",     # Convert Markdown to HTML
    "jsonschema",   # Validate manifest.json schema
    "jinja2",       # HTML templating
]

def install_missing_libraries():
    """
    Ensure that all required libraries are installed dynamically.
    Installs missing packages and upgrades existing ones.
    """
    for lib in REQUIRED_LIBRARIES:
        try:
            __import__(lib)
        except ImportError:
            print(f"[INFO] Installing missing package: {lib} ...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", lib],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"[SUCCESS] Installed: {lib}")
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Failed to install {lib}: {e}")

# Ensure all dependencies are installed before executing the script
install_missing_libraries()

# Now import all modules safely after installation
from radon.complexity import cc_visit
from jinja2 import Template


# ====================================
# 🛠 User-Defined Settings (Defaults)
# ====================================
DRY_RUN_DEFAULT = False
VERBOSE_DEFAULT = False
HIGH_COMPLEXITY_THRESHOLD_DEFAULT = 10

# Exclusion settings
EXCLUDED_FOLDERS = ["node_modules", "dist", "build", "venv", "__pycache__", "coverage", "logs"]
EXCLUDED_FILES = ["python_project_tree.py", "project_summary.py"]

# Output filenames
SUMMARY_FILE = "project_summary.md"
SECURITY_REPORT = "security_report.md"
HTML_OUTPUT_FILE = "project_summary.html"
MANIFEST_FILE = "manifest.json"


class ProjectScanner:
    """
    A class that encapsulates the logic for scanning a code project.
    """

    def __init__(self, directory: Path, dry_run: bool = False, verbose: bool = False, threshold: int = 10):
        self.directory = directory
        self.dry_run = dry_run
        self.verbose = verbose
        self.high_complexity_threshold = threshold
        self.summary = {
            "Backend": [],
            "Frontend": [],
            "API Routes": [],
            "Database Queries": [],
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

    def analyze_complexity(self, file_path: Path):
        """
        Analyze the cyclomatic complexity of the given Python file.
        """
        complexity_results = {}
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        for item in cc_visit(code):
            cscore = item.complexity
            if cscore > self.high_complexity_threshold:
                complexity_results[item.name] = f"🔴 Score: {cscore} (High Complexity)"
            else:
                complexity_results[item.name] = f"🟢 Score: {cscore} (Low/Medium Complexity)"
        return complexity_results

    def extract_javascript_functions(self, lines: list):
        """
        Identify JavaScript function definitions in the file content.
        """
        content = "\n".join(lines)
        js_funcs = []
        func_pat = re.compile(r'function\s+([\w$]+)\s*\((.*?)\)\s*\{?', re.MULTILINE)
        arrow_pat = re.compile(r'(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?\(?([^\)]*?)\)?\s*=>', re.DOTALL)

        for match in func_pat.finditer(content):
            js_funcs.append(f"function {match.group(1)}({match.group(2)})")
        for match in arrow_pat.finditer(content):
            js_funcs.append(f"(arrow) {match.group(1)}({match.group(2)})")
        return js_funcs

    def extract_javascript_invocations(self, lines: list, defined_funcs: list):
        """
        Detect JavaScript function calls based on discovered function definitions.
        """
        content = "\n".join(lines)
        invocations = []
        func_names = {name.split(" ")[-1].split("(")[0] for name in defined_funcs}
        for func in func_names:
            if re.search(rf'\b{re.escape(func)}\s*\(', content):
                invocations.append(func)
        return invocations

    def process_file(self, file_path: Path):
        """
        Process each file, extracting relevant data.
        """
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to read {file_path}: {e}")
            return

        js_funcs = self.extract_javascript_functions(lines)
        if js_funcs:
            self.summary["JS Functions"].extend(js_funcs)

        js_calls = self.extract_javascript_invocations(lines, js_funcs)
        if js_calls:
            self.summary["JS Invocations"].extend(js_calls)

        if file_path.suffix == ".py":
            complexity = self.analyze_complexity(file_path)
            self.summary["Complex Functions"].update(complexity)

        with self.counter_lock:
            self.total_files_scanned += 1

    def scan_project(self):
        """
        The main scanning function.
        """
        start_time = time.time()

        with ThreadPoolExecutor() as executor:
            for file_path in self.directory.rglob("*"):
                if file_path.is_file() and file_path.suffix in {".py", ".js", ".jsx", ".tsx"}:
                    executor.submit(self.process_file, file_path)

        elapsed = time.time() - start_time
        print(f"✅ Scan completed in {elapsed:.2f}s")


if __name__ == "__main__":
    project_dir = Path(".").resolve()
    scanner = ProjectScanner(project_dir, dry_run=False, verbose=True)
    scanner.scan_project()
