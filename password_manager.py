"""

Advanced Password Manager with GUI and CLI

"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import random
import string
import logging
import json
import argparse
import sys
import hashlib
import requests
from datetime import datetime, timedelta
from functools import lru_cache
from typing import List, Tuple
from zxcvbn import zxcvbn

# Configuration
logging.basicConfig(filename='password_manager.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
BREACH_CHECK_API = "https://api.pwnedpasswords.com/range/"
PASSPHRASE_WORDLIST_URL = "https://eff.org/files/2016/07/18/eff_large_wordlist.txt"
MAX_CLIPBOARD_TIME = 30  # seconds
MIN_PASSWORD_LENGTH = 12
WEAK_WORDLIST_PATH = "./weak_passwords.txt"
BANNED_WORDLIST_PATH = "./banned_passwords.txt"

class Wordlist:
    """Enhanced wordlist handler with caching"""
    _cache = {}

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.words = self._load_wordlist()

    def _load_wordlist(self) -> set:
        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                wordlist = {line.strip().lower() for line in f}
                self._cache[self.file_path] = wordlist
                return wordlist
        except Exception as e:
            logging.error(f"Error loading wordlist: {str(e)}")
            return set()

    def contains(self, word: str) -> bool:
        return word.lower() in self.words

class PasswordStrengthAnalyzer:
    """Core password analysis engine"""
    def __init__(self):
        self.weak_wordlist = Wordlist(WEAK_WORDLIST_PATH)
        self.banned_wordlist = Wordlist(BANNED_WORDLIST_PATH)
        self.common_patterns = [
            (r'\d{4,}', "Sequential numbers"),
            (r'(.)\1{3,}', "Repeated characters"),
            (r'(abc|def|ghi|jkl|mno|pqrs|tuv|wxyz){3,}', "Keyboard pattern")
        ]
        self.passphrase_words = self._load_passphrase_wordlist()

    def _load_passphrase_wordlist(self) -> List[str]:
        try:
            response = requests.get(PASSPHRASE_WORDLIST_URL, timeout=5)
            return [line.split('\t')[1] for line in response.text.splitlines() if '\t' in line]
        except Exception as e:
            logging.warning(f"Couldn't load passphrase wordlist: {str(e)}")
            return []

    def _check_breaches(self, password: str) -> int:
        """Check password against HaveIBeenPwned database"""
        sha_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha_hash[:5], sha_hash[5:]
        
        try:
            response = requests.get(f"{BREACH_CHECK_API}{prefix}", timeout=3)
            if response.status_code == 200:
                breach_count = 0
                for line in response.text.splitlines():
                    parts = line.split(':')
                    if len(parts) == 2:
                        hash_part, count_str = parts
                        if hash_part == suffix and count_str.isdigit():
                            breach_count += int(count_str)
                return breach_count
        except requests.RequestException:
            pass
        return 0

    def _detect_patterns(self, password: str) -> List[str]:
        """Identify common insecure patterns"""
        issues = []
        for pattern, description in self.common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                issues.append(description)
        return issues

    def analyze(self, password: str) -> dict:
        """Main analysis method"""
        result = {
            'length': len(password),
            'strength': 0,
            'issues': [],
            'suggestions': [],
            'breach_count': 0,
            'complexity': {
                'upper': bool(re.search(r'[A-Z]', password)),
                'lower': bool(re.search(r'[a-z]', password)),
                'digit': bool(re.search(r'\d', password)),
                'special': bool(re.search(r'[^A-Za-z0-9]', password))
            }
        }

        # Basic checks
        if len(password) < MIN_PASSWORD_LENGTH:
            result['issues'].append(f"Too short (min {MIN_PASSWORD_LENGTH} chars)")

        # External checks
        if self.weak_wordlist.contains(password):
            result['issues'].append("Common weak password")
        if self.banned_wordlist.contains(password):
            result['issues'].append("Banned password")

        # Breach check
        result['breach_count'] = self._check_breaches(password)
        if result['breach_count'] > 0:
            result['issues'].append(f"Found in {result['breach_count']} breaches")

        # Pattern detection
        result['issues'] += self._detect_patterns(password)

        # ZXCVBN analysis
        zxcvbn_result = zxcvbn(password)
        result['strength'] = zxcvbn_result['score']
        result['suggestions'] = zxcvbn_result['feedback']['suggestions']

        result['guesses'] = zxcvbn_result['guesses']
        result['crack_time_fast'] = zxcvbn_result['crack_times_display']['offline_fast_hashing_1e10_per_second']
        result['crack_time_slow'] = zxcvbn_result['crack_times_display']['offline_slow_hashing_1e4_per_second']

        # Generate complexity suggestions
        if not result['complexity']['upper']:
            result['suggestions'].append("Add uppercase letters")
        if not result['complexity']['lower']:
            result['suggestions'].append("Add lowercase letters")
        if not result['complexity']['digit']:
            result['suggestions'].append("Add numbers")
        if not result['complexity']['special']:
            result['suggestions'].append("Add special characters")

        return result

    def generate_password(self, length: int = 16, passphrase: bool = False) -> str:
        """Generate secure password"""
        if passphrase and self.passphrase_words:
            words = random.sample(self.passphrase_words, 4)
            return '-'.join(words).title() + str(random.randint(10, 99))
        
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.SystemRandom().choice(characters) for _ in range(length))

class PasswordManagerGUI(tk.Tk):
    """GUI Interface"""
    def __init__(self):
        super().__init__()
        self.title("Password Manager Pro")
        self.analyzer = PasswordStrengthAnalyzer()
        self.clipboard_timeout = None
        self.last_changed = datetime.now()
        self._create_widgets()
        self._setup_bindings()

    def _create_widgets(self):
        # Password entry
        self.entry_frame = ttk.Frame(self)
        self.entry_frame.pack(pady=10)
        
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(self.entry_frame, textvariable=self.password_var, show="*", width=30)
        self.entry.grid(row=0, column=0, padx=5)
        
        self.visibility_btn = ttk.Button(self.entry_frame, text="👁", width=3,
                                       command=self.toggle_visibility)
        self.visibility_btn.grid(row=0, column=1)

        # Strength meter
        self.strength_frame = ttk.LabelFrame(self, text="Password Strength")
        self.strength_frame.pack(pady=5, fill='x')
        
        self.strength_meter = ttk.Progressbar(self.strength_frame, orient='horizontal',
                                            length=200, mode='determinate')
        self.strength_meter.pack(pady=5)
        self.strength_label = ttk.Label(self.strength_frame, text="")
        self.strength_label.pack()

        # Analysis panel
        self.analysis_frame = ttk.LabelFrame(self, text="Security Analysis")
        self.analysis_frame.pack(pady=5, fill='both', expand=True)
        
        self.analysis_text = tk.Text(self.analysis_frame, height=8, wrap=tk.WORD)
        self.analysis_text.pack(fill='both', expand=True)

        # Control buttons
        self.btn_frame = ttk.Frame(self)
        self.btn_frame.pack(pady=10)
        
        self.check_btn = ttk.Button(self.btn_frame, text="Check", command=self.analyze_password)
        self.check_btn.grid(row=0, column=0, padx=5)
        
        self.generate_btn = ttk.Button(self.btn_frame, text="Generate",
                                      command=self.generate_password)
        self.generate_btn.grid(row=0, column=1, padx=5)
        
        self.export_btn = ttk.Button(self.btn_frame, text="Export",
                                    command=self.export_results)
        self.export_btn.grid(row=0, column=2, padx=5)

    def _setup_bindings(self):
        self.password_var.trace_add('write', self.update_real_time_feedback)
        self.bind('<Control-c>', self.copy_to_clipboard)
        self.bind('<Control-v>', self.paste_from_clipboard)

    def update_real_time_feedback(self, *args):
        analysis = self.analyzer.analyze(self.password_var.get())
        self.strength_meter['value'] = (analysis['strength'] + 1) * 20
        self.update_strength_label(analysis)
        self.update_analysis_text(analysis)

    def update_strength_label(self, analysis):
        colors = {0: 'red', 1: 'orange', 2: 'yellow', 3: 'lightgreen', 4: 'darkgreen'}
        self.strength_label.config(
            text=f"Strength: {analysis['strength']}/4",
            foreground=colors.get(analysis['strength'], 'black')
        )

    def update_analysis_text(self, analysis):
        text = []
        if analysis['issues']:
            text.append("⚠️ Issues found:")
            text.extend(f"• {issue}" for issue in analysis['issues'])
        if analysis['suggestions']:
            text.append("\n🔧 Suggestions:")
            text.extend(f"• {sug}" for sug in analysis['suggestions'])
        if analysis['breach_count'] > 0:
            text.append(f"\n🚨 This password has been found in {analysis['breach_count']} data breaches!")
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(tk.END, '\n'.join(text))

    def toggle_visibility(self):
        current_show = self.entry.cget('show')
        self.entry.config(show='' if current_show == '*' else '*')
        self.visibility_btn.config(text="👁" if current_show == '*' else "🔒")

    def generate_password(self):
        password = self.analyzer.generate_password(passphrase=random.choice([True, False]))
        self.password_var.set(password)
        self.last_changed = datetime.now()
        self.copy_to_clipboard()

    def analyze_password(self):
        password = self.password_var.get()
    
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password")
            return

        analysis = self.analyzer.analyze(password)

        self.strength_meter['value'] = (analysis['strength'] + 1) * 20
        self.update_strength_label(analysis)
        self.update_analysis_text(analysis)

    def copy_to_clipboard(self, event=None):
        self.clipboard_clear()
        self.clipboard_append(self.password_var.get())
        self.set_clipboard_timeout()

    def set_clipboard_timeout(self):
        if self.clipboard_timeout:
            self.after_cancel(self.clipboard_timeout)
        self.clipboard_timeout = self.after(
            MAX_CLIPBOARD_TIME * 1000,
            self.clear_clipboard
        )

    def clear_clipboard(self):
        self.clipboard_clear()
        messagebox.showinfo("Clipboard", "Password cleared from clipboard")

    def paste_from_clipboard(self, event=None):
        try:
            self.password_var.set(self.clipboard_get())
        except tk.TclError:
            pass

    def export_results(self):
        analysis = self.analyzer.analyze(self.password_var.get())
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(analysis, f, indent=2)
            messagebox.showinfo("Export", "Results exported successfully")

class CLIManager:
    """Command Line Interface"""
    def __init__(self):
        self.analyzer = PasswordStrengthAnalyzer()

    def run(self, args):
        if args.check:
            self.analyze_password(args.check)
        elif args.generate:
            self.generate_password(args)
        elif args.batch:
            self.process_batch(args.batch, args.format)

    def analyze_password(self, password: str):
        analysis = self.analyzer.analyze(password)
        print(f"\nPassword Analysis for '{password[:2]}...{password[-2:]}':")
        print(f"Strength: {analysis['strength']}/4")
        print(f"Length: {analysis['length']}")
        print("Issues:", ", ".join(analysis['issues']) or "None")
        print("Suggestions:", "\n- ".join(analysis['suggestions']) or "None")

    def generate_password(self, args):
        password = self.analyzer.generate_password(
            length=args.length,
            passphrase=args.passphrase
        )
        print(f"\nGenerated Password: {password}")
        self.analyze_password(password)

    def process_batch(self, file_path: str, format: str = 'text'):
        try:
            with open(file_path, 'r') as f:
                passwords = [line.strip() for line in f]
            
            results = [self.analyzer.analyze(pwd) for pwd in passwords]
            
            if format == 'json':
                print(json.dumps(results, indent=2))
            elif format == 'csv':
                self._export_csv(results)
            else:
                self._print_text_report(results)
                
        except Exception as e:
            print(f"Error processing batch: {str(e)}")

    def _export_csv(self, results):
        print("password,strength,issues")
        for res in results:
            print(f"{res['password']},{res['strength']},\"{';'.join(res['issues'])}\"")

    def _print_text_report(self, results):
        for res in results:
            print(f"\nPassword: {res['password'][:2]}...{res['password'][-2:]}")
            print(f"Strength: {res['strength']}/4 | Issues: {len(res['issues'])}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Manager",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  GUI Mode:            python password_manager.py
  Check Password:      python password_manager.py --check 'MyPassword123'
  Generate Password:   python password_manager.py --generate --length 20
  Generate Passphrase: python password_manager.py --generate --passphrase
  Batch Processing:    python password_manager.py --batch passwords.txt --format csv
  Commands Help:       python password_manager.py --help-commands"""
    )

    parser.add_argument('--check', help="Check password strength")
    parser.add_argument('--generate', action='store_true', 
                      help="Generate password/passphrase")
    parser.add_argument('--length', type=int, default=16,
                      help="Password length (default: %(default)s)")
    parser.add_argument('--passphrase', action='store_true',
                      help="Generate passphrase instead of random password")
    parser.add_argument('--batch', help="Batch process passwords from file")
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text',
                      help="Output format for batch processing (default: %(default)s)")
    parser.add_argument('--help-commands', action='store_true',
                      help="Show detailed command list and examples")

    args = parser.parse_args()

    if args.help_commands:
        print("""Available Commands:
        
  --check PASSWORD     Check strength of a specific password
  --generate           Generate new password/passphrase
  --length LENGTH      Set password length (default: 16)
  --passphrase         Generate memorable passphrase
  --batch FILE         Process multiple passwords from a file
  --format FORMAT      Output format for batch processing (text/json/csv)
  --help-commands      Show this command list
        
Examples:
  Start GUI:               python password_manager.py
  Check password:          python password_manager.py --check 'MyPass123'
  Generate strong password:python password_manager.py --generate --length 20
  Generate passphrase:     python password_manager.py --generate --passphrase
  Batch process to CSV:    python password_manager.py --batch passwords.txt --format csv""")
        sys.exit(0)

    # Check if any CLI arguments were actually provided
    cli_args_provided = any([args.check, args.generate, args.batch])
    
    if cli_args_provided:
        CLIManager().run(args)
    else:
        # Start GUI if no CLI arguments provided
        PasswordManagerGUI().mainloop()

if __name__ == "__main__":
    main()