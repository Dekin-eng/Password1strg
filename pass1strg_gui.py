"""
PASS1STRG - Password Strength Auditor GUI
Modern dark theme UI with Tkinter
No external dependencies required!
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import math
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

# ============================================================================
# PASSWORD ANALYZER ENGINE
# ============================================================================

class PasswordAnalyzer:
    """Password strength analysis engine"""
    
    COMMON_PASSWORDS = {
        '123456', 'password', '123456789', 'qwerty', 'abc123', 'password123',
        'admin', 'letmein', 'welcome', 'monkey', '12345', '12345678',
        'sunshine', 'iloveyou', 'computer', 'secret', 'passw0rd'
    }
    
    @staticmethod
    def analyze(password: str, account: str = "", username: str = "") -> Dict:
        """Analyze password strength"""
        issues = []
        suggestions = []
        score = 100
        
        # Length check
        length = len(password)
        if length < 8:
            issues.append("Too short (< 8 characters)")
            suggestions.append("Use at least 12 characters")
            score -= 30
        elif length < 10:
            issues.append("Could be longer")
            suggestions.append("Use 12+ characters")
            score -= 10
        elif length < 12:
            score -= 5
        
        # Character checks
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
        
        if not has_upper:
            issues.append("No uppercase letters")
            suggestions.append("Add uppercase (A-Z)")
            score -= 15
        if not has_lower:
            issues.append("No lowercase letters")
            suggestions.append("Add lowercase (a-z)")
            score -= 15
        if not has_digit:
            issues.append("No numbers")
            suggestions.append("Add numbers (0-9)")
            score -= 15
        if not has_symbol:
            issues.append("No special characters")
            suggestions.append("Add symbols (!@#$%^&*)")
            score -= 15
        
        # Common password check
        if password.lower() in PasswordAnalyzer.COMMON_PASSWORDS:
            issues.append("Common/weak password")
            suggestions.append("Use a unique password")
            score -= 30
        
        # Pattern checks
        if re.search(r'(.)\1{2,}', password):
            issues.append("Repeated characters")
            suggestions.append("Avoid repetition")
            score -= 10
        
        if re.search(r'12345|qwerty|asdf|zxcv|abcde', password.lower()):
            issues.append("Keyboard pattern detected")
            suggestions.append("Avoid keyboard patterns")
            score -= 15
        
        if username and password.lower() == username.lower():
            issues.append("Password matches username")
            suggestions.append("Don't use username as password")
            score -= 25
        
        score = max(0, min(100, score))
        
        # Strength label
        if score >= 80:
            strength = "Strong"
            color = "#27ae60"
        elif score >= 60:
            strength = "Moderate"
            color = "#f39c12"
        elif score >= 40:
            strength = "Weak"
            color = "#e67e22"
        else:
            strength = "Very Weak"
            color = "#e74c3c"
        
        # Crack time estimate
        if password.lower() in PasswordAnalyzer.COMMON_PASSWORDS:
            crack_time = "Instant (common password)"
        elif length < 6:
            crack_time = "Seconds"
        elif length < 8:
            crack_time = "Minutes to hours"
        elif length < 10:
            crack_time = "Days to weeks" if (has_upper and has_lower and has_digit and has_symbol) else "Years"
        elif length < 12:
            crack_time = "Years to decades"
        else:
            crack_time = "Centuries"
        
        return {
            "score": score,
            "strength": strength,
            "color": color,
            "crack_time": crack_time,
            "issues": issues,
            "suggestions": suggestions[:3],
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol
        }


# ============================================================================
# MAIN GUI APPLICATION
# ============================================================================

class Pass1strgGUI:
    """Main GUI application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PASS1STRG - Password Strength Auditor")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)
        
        # Set dark theme colors
        self.colors = {
            'bg': '#1e1e2e',
            'bg2': '#181825',
            'bg3': '#313244',
            'fg': '#cdd6f4',
            'fg_dim': '#6c7086',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'error': '#f38ba8',
            'border': '#45475a'
        }
        
        self.configure_styles()
        self.passwords = []  # Store passwords {account, username, password}
        self.results = []    # Store analysis results
        
        self.setup_ui()
        
    def configure_styles(self):
        """Configure ttk styles for dark theme"""
        self.root.configure(bg=self.colors['bg'])
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabelframe', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TLabelframe.Label', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', background=self.colors['bg3'], foreground=self.colors['fg'])
        style.configure('TEntry', fieldbackground=self.colors['bg3'], foreground=self.colors['fg'])
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Input area
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Right panel - Results area
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.setup_input_panel(left_panel)
        self.setup_results_panel(right_panel)
        
    def setup_input_panel(self, parent):
        """Setup the input panel on the left"""
        # Title
        title = tk.Label(parent, text="🔐 PASS1STRG", 
                        font=('Segoe UI', 20, 'bold'),
                        bg=self.colors['bg'], fg=self.colors['accent'])
        title.pack(pady=(0, 20))
        
        subtitle = tk.Label(parent, text="Password Strength Auditor",
                           font=('Segoe UI', 10),
                           bg=self.colors['bg'], fg=self.colors['fg_dim'])
        subtitle.pack(pady=(0, 30))
        
        # Add password frame
        add_frame = tk.LabelFrame(parent, text=" Add New Password ",
                                  bg=self.colors['bg'], fg=self.colors['fg'],
                                  font=('Segoe UI', 11, 'bold'))
        add_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Account name
        tk.Label(add_frame, text="Account Name:", bg=self.colors['bg'], 
                fg=self.colors['fg']).pack(anchor=tk.W, padx=10, pady=(10, 2))
        self.account_entry = tk.Entry(add_frame, bg=self.colors['bg3'], 
                                      fg=self.colors['fg'], insertbackground=self.colors['fg'],
                                      font=('Segoe UI', 10), relief=tk.FLAT)
        self.account_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Username
        tk.Label(add_frame, text="Username/Email:", bg=self.colors['bg'], 
                fg=self.colors['fg']).pack(anchor=tk.W, padx=10, pady=(0, 2))
        self.username_entry = tk.Entry(add_frame, bg=self.colors['bg3'],
                                       fg=self.colors['fg'], insertbackground=self.colors['fg'],
                                       font=('Segoe UI', 10), relief=tk.FLAT)
        self.username_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Password
        tk.Label(add_frame, text="Password:", bg=self.colors['bg'],
                fg=self.colors['fg']).pack(anchor=tk.W, padx=10, pady=(0, 2))
        
        password_frame = tk.Frame(add_frame, bg=self.colors['bg'])
        password_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        self.password_entry = tk.Entry(password_frame, bg=self.colors['bg3'],
                                       fg=self.colors['fg'], insertbackground=self.colors['fg'],
                                       font=('Segoe UI', 10), relief=tk.FLAT, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_pwd_var = tk.BooleanVar()
        self.show_check = tk.Checkbutton(password_frame, text="Show", 
                                         variable=self.show_pwd_var,
                                         command=self.toggle_password_visibility,
                                         bg=self.colors['bg'], fg=self.colors['fg_dim'],
                                         selectcolor=self.colors['bg'])
        self.show_check.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Add button
        self.add_btn = tk.Button(add_frame, text="➕ Add Password",
                                 command=self.add_password,
                                 bg=self.colors['accent'], fg='white',
                                 font=('Segoe UI', 10, 'bold'),
                                 relief=tk.FLAT, cursor='hand2')
        self.add_btn.pack(fill=tk.X, padx=10, pady=(10, 10))
        
        # Live strength meter
        self.password_entry.bind('<KeyRelease>', self.update_live_strength)
        
        # Live strength display
        self.live_strength_frame = tk.LabelFrame(parent, text=" Live Password Strength ",
                                                  bg=self.colors['bg'], fg=self.colors['fg'],
                                                  font=('Segoe UI', 10, 'bold'))
        self.live_strength_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.live_score_label = tk.Label(self.live_strength_frame, text="Score: --/100",
                                         bg=self.colors['bg'], font=('Segoe UI', 12, 'bold'))
        self.live_score_label.pack(pady=(10, 5))
        
        self.live_strength_label = tk.Label(self.live_strength_frame, text="",
                                            bg=self.colors['bg'], font=('Segoe UI', 10))
        self.live_strength_label.pack()
        
        self.live_issues_text = tk.Text(self.live_strength_frame, height=5,
                                        bg=self.colors['bg2'], fg=self.colors['fg_dim'],
                                        font=('Segoe UI', 9), relief=tk.FLAT, wrap=tk.WORD)
        self.live_issues_text.pack(fill=tk.X, padx=10, pady=(5, 10))
        
        # Sample data button
        sample_btn = tk.Button(parent, text="📁 Load Sample Data",
                               command=self.load_sample_data,
                               bg=self.colors['bg3'], fg=self.colors['fg'],
                               font=('Segoe UI', 10), relief=tk.FLAT, cursor='hand2')
        sample_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Clear all button
        clear_btn = tk.Button(parent, text="🗑️ Clear All Passwords",
                              command=self.clear_all,
                              bg=self.colors['error'], fg='white',
                              font=('Segoe UI', 10), relief=tk.FLAT, cursor='hand2')
        clear_btn.pack(fill=tk.X)
        
    def setup_results_panel(self, parent):
        """Setup the results panel on the right"""
        # Statistics frame
        stats_frame = tk.LabelFrame(parent, text=" Statistics ",
                                    bg=self.colors['bg'], fg=self.colors['fg'],
                                    font=('Segoe UI', 11, 'bold'))
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Text(stats_frame, height=6,
                                  bg=self.colors['bg2'], fg=self.colors['fg'],
                                  font=('Segoe UI', 10), relief=tk.FLAT)
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Password list frame
        list_frame = tk.LabelFrame(parent, text=" Password List ",
                                   bg=self.colors['bg'], fg=self.colors['fg'],
                                   font=('Segoe UI', 11, 'bold'))
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview for password list
        columns = ('Account', 'Username', 'Score', 'Strength')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        self.tree.heading('Account', text='Account')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Score', text='Score')
        self.tree.heading('Strength', text='Strength')
        
        self.tree.column('Account', width=120)
        self.tree.column('Username', width=150)
        self.tree.column('Score', width=60)
        self.tree.column('Strength', width=80)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self.on_password_select)
        
        # Audit button
        self.audit_btn = tk.Button(parent, text="🔍 Run Full Audit",
                                   command=self.run_audit,
                                   bg=self.colors['success'], fg='#1e1e2e',
                                   font=('Segoe UI', 12, 'bold'),
                                   relief=tk.FLAT, cursor='hand2')
        self.audit_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Report button
        self.report_btn = tk.Button(parent, text="📄 Generate Report",
                                    command=self.generate_report,
                                    bg=self.colors['accent'], fg='white',
                                    font=('Segoe UI', 11, 'bold'),
                                    relief=tk.FLAT, cursor='hand2')
        self.report_btn.pack(fill=tk.X)
        
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_pwd_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def update_live_strength(self, event=None):
        """Update live strength meter while typing"""
        password = self.password_entry.get()
        if not password:
            self.live_score_label.config(text="Score: --/100", fg=self.colors['fg_dim'])
            self.live_strength_label.config(text="")
            self.live_issues_text.delete(1.0, tk.END)
            return
        
        result = PasswordAnalyzer.analyze(password)
        
        self.live_score_label.config(text=f"Score: {result['score']}/100", fg=result['color'])
        self.live_strength_label.config(text=f"Strength: {result['strength']}", fg=result['color'])
        
        self.live_issues_text.delete(1.0, tk.END)
        if result['issues']:
            self.live_issues_text.insert(1.0, "Issues:\n• " + "\n• ".join(result['issues']))
        else:
            self.live_issues_text.insert(1.0, "✓ No issues found! Good password!")
    
    def add_password(self):
        """Add a password to the list"""
        account = self.account_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not account:
            messagebox.showwarning("Missing Info", "Please enter an account name")
            return
        if not password:
            messagebox.showwarning("Missing Info", "Please enter a password")
            return
        
        # Analyze password
        result = PasswordAnalyzer.analyze(password, account, username)
        
        # Store
        self.passwords.append({
            "account": account,
            "username": username,
            "password": password
        })
        self.results.append(result)
        
        # Add to treeview
        self.tree.insert('', tk.END, values=(
            account,
            username[:20] + "..." if len(username) > 20 else username,
            f"{result['score']}/100",
            result['strength']
        ))
        
        # Clear entries
        self.account_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.show_pwd_var.set(False)
        self.password_entry.config(show="•")
        
        # Update statistics
        self.update_statistics()
        
        messagebox.showinfo("Success", f"Added password for {account}")
    
    def update_statistics(self):
        """Update statistics display"""
        if not self.results:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, "No passwords added yet.")
            return
        
        total = len(self.results)
        avg_score = sum(r['score'] for r in self.results) / total
        
        strong = sum(1 for r in self.results if r['strength'] == 'Strong')
        moderate = sum(1 for r in self.results if r['strength'] == 'Moderate')
        weak = sum(1 for r in self.results if r['strength'] == 'Weak')
        very_weak = sum(1 for r in self.results if r['strength'] == 'Very Weak')
        
        stats_text = f"""
📊 Total Passwords: {total}
⭐ Average Score: {avg_score:.1f}/100
✅ Strong: {strong}  |  ⚠️ Moderate: {moderate}
🔴 Weak: {weak}  |  💀 Very Weak: {very_weak}
        """
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)
    
    def on_password_select(self, event):
        """Handle password selection from treeview"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        values = item['values']
        if not values:
            return
        
        # Find the password in the list
        account_name = values[0]
        for i, pwd in enumerate(self.passwords):
            if pwd['account'] == account_name:
                result = self.results[i]
                
                # Show details in a popup
                self.show_password_details(pwd, result)
                break
    
    def show_password_details(self, password, result):
        """Show detailed password analysis in a popup"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Password Details - {password['account']}")
        detail_window.geometry("500x500")
        detail_window.configure(bg=self.colors['bg'])
        detail_window.minsize(400, 400)
        
        # Center the window
        detail_window.transient(self.root)
        detail_window.grab_set()
        
        # Content
        frame = tk.Frame(detail_window, bg=self.colors['bg'])
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(frame, text=f"🔐 {password['account']}",
                        font=('Segoe UI', 16, 'bold'),
                        bg=self.colors['bg'], fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        # Username
        tk.Label(frame, text=f"Username: {password['username']}",
                bg=self.colors['bg'], fg=self.colors['fg'],
                font=('Segoe UI', 10)).pack(anchor=tk.W, pady=2)
        
        # Score
        score_frame = tk.Frame(frame, bg=self.colors['bg'])
        score_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(score_frame, text="Security Score:",
                bg=self.colors['bg'], fg=self.colors['fg'],
                font=('Segoe UI', 11, 'bold')).pack(side=tk.LEFT)
        
        score_label = tk.Label(score_frame, text=f"{result['score']}/100",
                               bg=self.colors['bg'], fg=result['color'],
                               font=('Segoe UI', 14, 'bold'))
        score_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Strength
        strength_label = tk.Label(frame, text=f"Strength: {result['strength']}",
                                  bg=self.colors['bg'], fg=result['color'],
                                  font=('Segoe UI', 12, 'bold'))
        strength_label.pack(anchor=tk.W, pady=5)
        
        # Crack time
        tk.Label(frame, text=f"Estimated crack time: {result['crack_time']}",
                bg=self.colors['bg'], fg=self.colors['fg_dim'],
                font=('Segoe UI', 10)).pack(anchor=tk.W, pady=5)
        
        # Separator
        tk.Frame(frame, height=2, bg=self.colors['border']).pack(fill=tk.X, pady=10)
        
        # Issues
        tk.Label(frame, text="Issues Found:",
                bg=self.colors['bg'], fg=self.colors['error'],
                font=('Segoe UI', 11, 'bold')).pack(anchor=tk.W)
        
        issues_text = tk.Text(frame, height=5, bg=self.colors['bg2'],
                              fg=self.colors['fg'], font=('Segoe UI', 9),
                              relief=tk.FLAT, wrap=tk.WORD)
        issues_text.pack(fill=tk.X, pady=(5, 10))
        
        if result['issues']:
            issues_text.insert(1.0, "• " + "\n• ".join(result['issues']))
        else:
            issues_text.insert(1.0, "✓ No issues found!")
        issues_text.config(state=tk.DISABLED)
        
        # Suggestions
        tk.Label(frame, text="Suggestions:",
                bg=self.colors['bg'], fg=self.colors['success'],
                font=('Segoe UI', 11, 'bold')).pack(anchor=tk.W)
        
        suggestions_text = tk.Text(frame, height=4, bg=self.colors['bg2'],
                                   fg=self.colors['fg'], font=('Segoe UI', 9),
                                   relief=tk.FLAT, wrap=tk.WORD)
        suggestions_text.pack(fill=tk.X, pady=(5, 10))
        
        if result['suggestions']:
            suggestions_text.insert(1.0, "→ " + "\n→ ".join(result['suggestions']))
        else:
            suggestions_text.insert(1.0, "✓ Password looks good!")
        suggestions_text.config(state=tk.DISABLED)
        
        # Close button
        close_btn = tk.Button(frame, text="Close",
                              command=detail_window.destroy,
                              bg=self.colors['accent'], fg='white',
                              font=('Segoe UI', 10, 'bold'),
                              relief=tk.FLAT, cursor='hand2')
        close_btn.pack(pady=(10, 0))
    
    def load_sample_data(self):
        """Load sample passwords for testing"""
        sample_data = [
            {"account": "Gmail", "username": "user@gmail.com", "password": "password123"},
            {"account": "GitHub", "username": "developer", "password": "GitHub@2024Secure"},
            {"account": "Facebook", "username": "john_doe", "password": "john1985"},
            {"account": "Bank of America", "username": "jdoe", "password": "SuperStr0ngP@ss"},
            {"account": "Netflix", "username": "johndoe@email.com", "password": "123456"},
            {"account": "Work Email", "username": "john.doe@company.com", "password": "Winter2024"},
        ]
        
        for item in sample_data:
            result = PasswordAnalyzer.analyze(item['password'], item['account'], item['username'])
            self.passwords.append(item)
            self.results.append(result)
            self.tree.insert('', tk.END, values=(
                item['account'],
                item['username'][:20] + "..." if len(item['username']) > 20 else item['username'],
                f"{result['score']}/100",
                result['strength']
            ))
        
        self.update_statistics()
        messagebox.showinfo("Success", f"Loaded {len(sample_data)} sample passwords")
    
    def clear_all(self):
        """Clear all passwords"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all passwords?"):
            self.passwords = []
            self.results = []
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.update_statistics()
            messagebox.showinfo("Success", "All passwords cleared")
    
    def run_audit(self):
        """Run full audit and show summary"""
        if not self.results:
            messagebox.showwarning("No Data", "Please add passwords first")
            return
        
        total = len(self.results)
        avg_score = sum(r['score'] for r in self.results) / total
        strong = sum(1 for r in self.results if r['strength'] == 'Strong')
        moderate = sum(1 for r in self.results if r['strength'] == 'Moderate')
        weak = sum(1 for r in self.results if r['strength'] == 'Weak')
        very_weak = sum(1 for r in self.results if r['strength'] == 'Very Weak')
        
        # Check for reused passwords
        passwords_list = [p['password'] for p in self.passwords]
        reused = len(passwords_list) - len(set(passwords_list))
        
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                    AUDIT SUMMARY                             ║
╠══════════════════════════════════════════════════════════════╣
║  Total Passwords Analyzed: {total:<43} ║
║  Average Security Score: {avg_score:.1f}/100{' ' * 39} ║
║                                                              ║
║  Strength Distribution:                                     ║
║    ✅ Strong: {strong:<41} ║
║    ⚠️  Moderate: {moderate:<40} ║
║    🔴 Weak: {weak:<43} ║
║    💀 Very Weak: {very_weak:<40} ║
║                                                              ║
║  🔁 Reused Passwords: {reused:<44} ║
║                                                              ║
║  Recommendations:                                           ║
║    1. Use unique passwords for every account                ║
║    2. Create passwords with 12+ characters                  ║
║    3. Include all character types                           ║
║    4. Enable 2FA wherever possible                          ║
╚══════════════════════════════════════════════════════════════╝
        """
        
        messagebox.showinfo("Audit Summary", summary)
    
    def generate_report(self):
        """Generate and save report"""
        if not self.results:
            messagebox.showwarning("No Data", "Please add passwords first")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pass1strg_report_{timestamp}.txt"
        
        total = len(self.results)
        avg_score = sum(r['score'] for r in self.results) / total
        strong = sum(1 for r in self.results if r['strength'] == 'Strong')
        moderate = sum(1 for r in self.results if r['strength'] == 'Moderate')
        weak = sum(1 for r in self.results if r['strength'] == 'Weak')
        very_weak = sum(1 for r in self.results if r['strength'] == 'Very Weak')
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("PASS1STRG - PASSWORD SECURITY AUDIT REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Passwords: {total}\n")
            f.write(f"Average Score: {avg_score:.1f}/100\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("DETAILED RESULTS\n")
            f.write("-" * 70 + "\n")
            
            for i, (pwd, result) in enumerate(zip(self.passwords, self.results), 1):
                f.write(f"\n{i}. {pwd['account']}\n")
                f.write(f"   Username: {pwd['username']}\n")
                f.write(f"   Score: {result['score']}/100 ({result['strength']})\n")
                f.write(f"   Crack Time: {result['crack_time']}\n")
                if result['issues']:
                    f.write(f"   Issues: {', '.join(result['issues'])}\n")
                if result['suggestions']:
                    f.write(f"   Suggestions: {', '.join(result['suggestions'])}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 70 + "\n")
            f.write("1. Use unique passwords for every account\n")
            f.write("2. Create passwords with 12+ characters\n")
            f.write("3. Include uppercase, lowercase, numbers, and symbols\n")
            f.write("4. Use a password manager\n")
            f.write("5. Enable two-factor authentication (2FA)\n")
        
        messagebox.showinfo("Report Saved", f"Report saved as:\n{filename}")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    app = Pass1strgGUI()
    app.run()