#!/usr/bin/env python3
"""
PASS1STRG - Password Strength Auditor
Working Version - No syntax errors
"""

import re
import math
import json
from datetime import datetime
from pathlib import Path

import pass1strg_gui

# ============================================================================
# PASSWORD ANALYZER
# ============================================================================

class PasswordAnalyzer:
    """Simple password strength analyzer"""
    
    # Common weak passwords to check
    COMMON_PASSWORDS = {
        '123456', 'password', '123456789', 'qwerty', 'abc123', 'password123',
        'admin', 'letmein', 'welcome', 'monkey', '12345', '12345678',
        'sunshine', 'iloveyou', 'computer', 'secret', 'passw0rd'
    }
    
    def __init__(self):
        self.passwords = []
        self.results = []
    
    def analyze(self, password, account="", username=""):
        """Analyze a single password"""
        issues = []
        suggestions = []
        score = 100  # Start at 100, subtract for issues
        
        # Length check
        length = len(password)
        if length < 8:
            issues.append("Too short (less than 8 characters)")
            suggestions.append("Use at least 12 characters")
            score -= 30
        elif length < 10:
            issues.append("Could be longer")
            suggestions.append("Use 12+ characters for better security")
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
            suggestions.append("Add uppercase letters (A-Z)")
            score -= 15
        if not has_lower:
            issues.append("No lowercase letters")
            suggestions.append("Add lowercase letters (a-z)")
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
        if password.lower() in self.COMMON_PASSWORDS:
            issues.append("Common/weak password")
            suggestions.append("Use a unique, random password")
            score -= 30
        
        # Pattern checks
        if re.search(r'(.)\1{2,}', password):
            issues.append("Contains repeated characters")
            suggestions.append("Avoid repeating the same character")
            score -= 10
        
        if re.search(r'12345|qwerty|asdf|zxcv|abcde', password.lower()):
            issues.append("Contains keyboard pattern")
            suggestions.append("Avoid sequential keyboard patterns")
            score -= 15
        
        if username and password.lower() == username.lower():
            issues.append("Password matches username")
            suggestions.append("Never use username as password")
            score -= 25
        
        # Ensure score is between 0-100
        score = max(0, min(100, score))
        
        # Determine strength
        if score >= 80:
            strength = "Strong"
            emoji = "[+]"
        elif score >= 60:
            strength = "Moderate"
            emoji = "[!]"
        elif score >= 40:
            strength = "Weak"
            emoji = "[-]"
        else:
            strength = "Very Weak"
            emoji = "[X]"
        
        # Calculate crack time estimate
        crack_time = self._estimate_crack_time(password, has_upper, has_lower, has_digit, has_symbol)
        
        return {
            "account": account,
            "username": username,
            "password_masked": "*" * min(8, length) + ("..." if length > 8 else ""),
            "score": score,
            "strength": strength,
            "emoji": emoji,
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "crack_time": crack_time,
            "issues": issues,
            "suggestions": suggestions[:3]
        }
    
    def _estimate_crack_time(self, password, has_upper, has_lower, has_digit, has_symbol):
        """Estimate time to crack password"""
        if password.lower() in self.COMMON_PASSWORDS:
            return "Instant (common password)"
        
        length = len(password)
        if length < 6:
            return "Seconds"
        elif length < 8:
            return "Minutes to hours"
        elif length < 10:
            if has_upper and has_lower and has_digit and has_symbol:
                return "Years"
            else:
                return "Days to weeks"
        elif length < 12:
            return "Years to decades"
        else:
            return "Centuries"
    
    def add_password(self, account, username, password):
        """Add a password to analyze"""
        result = self.analyze(password, account, username)
        self.passwords.append({
            "account": account,
            "username": username,
            "password": password
        })
        self.results.append(result)
        return result
    
    def check_reuse(self):
        """Check for password reuse"""
        seen = {}
        reuse_count = 0
        for pwd in self.passwords:
            pwd_str = pwd["password"]
            if pwd_str in seen:
                seen[pwd_str] += 1
            else:
                seen[pwd_str] = 1
        
        for i, result in enumerate(self.results):
            pwd_str = self.passwords[i]["password"]
            count = seen[pwd_str]
            result["reuse_count"] = count
            if count > 1:
                reuse_count += 1
        
        return reuse_count
    
    def get_stats(self):
        """Get overall statistics"""
        if not self.results:
            return {}
        
        total = len(self.results)
        avg_score = sum(r["score"] for r in self.results) / total
        
        strength_counts = {"Strong": 0, "Moderate": 0, "Weak": 0, "Very Weak": 0}
        for r in self.results:
            strength_counts[r["strength"]] += 1
        
        return {
            "total": total,
            "average_score": round(avg_score, 1),
            "strong": strength_counts["Strong"],
            "moderate": strength_counts["Moderate"],
            "weak": strength_counts["Weak"],
            "very_weak": strength_counts["Very Weak"],
            "compliance_rate": round((strength_counts["Strong"] + strength_counts["Moderate"]) / total * 100, 1)
        }


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate audit reports"""
    
    @staticmethod
    def print_report(results, stats):
        """Print formatted report to console"""
        print("\n" + "=" * 70)
        print(" PASS1STRG - PASSWORD AUDIT REPORT")
        print("=" * 70)
        print(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f" Total Passwords: {stats['total']}")
        print(f" Average Score: {stats['average_score']}/100")
        print(f" Compliance Rate: {stats['compliance_rate']}%")
        print()
        
        # Strength distribution bar chart
        print(" STRENGTH DISTRIBUTION:")
        print("-" * 40)
        labels = ["Strong", "Moderate", "Weak", "Very Weak"]
        counts = [stats['strong'], stats['moderate'], stats['weak'], stats['very_weak']]
        for label, count in zip(labels, counts):
            bar = "#" * count if count > 0 else ""
            print(f"  {label:10}: {count:2} {bar}")
        print()
        
        # Detailed results
        print(" DETAILED RESULTS:")
        print("-" * 70)
        
        for r in results:
            print(f"\n{r['emoji']} {r['account'] or 'Unnamed'}")
            print(f"   Score: {r['score']}/100 ({r['strength']})")
            print(f"   Length: {r['length']} chars")
            print(f"   Crack time: {r['crack_time']}")
            
            if r.get('reuse_count', 1) > 1:
                print(f"   [!] Reused {r['reuse_count']} times")
            
            if r['issues']:
                print(f"   Issues:")
                for issue in r['issues']:
                    print(f"     - {issue}")
            
            if r['suggestions']:
                print(f"   Suggestions:")
                for sug in r['suggestions']:
                    print(f"     -> {sug}")
        
        # Recommendations
        print("\n" + "=" * 70)
        print(" RECOMMENDATIONS")
        print("=" * 70)
        print("1. Use unique passwords for every account")
        print("2. Create passwords with 12+ characters")
        print("3. Include uppercase, lowercase, numbers, and symbols")
        print("4. Use a password manager (Bitwarden, 1Password, etc.)")
        print("5. Enable two-factor authentication (2FA) everywhere possible")
        print("=" * 70)
    
    @staticmethod
    def save_html_report(results, stats, filename="pass1strg_report.html"):
        """Save report as HTML file"""
        rows = ""
        for r in results:
            score_color = "green" if r["score"] >= 70 else "orange" if r["score"] >= 50 else "red"
            rows += f"""
            <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;">{r['emoji']}</td>
                <td style="padding: 10px;"><strong>{r['account'] or '-'}</strong></td>
                <td style="padding: 10px;">{r['username'] or '-'}</td>
                <td style="padding: 10px; color: {score_color}; font-weight: bold;">{r['score']}</td>
                <td style="padding: 10px;">{r['strength']}</td>
                <td style="padding: 10px;">{r['length']}</td>
                <td style="padding: 10px; font-size: 0.85em;">{', '.join(r['issues'][:2]) if r['issues'] else 'None'}</td>
            </tr>
            """
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PASS1STRG - Password Audit Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            overflow: hidden;
        }}
        .header {{
            background: #667eea;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            padding: 20px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 15px;
            text-align: center;
            color: #666;
        }}
        .recommendations {{
            background: #e8f5e9;
            padding: 20px;
            margin: 20px;
            border-radius: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> PASS1STRG - Password Audit Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{stats['total']}</div>
                <div>Passwords</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['average_score']}</div>
                <div>Avg Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['compliance_rate']}%</div>
                <div>Compliance</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['strong']}</div>
                <div>Strong</div>
            </div>
        </div>
        
        <div style="overflow-x: auto; padding: 20px;">
            <h3>Detailed Results</h3>
            <table>
                <thead>
                    <tr>
                        <th></th><th>Account</th><th>Username</th><th>Score</th><th>Strength</th><th>Length</th><th>Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        
        <div class="recommendations">
            <h3>Security Recommendations</h3>
            <ul>
                <li>Use unique passwords for every account</li>
                <li>Create passwords with 12+ characters</li>
                <li>Include uppercase, lowercase, numbers, and symbols</li>
                <li>Enable two-factor authentication (2FA)</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>PASS1STRG - Password Strength Auditor</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename
    
    @staticmethod
    def save_text_report(results, stats, filename="pass1strg_report.txt"):
        """Save report as text file"""
        lines = []
        lines.append("=" * 70)
        lines.append("PASS1STRG - PASSWORD AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Passwords: {stats['total']}")
        lines.append(f"Average Score: {stats['average_score']}/100")
        lines.append(f"Compliance Rate: {stats['compliance_rate']}%")
        lines.append("")
        lines.append("-" * 70)
        lines.append("DETAILED RESULTS")
        lines.append("-" * 70)
        
        for r in results:
            lines.append(f"\n{r['emoji']} {r['account'] or 'Unnamed'}")
            lines.append(f"   Score: {r['score']}/100 ({r['strength']})")
            lines.append(f"   Length: {r['length']} chars")
            lines.append(f"   Crack time: {r['crack_time']}")
            if r['issues']:
                lines.append(f"   Issues: {', '.join(r['issues'])}")
            if r['suggestions']:
                lines.append(f"   Suggestions: {', '.join(r['suggestions'])}")
        
        lines.append("")
        lines.append("=" * 70)
        lines.append("RECOMMENDATIONS")
        lines.append("=" * 70)
        lines.append("1. Use unique passwords for every account")
        lines.append("2. Create passwords with 12+ characters")
        lines.append("3. Include uppercase, lowercase, numbers, and symbols")
        lines.append("4. Use a password manager")
        lines.append("5. Enable two-factor authentication (2FA)")
        lines.append("=" * 70)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return filename


# ============================================================================
# SAMPLE DATA
# ============================================================================

def get_sample_passwords():
    """Get sample passwords for testing"""
    return [
        {"account": "Gmail", "username": "user@gmail.com", "password": "password123"},
        {"account": "GitHub", "username": "developer", "password": "GitHub@2024Secure"},
        {"account": "Facebook", "username": "john_doe", "password": "john1985"},
        {"account": "Bank", "username": "jdoe", "password": "SuperStr0ngP@ss"},
        {"account": "Netflix", "username": "johndoe@email.com", "password": "123456"},
        {"account": "Work Email", "username": "john.doe@company.com", "password": "Winter2024"},
    ]


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def clear_screen():
    """Clear console screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print program banner"""
    print("""
============================================================
                                                            
     PASS1STRG - Password Strength Auditor                 
     Analyze | Detect Weaknesses | Generate Reports        
                                                            
============================================================
    """)


def main():
    """Main program loop"""
    analyzer = PasswordAnalyzer()
    report_gen = ReportGenerator()
    
    while True:
        clear_screen()
        print_banner()
        
        print("\n MAIN MENU")
        print("-" * 50)
        print("  1. Add passwords manually")
        print("  2. Load sample data (for testing)")
        print("  3. Run audit & generate reports")
        print("  4. View current passwords")
        print("  5. Clear all passwords")
        print("  6. Exit")
        print("-" * 50)
        
        choice = input("\n Select option (1-6): ").strip()
        
        if choice == '1':
            clear_screen()
            print("\n ADD PASSWORDS MANUALLY")
            print("-" * 40)
            print("Type 'quit' as account name to finish\n")
            
            while True:
                account = input("Account name: ").strip()
                if account.lower() == 'quit':
                    break
                if not account:
                    print("   Account name cannot be empty\n")
                    continue
                
                username = input("Username/Email: ").strip()
                password = input("Password: ").strip()
                
                if not password:
                    print("   Password cannot be empty\n")
                    continue
                
                result = analyzer.add_password(account, username, password)
                print(f"\n   Added: {account}")
                print(f"   Score: {result['score']}/100 ({result['strength']})")
                if result['issues']:
                    print(f"   Issues: {result['issues'][0]}")
                print()
            
            input("\nPress Enter to continue...")
        
        elif choice == '2':
            clear_screen()
            print("\n LOADING SAMPLE DATA")
            print("-" * 40)
            
            sample_data = get_sample_passwords()
            for item in sample_data:
                analyzer.add_password(item["account"], item["username"], item["password"])
            
            print(f"\n Loaded {len(sample_data)} sample passwords")
            input("\nPress Enter to continue...")
        
        elif choice == '3':
            if not analyzer.results:
                clear_screen()
                print("\n No passwords to analyze!")
                print("   Please add passwords first (option 1 or 2)")
                input("\nPress Enter to continue...")
                continue
            
            clear_screen()
            print("\n RUNNING SECURITY AUDIT")
            print("-" * 40)
            
            # Check for password reuse
            analyzer.check_reuse()
            stats = analyzer.get_stats()
            
            # Display report
            report_gen.print_report(analyzer.results, stats)
            
            # Save reports
            print("\n SAVING REPORTS...")
            html_file = report_gen.save_html_report(analyzer.results, stats)
            txt_file = report_gen.save_text_report(analyzer.results, stats)
            
            print(f"   HTML report: {html_file}")
            print(f"   Text report: {txt_file}")
            
            input("\nPress Enter to continue...")
        
        elif choice == '4':
            clear_screen()
            print("\n CURRENT PASSWORDS")
            print("-" * 50)
            
            if not analyzer.results:
                print("\n   No passwords added yet.")
            else:
                for i, r in enumerate(analyzer.results, 1):
                    print(f"\n   {i}. {r['emoji']} {r['account']}")
                    print(f"      Username: {r['username'] or '(none)'}")
                    print(f"      Score: {r['score']}/100 ({r['strength']})")
                    if r.get('reuse_count', 1) > 1:
                        print(f"      Reused {r['reuse_count']} times")
            
            input("\nPress Enter to continue...")
        
        elif choice == '5':
            clear_screen()
            confirm = input("\n Clear all passwords? (yes/no): ").strip().lower()
            if confirm == 'yes':
                analyzer.passwords = []
                analyzer.results = []
                print("\n All passwords cleared!")
            else:
                print("\n Cancelled.")
            input("\nPress Enter to continue...")
        
        elif choice == '6':
            print("\n Goodbye! Stay secure! \n")
            break
        
        else:
            print("\n Invalid option! Please choose 1-6")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    app = pass1strg_gui.Pass1strgGUI()
    app.run()