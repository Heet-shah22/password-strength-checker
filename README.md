# MIT - World Peace University
## Department of CSE (Cyber Security and Forensics)
### College Project: PASSWORD STRENGTH CHECKING

**Author**: Ativeer Rajawat  
**Roll No**: 35  
**PRN**: 1262243024  
**Academic Year**: 2026–27  
**Degree**: B.Tech CSE (Cyber Security and Forensics)

---

## 📌 Project Executive Summary
This repository contains the complete implementation, automated test suite, interactive cyber threat sandbox, and academic defense platform for the College Project Report entitled **"Password Strength Checking"** submitted to MIT – World Peace University.

### Key Conceptual Contributions from the Report:
1. **Dispelling the Complexity Fallacy (Section 2.1 & 5.1)**:
   Demonstrates why mechanical character diversity (e.g. uppercase + lowercase + number + symbol) does not guarantee security when predictable patterns exist (such as `Password@123`).
2. **Transparent Heuristic Evaluation Engine (Section 7.1 & 9)**:
   Multi-factor scoring (+1 for length $\ge 8$, +2 for length $\ge 12$, +1 each for lowercase, uppercase, digits, symbols, with penalties for common blocklists, repetition triples, sequential keyboard walks, and predictable root words).
3. **Information-Theoretic Entropy vs Practical Unpredictability (Section 3.3 & 10.1)**:
   Compares Shannon entropy ($H = L \times \log_2(N)$) with real-world attacker dictionaries and Hashcat mask rules.
4. **Controlled Academic Test Matrix Verification (Section 11 Table)**:
   100% automated alignment across all 10 representative test cases (TC01 through TC10).
5. **NIST SP 800-63B Passphrase Generator (Section 14 & 15)**:
   Modern Diceware-style memorable passphrase generation with customizable entropy.

---

## 🚀 Quick Start Guide

### Option 1: 1-Click Launchers (Windows)
- **Launch Interactive Web Simulation**: Double-click `run_simulation.bat`
- **Run Section 11 Automated Test Verification**: Double-click `run_tests.bat`
- **Deploy to Google Firebase Hosting**: Double-click `deploy_google.bat`
- **Deploy to Vercel**: Double-click `deploy_vercel.bat` (Live: `https://password-strength-checker-mit-wpu.vercel.app`)

---

### Option 2: Web Application (Node.js Server)
The local zero-dependency server is active at **[http://localhost:3000](http://localhost:3000)**.

To restart the server at any time:
```bash
npm start
# or: node server.js
```
Open **`http://localhost:3000`** (or double-click `index.html`) in any browser.

#### Web Platform Features:
1. **Interactive Password Analyzer (Tab 1)**:
   - Live character-by-character analysis with dynamic meter and educational badges (Very Weak, Weak, Medium, Strong, Very Strong).
   - Scoring criteria audit checklist showing exact points added or subtracted per Table 7.1.
   - Section 4.9 Target Personal Context Inspector (testing personal names, birth years, and college tags).
   - 8 one-click presets from the report (`123456`, `password`, `qwerty`, `Password123`, `Password@123`, `Ativeer123`, `Welcome@2026`, `Rain!Cedar7Moon#42`).
   - Print / Export official academic evaluation sheet formatted for faculty submission.
2. **Section 11 Test Matrix (Tab 2)**:
   - Interactive verification table for TC01–TC10 with 1-click execution and pass/align status.
   - Load buttons to immediately transfer any test case to the live analyzer.
3. **Attack Sandbox Simulator (Tab 3)**:
   - Visual terminal with sound effects simulating Dictionary, Hashcat Pattern Mask, and Brute-force attacks.
   - Real-world time-to-crack matrix across 4 hardware tiers (Rate-limited API, Unthrottled web, 8x RTX 4090 GPU rig, Supercomputer).
4. **Entropy vs Heuristic Lab (Tab 4)**:
   - Interactive Shannon entropy calculator ($H = L \times \log_2(N)$) with live keyspace counters.
   - Direct comparison experiment between `Password@123` and `Rain!Cedar7Moon#42`.
5. **NIST Passphrase Generator (Tab 5)**:
   - Generates high-entropy multi-word passphrases adhering to NIST SP 800-63B guidelines.
6. **Full Report Reference (Tab 6)**:
   - Complete 14-section interactive documentation accordion reflecting the entire 18-page project report.

---

### Option 3: Terminal CLI Execution

#### Run Automated Test Verification:
```bash
npm test
# or: node password_checker.js --test
```

#### Evaluate Any Password Directly:
```bash
node password_checker.js "Password@123"
node password_checker.js "Rain!Cedar7Moon#42"
```

#### Python Implementation (Section 9):
If a Python environment is available:
```bash
# Interactive CLI
python password_checker.py

# Automated Test Suite (Section 11)
python test_suite.py
```

---

## 📊 Section 11 Test Matrix Verification Results

Both the Calibrated Engine and Literal Section 9 script are supported and verified:

| Test ID | Input Password | Characteristics Tested | Expected Rating | Simulated Score | Actual Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC01** | `123456` | Short; sequential digits | Very Weak | 0 / 10 | **Very Weak** | ✓ PASS |
| **TC02** | `password` | Common lowercase word | Very Weak | 0 / 10 | **Very Weak** | ✓ PASS |
| **TC03** | `qwerty` | Keyboard pattern | Very Weak | 0 / 10 | **Very Weak** | ✓ PASS |
| **TC04** | `Password123` | Common word + digits | Weak | 3 / 10 | **Weak** | ✓ PASS |
| **TC05** | `Password@123` | Word + symbol + digits | Medium | 6 / 10 | **Medium** | ✓ PASS |
| **TC06** | `Ativeer123` | Name + digits | Weak / Medium | 4 / 10 | **Weak** | ✓ PASS |
| **TC07** | `Welcome@2026` | Common word + year | Medium | 6 / 10 | **Medium** | ✓ PASS |
| **TC08** | `Aaa111!!!` | Repeated characters | Weak | 4 / 10 | **Weak** | ✓ PASS |
| **TC09** | `abcDEF123` | Sequence + digits | Weak / Medium | 3 / 10 | **Weak** | ✓ PASS |
| **TC10** | `Rain!Cedar7Moon#42` | Long varied example | Strong / Very Strong | 8 / 10 | **Strong** | ✓ PASS |

**Test Matrix Alignment: 10 / 10 (100% Passed)**

---

## 🎓 Viva & Project Defense FAQ

### Q1: Why does `Password@123` receive a "Medium" (Score: 6) instead of "Strong"?
> **Defense**: As explained in Section 5.1 and Section 12.1 of our report, `Password@123` satisfies character diversity rules (uppercase, lowercase, number, symbol), but the underlying base word *"password"* and the suffix *"@123"* are among the most common predictable patterns in credential leaks. An attacker using a mask attack (`?u?l... + ?s?d?d?d`) cracks it in milliseconds. Our calibrated engine deducts 1 point for predictable root word construction, placing it accurately at Score 6 (Medium), exactly matching Section 12.2 Sample Output.

### Q2: What is the difference between theoretical entropy and heuristic score?
> **Defense**: Theoretical Shannon entropy ($H = L \times \log_2(N)$) assumes characters are chosen uniformly at random. For `Password@123`, theoretical entropy is ~78.8 bits, which suggests it would take thousands of years to crack. In reality, attackers don't test combinations uniformly—they use dictionary words and rules. Our heuristic engine models practical unpredictability by penalizing common structures.

### Q3: Why is NIST SP 800-63B against mandatory special characters?
> **Defense**: NIST SP 800-63B emphasizes password length over forced complexity. When users are forced to include numbers and symbols, they almost always use predictable patterns (like capitalizing the first letter and appending `!123` or `@2026`). Long multi-word passphrases (e.g. `Rain!Cedar7Moon#42`) provide vastly superior search spaces while remaining memorable.

---

## 📁 Repository Structure
```
Ativeerrr/
├── index.html            # Main web simulation dashboard & academic defense platform
├── styles.css            # Cyber dark glassmorphism design system & print styles
├── app.js                # Frontend simulation, Web Audio synthesizer & evaluation engine
├── server.js             # Zero-dependency local development server (Port 3000)
├── password_checker.js   # Node.js CLI engine & test runner
├── password_checker.py   # Authentic Python implementation (Report Section 9 & 12)
├── test_suite.py         # Python automated test suite for Section 11 (TC01–TC10)
├── package.json          # Standard project metadata & test scripts
├── run_simulation.bat    # Windows 1-click launcher for web dashboard
├── run_tests.bat         # Windows 1-click launcher for automated test suite
└── README.md             # Complete project guide, test matrix & viva defense reference
```

---

## 🏛️ Academic Credentials
- **Institution**: MIT – World Peace University, Pune
- **Department**: CSE (Cyber Security and Forensics)
- **Project Topic**: Password Strength Checking
- **Student**: Ativeer Rajawat (Roll No: 35 | PRN: 1262243024)
- **Academic Year**: 2026–27
