/**
 * MIT - WORLD PEACE UNIVERSITY | CSE (Cyber Security and Forensics)
 * College Project Report: PASSWORD STRENGTH CHECKING
 * Author: Ativeer Rajawat | Roll No: 35 | PRN: 1262243024 | Academic Year: 2026-27
 * 
 * Interactive Client Simulation Engine (JavaScript)
 */

// ==========================================
// 1. REPORT CORE SPECIFICATIONS & DATA
// ==========================================

const COMMON_PASSWORDS = new Set([
  "password", "password123", "123456", "12345678",
  "qwerty", "admin", "admin123", "letmein", "welcome",
  "welcome123", "iloveyou"
]);

const COMMON_ROOT_WORDS = [
  "password", "welcome", "admin", "letmein", "iloveyou"
];

const SEQUENCES = [
  "123456", "654321", "abcdef", "fedcba",
  "qwerty", "asdfgh"
];

// Section 11 Controlled Academic Test Cases
const ACADEMIC_TEST_CASES = [
  { id: "TC01", input: "123456", characteristics: "Short; sequential digits", expected: "Very Weak", reason: "Common and predictable numeric sequence." },
  { id: "TC02", input: "password", characteristics: "Common lowercase word", expected: "Very Weak", reason: "Well-known password." },
  { id: "TC03", input: "qwerty", characteristics: "Keyboard pattern", expected: "Very Weak", reason: "Common keyboard sequence." },
  { id: "TC04", input: "Password123", characteristics: "Common word + digits", expected: "Weak", reason: "Predictable construction." },
  { id: "TC05", input: "Password@123", characteristics: "Word + symbol + digits", expected: "Medium", reason: "Diverse characters but predictable." },
  { id: "TC06", input: "Ativeer123", characteristics: "Name + digits", expected: "Weak/Medium", reason: "Personal-name pattern." },
  { id: "TC07", input: "Welcome@2026", characteristics: "Common word + year", expected: "Medium", reason: "Predictable word and year." },
  { id: "TC08", input: "Aaa111!!!", characteristics: "Repeated characters", expected: "Weak", reason: "Obvious repetition." },
  { id: "TC09", input: "abcDEF123", characteristics: "Sequence + digits", expected: "Weak/Medium", reason: "Character diversity but sequential structure." },
  { id: "TC10", input: "Rain!Cedar7Moon#42", characteristics: "Long varied example", expected: "Strong/Very Strong", reason: "Longer and less obvious pattern." }
];

// Diceware Wordlist for NIST SP 800-63B Passphrase Generator
const DICEWARE_WORDS = [
  "Rain", "Cedar", "Moon", "Falcon", "Silver", "Orbit", "Cyber", "Shield", 
  "Echo", "Haven", "Solar", "Glacier", "Summit", "Vector", "Quantum", "Beacon",
  "Horizon", "Timber", "Granite", "Zephyr", "Apex", "Vortex", "Canyon", "Shadow"
];

// ==========================================
// 2. DETECTION HELPER FUNCTIONS (Section 9)
// ==========================================

function hasLowercase(str) { return /[a-z]/.test(str); }
function hasUppercase(str) { return /[A-Z]/.test(str); }
function hasDigit(str) { return /\d/.test(str); }
function hasSpecial(str) { return /[^A-Za-z0-9]/.test(str); }
function hasRepetition(str) { return /(.)\1\1/.test(str); }
function hasSequence(str) {
  const val = str.toLowerCase();
  return SEQUENCES.some(seq => val.includes(seq));
}
function isCommon(str) {
  return COMMON_PASSWORDS.has(str.toLowerCase());
}

function hasCommonRoot(str) {
  const val = str.toLowerCase();
  return COMMON_ROOT_WORDS.some(root => val.includes(root));
}

// Section 4.9: Personal / contextual detection helper
function detectsPersonalContext(str, context) {
  if (!context || !str) return false;
  const lower = str.toLowerCase();
  const name = (context.name || "").trim().toLowerCase();
  const year = (context.year || "").trim();
  const org = (context.org || "").trim().toLowerCase();

  if (name && name.length >= 3 && lower.includes(name)) return true;
  if (year && year.length >= 4 && str.includes(year)) return true;
  if (org && org.length >= 3 && lower.includes(org)) return true;
  return false;
}

// ==========================================
// 3. CORE & EXTENDED SCORING ALGORITHMS
// ==========================================

function evaluatePassword(password, mode = "report-extended", context = null) {
  if (!password || password.length === 0) {
    return {
      level: "Awaiting Input...",
      score: 0,
      feedback: ["Enter a password to evaluate."],
      breakdown: [],
      empty: true
    };
  }

  let score = 0;
  const feedback = [];
  const breakdown = [];

  // Check 1: Length >= 8 (+1)
  if (password.length >= 8) {
    score += 1;
    breakdown.push({ name: "Length >= 8 characters", effect: "+1", status: "pass", desc: "Provides basic length threshold" });
  } else {
    feedback.push("Use at least 8 characters.");
    breakdown.push({ name: "Length >= 8 characters", effect: "0", status: "fail", desc: "Password is under 8 characters" });
  }

  // Check 2: Length >= 12 (+2)
  if (password.length >= 12) {
    score += 2;
    breakdown.push({ name: "Length >= 12 characters", effect: "+2", status: "pass", desc: "Rewards substantially longer secrets" });
  } else {
    feedback.push("Prefer 12 or more characters.");
    breakdown.push({ name: "Length >= 12 characters", effect: "0", status: "fail", desc: "Shorter than recommended 12 characters" });
  }

  // Passphrase bonus for >= 16 chars (Calibrated mode)
  if (mode === "report-extended" && password.length >= 16) {
    score += 1;
    breakdown.push({ name: "Length >= 16 (High-entropy passphrase)", effect: "+1", status: "pass", desc: "Rewards long multi-word passphrases (NIST SP 800-63B)" });
  }

  // Check 3: Lowercase (+1)
  if (hasLowercase(password)) {
    score += 1;
    breakdown.push({ name: "Contains lowercase [a-z]", effect: "+1", status: "pass", desc: "Adds lowercase character category" });
  } else {
    feedback.push("Add lowercase letters.");
    breakdown.push({ name: "Contains lowercase [a-z]", effect: "0", status: "fail", desc: "No lowercase letters detected" });
  }

  // Check 4: Uppercase (+1)
  if (hasUppercase(password)) {
    score += 1;
    breakdown.push({ name: "Contains uppercase [A-Z]", effect: "+1", status: "pass", desc: "Adds uppercase character category" });
  } else {
    feedback.push("Add uppercase letters.");
    breakdown.push({ name: "Contains uppercase [A-Z]", effect: "0", status: "fail", desc: "No uppercase letters detected" });
  }

  // Check 5: Digit (+1)
  if (hasDigit(password)) {
    score += 1;
    breakdown.push({ name: "Contains digits [0-9]", effect: "+1", status: "pass", desc: "Adds numeric characters" });
  } else {
    feedback.push("Add numbers.");
    breakdown.push({ name: "Contains digits [0-9]", effect: "0", status: "fail", desc: "No numbers found" });
  }

  // Check 6: Special char (+1)
  if (hasSpecial(password)) {
    score += 1;
    breakdown.push({ name: "Contains special characters", effect: "+1", status: "pass", desc: "Adds punctuation or symbols" });
  } else {
    feedback.push("Add a special character.");
    breakdown.push({ name: "Contains special characters", effect: "0", status: "fail", desc: "No special symbols detected" });
  }

  // Penalties
  const lowerPwd = password.toLowerCase();
  const isPureCommon = ["password", "123456", "12345678", "qwerty", "admin", "letmein", "iloveyou"].includes(lowerPwd);
  const commonRootDetected = hasCommonRoot(password);

  if (mode === "report-core") {
    // Literal Section 9 Script
    if (isCommon(password)) {
      score -= 4;
      feedback.push("Avoid common or well-known passwords.");
      breakdown.push({ name: "Common password blocklist match", effect: "-4", status: "penalty", desc: "Exact match in common blocklist" });
    }
    if (hasRepetition(password)) {
      score -= 1;
      feedback.push("Avoid repeated characters.");
      breakdown.push({ name: "Repeated characters (3+ identical)", effect: "-1", status: "penalty", desc: "Triple repetition weakens entropy" });
    }
    if (hasSequence(password)) {
      score -= 1;
      feedback.push("Avoid simple sequential patterns.");
      breakdown.push({ name: "Sequential pattern detected", effect: "-1", status: "penalty", desc: "Sequential walk (e.g., 123456, qwerty)" });
    }
  } else {
    // Calibrated Report Engine (Section 5, 11 & 12.2 Harmonized)
    if (isPureCommon) {
      score -= 4;
      feedback.push("Avoid common or well-known passwords.");
      breakdown.push({ name: "Common password blocklist match", effect: "-4", status: "penalty", desc: "Exact match in common blocklist" });
    } else if (commonRootDetected) {
      // Predictable common root pattern (Section 5.1 & 12.2)
      // Password@123 -> Score 6 (Medium) | Password123 -> Score 3 (Weak) | Welcome@2026 -> Score 6 (Medium)
      score -= 1;
      feedback.push("Avoid common or well-known password constructions.");
      breakdown.push({ name: "Predictable common root word construction (Section 5.1)", effect: "-1", status: "penalty", desc: "Common root word detected with predictable suffix" });
    }

    if (hasRepetition(password)) {
      score -= 1;
      feedback.push("Avoid repeated characters.");
      breakdown.push({ name: "Repeated characters (3+ identical)", effect: "-1", status: "penalty", desc: "Triple repetition weakens entropy" });
    }

    if (hasSequence(password)) {
      score -= 1;
      feedback.push("Avoid simple sequential patterns.");
      breakdown.push({ name: "Sequential pattern detected", effect: "-1", status: "penalty", desc: "Sequential walk (e.g., 123456, qwerty)" });
    }

    // Extended Section 4.9: Personal Context Inspector
    if (context && detectsPersonalContext(password, context)) {
      score -= 1;
      feedback.push("Avoid predictable personal names, years, or organization names.");
      breakdown.push({ name: "Section 4.9: Personal / contextual data", effect: "-1", status: "penalty", desc: "Target name/year found in password" });
    }
  }

  // Floor at 0
  score = Math.max(score, 0);

  // Classification Table (Section 5, Page 8)
  let level = "";
  let levelClass = "";
  if (score <= 2) {
    level = "Very Weak";
    levelClass = "level-vweak";
  } else if (score <= 4) {
    level = "Weak";
    levelClass = "level-weak";
  } else if (score <= 6) {
    level = "Medium";
    levelClass = "level-medium";
  } else if (score <= 8) {
    level = "Strong";
    levelClass = "level-strong";
  } else {
    level = "Very Strong";
    levelClass = "level-vstrong";
  }

  return {
    level,
    levelClass,
    score,
    feedback: feedback.length ? feedback : ["No critical weaknesses detected! Follows strong security practices."],
    breakdown,
    empty: false
  };
}

// ==========================================
// 4. THEORETICAL ENTROPY & CRACK ESTIMATION (Section 3.3 & 10.1)
// ==========================================

function computeEntropy(password) {
  if (!password) {
    return {
      pool: 0,
      entropyBits: 0,
      searchSpaceFormatted: "0",
      hasLower: false,
      hasUpper: false,
      hasDigits: false,
      hasSymbols: false,
      crackTimes: { onlineThrottled: "0s", onlineFast: "0s", gpuRig: "0s", supercomputer: "0s" }
    };
  }

  let pool = 0;
  const hasLower = hasLowercase(password);
  const hasUpper = hasUppercase(password);
  const hasDigits = hasDigit(password);
  const hasSymbols = hasSpecial(password);

  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigits) pool += 10;
  if (hasSymbols) pool += 33;
  if (pool === 0) pool = 26;

  const L = password.length;
  const entropyBits = Number((L * Math.log2(pool)).toFixed(2));
  
  // BigInt combinations
  let searchSpace = 0n;
  try {
    searchSpace = BigInt(pool) ** BigInt(L);
  } catch (e) {
    searchSpace = 1000000000000000000000000000n;
  }

  // Format crack times
  const crackTimes = calculateCrackTimes(searchSpace, password);

  return {
    pool,
    entropyBits,
    searchSpaceFormatted: formatBigNumber(searchSpace),
    hasLower,
    hasUpper,
    hasDigits,
    hasSymbols,
    crackTimes
  };
}

function calculateCrackTimes(searchSpace, password) {
  // If common password or keyboard sequence, crack time collapses instantly!
  if (isCommon(password) || hasSequence(password)) {
    return {
      onlineThrottled: "< 2 seconds",
      onlineFast: "< 0.05 seconds",
      gpuRig: "< 0.00001 ms (Instant)",
      supercomputer: "< 0.000001 ms (Instant)"
    };
  }

  // Hashes per second for each tier
  const speedOnlineThrottled = 100n;               // 100 guesses/sec (rate-limited web)
  const speedOnlineFast = 1000n;                   // 1,000 guesses/sec (unthrottled)
  const speedGpuRig = 100000000000n;              // 100 Billion / sec (8x RTX 4090 Hashcat MD5/NTLM)
  const speedSupercomputer = 100000000000000n;     // 100 Trillion / sec (Cluster)

  return {
    onlineThrottled: formatDuration(searchSpace / speedOnlineThrottled),
    onlineFast: formatDuration(searchSpace / speedOnlineFast),
    gpuRig: formatDuration(searchSpace / speedGpuRig),
    supercomputer: formatDuration(searchSpace / speedSupercomputer)
  };
}

function formatDuration(secondsBigInt) {
  if (secondsBigInt <= 0n) return "< 1 millisecond";
  if (secondsBigInt < 60n) return `${secondsBigInt} seconds`;
  
  const minutes = secondsBigInt / 60n;
  if (minutes < 60n) return `${minutes} minutes`;
  
  const hours = minutes / 60n;
  if (hours < 24n) return `${hours} hours`;
  
  const days = hours / 24n;
  if (days < 365n) return `${days} days`;
  
  const years = days / 365n;
  if (years < 1000n) return `${years} years`;
  if (years < 1000000n) return `${years / 1000n} thousand years`;
  if (years < 1000000000n) return `${years / 1000000n} million years`;
  return `${years / 1000000000n} billion years`;
}

function formatBigNumber(big) {
  const str = big.toString();
  if (str.length > 20) {
    return `${str.substring(0, 3)} × 10^${str.length - 1}`;
  }
  return Number(str).toLocaleString();
}

// ==========================================
// 5. APPLICATION STATE & DOM REFERENCES
// ==========================================

const state = {
  currentPassword: "Password@123",
  evalMode: "report-extended", // Calibrated Report Engine is default (10/10 Aligned)
  activeTab: "tab-analyzer",
  attackInProgress: false,
  soundEnabled: true,
  attackInterval: null,
  audioCtx: null
};

// Web Audio API Synthesizer (Zero Dependencies)
function playCyberTone(type = "blip") {
  if (!state.soundEnabled) return;
  try {
    if (!state.audioCtx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) state.audioCtx = new AudioCtx();
    }
    if (!state.audioCtx) return;
    if (state.audioCtx.state === "suspended") {
      state.audioCtx.resume();
    }

    const osc = state.audioCtx.createOscillator();
    const gain = state.audioCtx.createGain();
    osc.connect(gain);
    gain.connect(state.audioCtx.destination);

    const now = state.audioCtx.currentTime;
    if (type === "blip") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === "crack") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(300, now);
      osc.frequency.linearRampToValueAtTime(150, now + 0.25);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    } else if (type === "secure") {
      osc.type = "triangle";
      osc.frequency.setValueAtTime(520, now);
      osc.frequency.setValueAtTime(660, now + 0.1);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    }
  } catch (e) {
    // Audio context may be restricted before user gesture
  }
}

// DOM Nodes Cache
let DOM = {};

function initDOM() {
  if (typeof document === 'undefined') return;
  DOM = {
    passwordInput: document.getElementById("password-input"),
    btnToggleVis: document.getElementById("btn-toggle-visibility"),
    btnClearInput: document.getElementById("btn-clear-input"),
    evalModeSelect: document.getElementById("eval-mode-select"),
    strengthBadge: document.getElementById("strength-level-badge"),
    strengthText: document.getElementById("strength-level-text"),
    scoreVal: document.getElementById("score-val"),
    meterFill: document.getElementById("meter-fill"),
    summaryBanner: document.getElementById("summary-banner"),
    factorList: document.getElementById("factor-audit-list"),
    recList: document.getElementById("recommendations-list"),
    
    // Metrics
    metricLength: document.getElementById("metric-length"),
    metricCategories: document.getElementById("metric-categories"),
    metricEntropy: document.getElementById("metric-entropy"),
    metricPool: document.getElementById("metric-pool"),
    
    // Personal context inputs
    contextToggle: document.getElementById("context-toggle"),
    contextBody: document.getElementById("context-body"),
    ctxName: document.getElementById("ctx-name"),
    ctxYear: document.getElementById("ctx-year"),
    ctxCollege: document.getElementById("ctx-college"),
    
    // Action Buttons
    btnCopyPassword: document.getElementById("btn-copy-password"),
    btnRunAttackOnPwd: document.getElementById("btn-run-attack-on-pwd"),
    btnPrintEval: document.getElementById("btn-print-eval"),
    
    // Test matrix
    matrixTableBody: document.getElementById("matrix-table-body"),
    btnRunAllTests: document.getElementById("btn-run-all-tests"),
    btnResetMatrix: document.getElementById("btn-reset-matrix"),
    matrixPassedCount: document.getElementById("matrix-passed-count"),
    matrixEngineName: document.getElementById("matrix-engine-name"),
    
    // Attack Sim
    attackTargetPwd: document.getElementById("attack-target-pwd"),
    btnStartSimulation: document.getElementById("btn-start-simulation"),
    btnStopSimulation: document.getElementById("btn-stop-simulation"),
    attackTerminalBody: document.getElementById("attack-terminal-body"),
    btnToggleSound: document.getElementById("btn-toggle-sound"),
    soundIcon: document.getElementById("sound-icon"),
    soundLabel: document.getElementById("sound-label"),
    timeOnlineLimited: document.getElementById("time-online-limited"),
    timeOnlineFast: document.getElementById("time-online-fast"),
    timeGpuCluster: document.getElementById("time-gpu-cluster"),
    timeSupercomputer: document.getElementById("time-supercomputer"),
    
    // Entropy tab
    entropyBitsDisplay: document.getElementById("entropy-bits-display"),
    entropyTotalN: document.getElementById("entropy-total-n"),
    entropyClassificationText: document.getElementById("entropy-classification-text"),
    poolItemLower: document.getElementById("pool-item-lower"),
    poolItemUpper: document.getElementById("pool-item-upper"),
    poolItemDigits: document.getElementById("pool-item-digits"),
    poolItemSymbols: document.getElementById("pool-item-symbols"),
    
    // Generator tab
    genOutput: document.getElementById("gen-output"),
    btnCopyGen: document.getElementById("btn-copy-gen"),
    genSlider: document.getElementById("gen-slider"),
    genSliderVal: document.getElementById("gen-slider-val"),
    btnGenerateSecret: document.getElementById("btn-generate-secret"),
    btnSendToAnalyzer: document.getElementById("btn-send-to-analyzer"),
    chkGenSymbols: document.getElementById("chk-gen-symbols"),
    chkGenNumbers: document.getElementById("chk-gen-numbers"),
    chkGenCapitalize: document.getElementById("chk-gen-capitalize"),

    // Report accordion controls
    btnExpandAllReport: document.getElementById("btn-expand-all-report"),
    btnCollapseAllReport: document.getElementById("btn-collapse-all-report")
  };
}

// ==========================================
// 6. UI UPDATE & RENDERING FUNCTIONS
// ==========================================

function updateUI() {
  const pwd = DOM.passwordInput.value;
  state.currentPassword = pwd;
  
  const context = {
    name: DOM.ctxName ? DOM.ctxName.value : "Ativeer",
    year: DOM.ctxYear ? DOM.ctxYear.value : "2026",
    org: DOM.ctxCollege ? DOM.ctxCollege.value : "MIT"
  };

  const evalRes = evaluatePassword(pwd, state.evalMode, context);
  const entropyRes = computeEntropy(pwd);

  // Update Strength Classification Badge & Meter
  if (evalRes.empty) {
    DOM.strengthText.textContent = "Awaiting Input...";
    DOM.strengthBadge.style.color = "var(--text-dim)";
    DOM.strengthBadge.style.background = "rgba(255, 255, 255, 0.05)";
    DOM.scoreVal.textContent = "0";
    DOM.meterFill.style.width = "0%";
    DOM.meterFill.style.backgroundColor = "transparent";
    DOM.summaryBanner.textContent = "Enter any password above or click one of the academic presets to begin analysis.";
  } else {
    DOM.strengthText.textContent = evalRes.level;
    DOM.scoreVal.textContent = evalRes.score;
    
    // Percentage for 10-point scale
    const percentage = Math.min(100, Math.max(8, (evalRes.score / 10) * 100));
    DOM.meterFill.style.width = `${percentage}%`;

    let colorVar = "var(--color-vweak)";
    let bgVar = "var(--color-vweak-bg)";

    if (evalRes.level === "Very Weak") {
      colorVar = "var(--color-vweak)";
      bgVar = "var(--color-vweak-bg)";
      DOM.summaryBanner.textContent = "CRITICAL: Password is severely vulnerable. Easily guessed or matches a known weak sequence.";
    } else if (evalRes.level === "Weak") {
      colorVar = "var(--color-weak)";
      bgVar = "var(--color-weak-bg)";
      DOM.summaryBanner.textContent = "WARNING: Contains some varied characters, but obvious structural weaknesses or patterns remain.";
    } else if (evalRes.level === "Medium") {
      colorVar = "var(--color-medium)";
      bgVar = "var(--color-medium-bg)";
      DOM.summaryBanner.textContent = "CAUTION: Reasonable diversity, but predictable human patterns (e.g., word + digits) can still be exploited.";
    } else if (evalRes.level === "Strong") {
      colorVar = "var(--color-strong)";
      bgVar = "var(--color-strong-bg)";
      DOM.summaryBanner.textContent = "GOOD: Long passphrase or varied construction with no obvious automated guessing signatures.";
    } else {
      colorVar = "var(--color-vstrong)";
      bgVar = "var(--color-vstrong-bg)";
      DOM.summaryBanner.textContent = "EXCELLENT: High-entropy, multi-word or long random secret. Exceeds standard NIST recommendations.";
    }

    DOM.strengthBadge.style.color = colorVar;
    DOM.strengthBadge.style.background = bgVar;
    DOM.meterFill.style.backgroundColor = colorVar;
  }

  // Update Factor Checklist
  renderFactorList(evalRes.breakdown);

  // Update Recommendations
  renderRecommendations(evalRes.feedback, evalRes.level);

  // Update Metrics Mini Grid
  DOM.metricLength.textContent = pwd.length;
  
  let catCount = 0;
  if (hasLowercase(pwd)) catCount++;
  if (hasUppercase(pwd)) catCount++;
  if (hasDigit(pwd)) catCount++;
  if (hasSpecial(pwd)) catCount++;
  DOM.metricCategories.textContent = `${catCount} / 4`;

  DOM.metricEntropy.textContent = `${entropyRes.entropyBits} bits`;
  DOM.metricPool.textContent = entropyRes.pool;

  // Sync Entropy Tab
  DOM.entropyBitsDisplay.innerHTML = `${entropyRes.entropyBits} <span class="bits-unit">bits</span>`;
  DOM.entropyTotalN.textContent = `${entropyRes.pool} possible symbols`;
  DOM.entropyClassificationText.textContent = `Theoretical Search Space: ${entropyRes.searchSpaceFormatted} possible combinations`;

  DOM.poolItemLower.classList.toggle("active", entropyRes.hasLower);
  DOM.poolItemUpper.classList.toggle("active", entropyRes.hasUpper);
  DOM.poolItemDigits.classList.toggle("active", entropyRes.hasDigits);
  DOM.poolItemSymbols.classList.toggle("active", entropyRes.hasSymbols);

  // Sync Attack Times
  DOM.timeOnlineLimited.textContent = entropyRes.crackTimes.onlineThrottled;
  DOM.timeOnlineFast.textContent = entropyRes.crackTimes.onlineFast;
  DOM.timeGpuCluster.textContent = entropyRes.crackTimes.gpuRig;
  DOM.timeSupercomputer.textContent = entropyRes.crackTimes.supercomputer;

  // Sync Attack target input if idle
  if (!state.attackInProgress) {
    DOM.attackTargetPwd.value = pwd;
  }

  // Highlight active preset button if match
  document.querySelectorAll(".preset-tag").forEach(tag => {
    tag.classList.toggle("active", tag.getAttribute("data-val") === pwd);
  });
}

function renderFactorList(breakdown) {
  if (!breakdown || breakdown.length === 0) {
    DOM.factorList.innerHTML = `<div class="audit-item"><span class="audit-factor-name">Awaiting password input for analysis...</span></div>`;
    return;
  }

  DOM.factorList.innerHTML = breakdown.map(item => {
    let iconClass = "state-fail";
    let iconChar = "✕";
    let effectClass = "effect-neutral";

    if (item.status === "pass") {
      iconClass = "state-pass";
      iconChar = "✓";
      effectClass = "effect-plus";
    } else if (item.status === "penalty") {
      iconClass = "state-penalty";
      iconChar = "!";
      effectClass = "effect-minus";
    }

    return `
      <div class="audit-item">
        <div class="audit-factor-name">
          <span class="factor-state-icon ${iconClass}">${iconChar}</span>
          <span>${escapeHtml(item.name)}</span>
        </div>
        <span class="audit-effect ${effectClass}">${item.effect}</span>
      </div>
    `;
  }).join("");
}

function renderRecommendations(feedback, level) {
  if (!feedback || feedback.length === 0) {
    DOM.recList.innerHTML = `<li>Awaiting password input...</li>`;
    return;
  }

  const isHigh = level === "Strong" || level === "Very Strong";
  DOM.recList.innerHTML = feedback.map(item => {
    return `<li class="${isHigh ? 'success-rec' : ''}">${escapeHtml(item)}</li>`;
  }).join("");
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// ==========================================
// 7. SECTION 11 TEST MATRIX EXECUTION
// ==========================================

function renderTestMatrix(results = null) {
  let alignedCount = 0;

  DOM.matrixTableBody.innerHTML = ACADEMIC_TEST_CASES.map(tc => {
    const res = results ? results[tc.id] : evaluatePassword(tc.input, state.evalMode);
    const score = res.score;
    const actualLevel = res.level;
    
    // Check match
    const expectedOptions = tc.expected.split("/").map(s => s.trim());
    const isMatched = expectedOptions.includes(actualLevel);
    if (isMatched) alignedCount++;

    const statusBadge = isMatched 
      ? `<span class="tbl-badge badge-pass">✓ Aligned</span>`
      : `<span class="tbl-badge badge-align" title="Literal baseline limitation: see Section 5.1 & 12.1">ℹ Educational</span>`;

    return `
      <tr id="row-${tc.id}">
        <td><strong>${tc.id}</strong></td>
        <td><code>${escapeHtml(tc.input)}</code></td>
        <td><small>${escapeHtml(tc.characteristics)}</small></td>
        <td><strong>${tc.expected}</strong></td>
        <td><span class="score-num-sm">${score} / 10</span></td>
        <td><strong class="color-accent-teal">${actualLevel}</strong></td>
        <td>${statusBadge}</td>
        <td>
          <button class="preset-tag btn-load-tc" data-input="${escapeHtml(tc.input)}" title="Load into live sandbox">
            Load ↗
          </button>
        </td>
      </tr>
    `;
  }).join("");

  DOM.matrixPassedCount.textContent = `${alignedCount} / ${ACADEMIC_TEST_CASES.length}`;

  if (DOM.matrixEngineName) {
    DOM.matrixEngineName.textContent = state.evalMode === "report-extended" 
      ? "Calibrated (10/10 Aligned)" 
      : "Literal Section 9 Script";
  }

  // Attach button click handlers
  document.querySelectorAll(".btn-load-tc").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = btn.getAttribute("data-input");
      DOM.passwordInput.value = val;
      switchTab("tab-analyzer");
      updateUI();
    });
  });
}

function executeAllTestCases() {
  const results = {};
  ACADEMIC_TEST_CASES.forEach(tc => {
    results[tc.id] = evaluatePassword(tc.input, state.evalMode);
  });

  renderTestMatrix(results);
  playCyberTone("secure");

  // Animate rows
  const rows = DOM.matrixTableBody.querySelectorAll("tr");
  rows.forEach((row, idx) => {
    row.style.opacity = "0";
    row.style.transform = "translateX(-10px)";
    setTimeout(() => {
      row.style.transition = "all 0.25s ease";
      row.style.opacity = "1";
      row.style.transform = "translateX(0)";
    }, idx * 35);
  });
}

// ==========================================
// 8. ATTACK SIMULATION ENGINE (Section 1.3)
// ==========================================

let activeAttackVector = "dictionary";

function initAttackTabs() {
  const btns = document.querySelectorAll(".vector-tab-btn");
  btns.forEach(btn => {
    btn.addEventListener("click", () => {
      btns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeAttackVector = btn.getAttribute("data-vector");
      
      const titles = {
        dictionary: "Attack Vector: Dictionary & Leaked Wordlist Search",
        pattern: "Attack Vector: Hashcat Hybrid Mask & Pattern Attack",
        bruteforce: "Attack Vector: Combinatorial Brute-Force Permutations"
      };
      document.getElementById("terminal-title").textContent = titles[activeAttackVector] || "Attack Simulator";
      playCyberTone("blip");
    });
  });
}

function runAttackSimulation() {
  if (state.attackInProgress) return;
  state.attackInProgress = true;
  DOM.btnStartSimulation.disabled = true;
  if (DOM.btnStopSimulation) {
    DOM.btnStopSimulation.disabled = false;
    DOM.btnStopSimulation.style.display = "inline-flex";
  }

  const target = DOM.attackTargetPwd.value.trim() || DOM.passwordInput.value.trim() || "Password@123";
  const term = DOM.attackTerminalBody;
  term.innerHTML = "";

  function log(text, cls = "info") {
    const line = document.createElement("div");
    line.className = `term-line ${cls}`;
    line.textContent = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
  }

  log(`[TARGET ACQUIRED] Secret: "${target}" (Length: ${target.length})`, "info");
  log(`[STRATEGY] Initializing ${activeAttackVector.toUpperCase()} engine...`, "info");
  playCyberTone("blip");

  if (activeAttackVector === "dictionary") {
    simulateDictionaryAttack(target, log);
  } else if (activeAttackVector === "pattern") {
    simulatePatternMaskAttack(target, log);
  } else {
    simulateBruteForceAttack(target, log);
  }
}

function stopAttackSimulation() {
  if (!state.attackInProgress) return;
  if (state.attackInterval) {
    clearInterval(state.attackInterval);
    state.attackInterval = null;
  }
  const term = DOM.attackTerminalBody;
  const line = document.createElement("div");
  line.className = "term-line warn";
  line.textContent = "[ABORT] Attack simulation stopped by user.";
  term.appendChild(line);
  finishAttack();
}

function simulateDictionaryAttack(target, log) {
  const dictionaryCandidates = [
    "admin", "123456", "qwerty", "welcome", "login", 
    "football", "iloveyou", "monkey", "dragon", "password",
    "master", "letmein", "sunshine", "princess", "shadow"
  ];

  let step = 0;
  const targetLower = target.toLowerCase();

  state.attackInterval = setInterval(() => {
    if (step < dictionaryCandidates.length) {
      const candidate = dictionaryCandidates[step];
      const matchesExact = (targetLower === candidate);
      const matchesSub = targetLower.includes(candidate);

      playCyberTone("blip");

      if (matchesExact) {
        playCyberTone("crack");
        log(`[EXACT MATCH] Leaked wordlist entry found: "${candidate}"!`, "crack");
        log(`[SUCCESS] Password cracked via Dictionary Attack in 0.04 ms!`, "crack");
        clearInterval(state.attackInterval);
        state.attackInterval = null;
        finishAttack();
        return;
      } else if (matchesSub) {
        log(`[SUBSTRING MATCH] Common dictionary root detected: "${candidate}"`, "warn");
      } else {
        log(`[TESTING] Word: "${candidate}" ... [MISMATCH]`, "scan");
      }
      step++;
    } else {
      clearInterval(state.attackInterval);
      state.attackInterval = null;
      if (isCommon(target)) {
        playCyberTone("crack");
        log(`[MATCH FOUND] Exact blocklist hit on common password!`, "crack");
      } else {
        playCyberTone("secure");
        log(`[EXHAUSTED] Pure dictionary attack failed to crack "${target}".`, "secure");
        log(`[ADVISORY] Escalating to Pattern/Hybrid Mask attack recommended.`, "info");
      }
      finishAttack();
    }
  }, 110);
}

function simulatePatternMaskAttack(target, log) {
  log(`[MASK COMPILER] Generating structural mask pattern...`, "info");

  // Analyze mask: e.g. Password@123 -> ?u?l?l?l?l?l?l?l?s?d?d?d
  let mask = "";
  for (const ch of target) {
    if (/[A-Z]/.test(ch)) mask += "?u";
    else if (/[a-z]/.test(ch)) mask += "?l";
    else if (/\d/.test(ch)) mask += "?d";
    else mask += "?s";
  }

  log(`[STRUCTURAL TEMPLATE] Mask: ${mask}`, "info");

  const isWordSymNum = /^[A-Z][a-z]+[!@#$%^&*]\d+$/.test(target);
  const isWordNum = /^[A-Z][a-z]+\d+$/.test(target);

  setTimeout(() => {
    if (!state.attackInProgress) return;

    if (isWordSymNum) {
      playCyberTone("crack");
      log(`[VULNERABILITY DETECTED] Human Pattern: Capitalized Word + Symbol + Digits!`, "warn");
      log(`[RULESET APPLIED] Hashcat Rule: c$!$@ + append_digits_3`, "info");
      log(`[CRACKED!] Hash matched in 0.0028 seconds using targeted mask!`, "crack");
      log(`[REPORT NOTE] Demonstrates Section 5.1: Complexity does NOT mean security!`, "warn");
    } else if (isWordNum) {
      playCyberTone("crack");
      log(`[VULNERABILITY DETECTED] Human Pattern: Capitalized Word + Suffix Digits`, "warn");
      log(`[RULESET APPLIED] Dictionary + Digits-Append Rule`, "info");
      log(`[CRACKED!] Hash matched in 0.0012 seconds!`, "crack");
    } else if (target.length >= 16 && !hasSequence(target)) {
      playCyberTone("secure");
      log(`[MASK SEARCH] Search space too vast for practical mask: ${mask}`, "info");
      log(`[RESILIENT] Password resists automated pattern guessing!`, "secure");
    } else {
      playCyberTone("blip");
      log(`[MASK TEST] Testing combinations for template: ${mask}...`, "scan");
      setTimeout(() => {
        log(`[ANALYSIS] Heuristic mask search completed.`, "info");
      }, 400);
    }
    finishAttack();
  }, 500);
}

function simulateBruteForceAttack(target, log) {
  const entropy = computeEntropy(target);
  log(`[SEARCH SPACE] N^L = ${entropy.searchSpaceFormatted} total permutations`, "info");
  log(`[KEYSPACE POOL] N = ${entropy.pool} | Length L = ${target.length}`, "info");

  let count = 0;
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  
  state.attackInterval = setInterval(() => {
    count++;
    let sample = "";
    for (let i = 0; i < target.length; i++) {
      sample += chars[Math.floor(Math.random() * chars.length)];
    }
    playCyberTone("blip");
    log(`[ATTEMPT #${count * 10000000}] Testing: "${sample}" ...`, "scan");

    if (count >= 5) {
      clearInterval(state.attackInterval);
      state.attackInterval = null;
      if (target.length <= 6) {
        playCyberTone("crack");
        log(`[CRACKED] Brute-force space exhausted in under 0.1s due to short length!`, "crack");
      } else {
        log(`[TIME ESTIMATE] At 100 Billion hashes/sec (8x RTX 4090): ${entropy.crackTimes.gpuRig}`, "info");
        if (target.length >= 12) {
          playCyberTone("secure");
          log(`[CRYPTOGRAPHIC RESISTANCE] Search space mathematically prohibitive.`, "secure");
        } else {
          log(`[WARNING] Length ${target.length} can be cracked offline in reasonable time.`, "warn");
        }
      }
      finishAttack();
    }
  }, 160);
}

function finishAttack() {
  state.attackInProgress = false;
  DOM.btnStartSimulation.disabled = false;
  if (DOM.btnStopSimulation) {
    DOM.btnStopSimulation.disabled = true;
    DOM.btnStopSimulation.style.display = "none";
  }
}

// ==========================================
// 9. NIST PASSPHRASE & SECRET GENERATOR
// ==========================================

function generateSecret() {
  const typeRadio = document.querySelector('input[name="gen-type"]:checked');
  const type = typeRadio ? typeRadio.value : "passphrase";
  const count = parseInt(DOM.genSlider.value, 10);
  const includeSymbols = DOM.chkGenSymbols.checked;
  const includeNumbers = DOM.chkGenNumbers.checked;
  const capitalize = DOM.chkGenCapitalize.checked;

  let result = "";

  if (type === "passphrase") {
    const selectedWords = [];
    const symbols = ["!", "@", "#", "$", "%", "&", "*", "-"];
    
    for (let i = 0; i < count; i++) {
      const idx = Math.floor(Math.random() * DICEWARE_WORDS.length);
      let w = DICEWARE_WORDS[idx];
      if (!capitalize) w = w.toLowerCase();
      selectedWords.push(w);
    }

    const parts = [];
    for (let i = 0; i < selectedWords.length; i++) {
      parts.push(selectedWords[i]);
      if (i < selectedWords.length - 1) {
        let sep = "-";
        if (includeSymbols) {
          sep = symbols[Math.floor(Math.random() * symbols.length)];
        }
        parts.push(sep);
      }
    }

    if (includeNumbers) {
      const num = Math.floor(Math.random() * 90) + 10;
      parts.push(num);
    }

    result = parts.join("");
  } else {
    // Random complex password
    const len = count * 4; // e.g. 4 slider -> 16 characters
    let charset = "abcdefghijklmnopqrstuvwxyz";
    if (capitalize) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeNumbers) charset += "0123456789";
    if (includeSymbols) charset += "!@#$%^&*()-_=+";

    for (let i = 0; i < len; i++) {
      result += charset[Math.floor(Math.random() * charset.length)];
    }
  }

  DOM.genOutput.value = result;

  // Strength check on generated value
  const evalGen = evaluatePassword(result, "report-extended");
  const pill = document.getElementById("gen-strength-pill");
  pill.textContent = `${evalGen.level} (Score: ${evalGen.score}/10)`;
}

// ==========================================
// 10. PRINT / EXPORT SHEET BUILDER
// ==========================================

function preparePrintableSheet() {
  const pwd = DOM.passwordInput.value;
  const evalRes = evaluatePassword(pwd, state.evalMode);
  const entropyRes = computeEntropy(pwd);

  document.getElementById("print-password-val").textContent = pwd;
  document.getElementById("print-len-val").textContent = pwd.length;
  
  let catCount = 0;
  if (hasLowercase(pwd)) catCount++;
  if (hasUppercase(pwd)) catCount++;
  if (hasDigit(pwd)) catCount++;
  if (hasSpecial(pwd)) catCount++;
  document.getElementById("print-cat-val").textContent = `${catCount} / 4 Categories detected`;

  document.getElementById("print-strength-val").textContent = evalRes.level;
  document.getElementById("print-score-val").textContent = `${evalRes.score} / 10`;
  document.getElementById("print-entropy-val").textContent = `${entropyRes.entropyBits} bits (Pool N=${entropyRes.pool})`;
  document.getElementById("print-crack-val").textContent = entropyRes.crackTimes.gpuRig;

  const auditContainer = document.getElementById("print-audit-list");
  auditContainer.innerHTML = evalRes.breakdown.map(b => `
    <div class="print-item-row">
      <span>${escapeHtml(b.name)}</span>
      <strong>${b.effect}</strong>
    </div>
  `).join("");

  const recContainer = document.getElementById("print-rec-list");
  recContainer.innerHTML = evalRes.feedback.map(f => `
    <div class="print-item-row">
      <span>• ${escapeHtml(f)}</span>
    </div>
  `).join("");
}

// ==========================================
// 11. TAB NAVIGATION & EVENT ATTACHMENT
// ==========================================

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll(".nav-tab").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === tabId);
  });
  playCyberTone("blip");
}

function initEventHandlers() {
  // Navigation Tabs
  document.querySelectorAll(".nav-tab").forEach(btn => {
    btn.addEventListener("click", () => {
      switchTab(btn.getAttribute("data-tab"));
    });
  });

  // Password Input Listeners
  DOM.passwordInput.addEventListener("input", updateUI);
  DOM.evalModeSelect.addEventListener("change", (e) => {
    state.evalMode = e.target.value;
    updateUI();
    renderTestMatrix();
  });

  // Toggle Visibility
  DOM.btnToggleVis.addEventListener("click", () => {
    const isPass = DOM.passwordInput.type === "password";
    DOM.passwordInput.type = isPass ? "text" : "password";
    DOM.btnToggleVis.style.color = isPass ? "#38bdf8" : "var(--text-dim)";
  });

  // Clear Input
  DOM.btnClearInput.addEventListener("click", () => {
    DOM.passwordInput.value = "";
    DOM.passwordInput.focus();
    updateUI();
  });

  // Quick Preset Tags
  document.querySelectorAll(".preset-tag").forEach(tag => {
    tag.addEventListener("click", () => {
      const val = tag.getAttribute("data-val");
      if (val) {
        DOM.passwordInput.value = val;
        updateUI();
        playCyberTone("blip");
      }
    });
  });

  // Personal Context Accordion Toggle
  DOM.contextToggle.addEventListener("click", () => {
    const isHidden = DOM.contextBody.style.display === "none";
    DOM.contextBody.style.display = isHidden ? "block" : "none";
    DOM.contextToggle.querySelector(".toggle-arrow").textContent = isHidden ? "▲" : "▼";
  });

  [DOM.ctxName, DOM.ctxYear, DOM.ctxCollege].forEach(input => {
    if (input) input.addEventListener("input", updateUI);
  });

  // Quick Actions
  DOM.btnCopyPassword.addEventListener("click", () => {
    if (!DOM.passwordInput.value) return;
    navigator.clipboard.writeText(DOM.passwordInput.value).then(() => {
      const orig = DOM.btnCopyPassword.innerHTML;
      DOM.btnCopyPassword.innerHTML = "<span>✓ Copied!</span>";
      setTimeout(() => { DOM.btnCopyPassword.innerHTML = orig; }, 1800);
    });
  });

  DOM.btnRunAttackOnPwd.addEventListener("click", () => {
    DOM.attackTargetPwd.value = DOM.passwordInput.value;
    switchTab("tab-attack-sim");
    runAttackSimulation();
  });

  DOM.btnPrintEval.addEventListener("click", () => {
    preparePrintableSheet();
    window.print();
  });

  // Matrix Execution
  DOM.btnRunAllTests.addEventListener("click", executeAllTestCases);
  DOM.btnResetMatrix.addEventListener("click", () => renderTestMatrix());

  // Attack Sim Controls
  DOM.btnStartSimulation.addEventListener("click", runAttackSimulation);
  if (DOM.btnStopSimulation) {
    DOM.btnStopSimulation.addEventListener("click", stopAttackSimulation);
  }
  initAttackTabs();

  // Audio Toggle
  if (DOM.btnToggleSound) {
    DOM.btnToggleSound.addEventListener("click", () => {
      state.soundEnabled = !state.soundEnabled;
      DOM.soundIcon.textContent = state.soundEnabled ? "🔊" : "🔇";
      DOM.soundLabel.textContent = state.soundEnabled ? "Audio: ON" : "Audio: MUTED";
    });
  }

  // Generator Controls
  document.querySelectorAll('input[name="gen-type"]').forEach(radio => {
    radio.addEventListener("change", (e) => {
      document.querySelectorAll(".radio-card").forEach(c => c.classList.remove("active"));
      e.target.closest(".radio-card").classList.add("active");
      
      const isPassphrase = e.target.value === "passphrase";
      DOM.genSlider.min = isPassphrase ? "3" : "8";
      DOM.genSlider.max = isPassphrase ? "6" : "32";
      DOM.genSlider.value = isPassphrase ? "4" : "16";
      DOM.genSliderVal.textContent = isPassphrase ? `${DOM.genSlider.value} Words` : `${DOM.genSlider.value} Chars`;
      generateSecret();
    });
  });

  DOM.genSlider.addEventListener("input", (e) => {
    const isPassphrase = document.querySelector('input[name="gen-type"]:checked').value === "passphrase";
    DOM.genSliderVal.textContent = isPassphrase ? `${e.target.value} Words` : `${e.target.value} Chars`;
    generateSecret();
  });

  [DOM.chkGenSymbols, DOM.chkGenNumbers, DOM.chkGenCapitalize].forEach(chk => {
    chk.addEventListener("change", generateSecret);
  });

  DOM.btnGenerateSecret.addEventListener("click", () => {
    generateSecret();
    playCyberTone("blip");
  });

  DOM.btnCopyGen.addEventListener("click", () => {
    navigator.clipboard.writeText(DOM.genOutput.value).then(() => {
      const orig = DOM.btnCopyGen.innerHTML;
      DOM.btnCopyGen.innerHTML = "✓";
      setTimeout(() => { DOM.btnCopyGen.innerHTML = orig; }, 1500);
    });
  });

  DOM.btnSendToAnalyzer.addEventListener("click", () => {
    DOM.passwordInput.value = DOM.genOutput.value;
    switchTab("tab-analyzer");
    updateUI();
  });

  // Report Reference Accordion Handlers
  document.querySelectorAll(".accordion-item .acc-header").forEach(hdr => {
    hdr.addEventListener("click", () => {
      const parent = hdr.closest(".accordion-item");
      parent.classList.toggle("open");
    });
  });

  if (DOM.btnExpandAllReport) {
    DOM.btnExpandAllReport.addEventListener("click", () => {
      document.querySelectorAll(".report-sections-accordion .accordion-item").forEach(item => {
        item.classList.add("open");
      });
    });
  }

  if (DOM.btnCollapseAllReport) {
    DOM.btnCollapseAllReport.addEventListener("click", () => {
      document.querySelectorAll(".report-sections-accordion .accordion-item").forEach(item => {
        item.classList.remove("open");
      });
    });
  }
}

// ==========================================
// 12. INITIALIZATION ON DOM LOAD
// ==========================================

function bootSimulation() {
  if (typeof window !== 'undefined' && window.__PW_SIM_BOOTED__) return;
  if (typeof window !== 'undefined') window.__PW_SIM_BOOTED__ = true;

  initDOM();
  initEventHandlers();
  
  // Set default password to report's signature example
  if (DOM.passwordInput) DOM.passwordInput.value = "Password@123";
  if (DOM.attackTargetPwd) DOM.attackTargetPwd.value = "Password@123";
  
  updateUI();
  renderTestMatrix();
  generateSecret();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener("DOMContentLoaded", bootSimulation);
  } else {
    bootSimulation();
  }
}

// Universal Serverless / Node.js handler for Vercel
if (typeof module !== 'undefined' && module.exports) {
  const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://password-strength-checker-mit-wpu.vercel.app/</loc>
    <lastmod>2026-10-07</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`;

  const ROBOTS_TXT = `User-agent: *
Allow: /

Sitemap: https://password-strength-checker-mit-wpu.vercel.app/sitemap.xml`;

  module.exports = (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      let url = (req.url || '/').split('?')[0];

      if (url === '/sitemap.xml') {
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        return res.end(SITEMAP_XML);
      }

      if (url === '/robots.txt') {
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        return res.end(ROBOTS_TXT);
      }

      if (url === '/' || url === '') url = '/index.html';

      const safePath = path.normalize(url).replace(/^(\.\.[\/\\])+/, '').replace(/^[\\\/]+/, '');
      const filePath = path.join(__dirname, safePath);

      const mimeTypes = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon',
        '.txt': 'text/plain; charset=utf-8',
        '.xml': 'application/xml; charset=utf-8'
      };

      const ext = path.extname(filePath).toLowerCase();
      const contentType = mimeTypes[ext] || 'text/html; charset=utf-8';

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        res.setHeader('Content-Type', contentType);
        return res.end(fs.readFileSync(filePath));
      }

      const indexPath = path.join(__dirname, 'index.html');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(fs.readFileSync(indexPath));
    } catch (err) {
      res.statusCode = 500;
      res.end('Server Error: ' + (err && err.message));
    }
  };
}
