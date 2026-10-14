import React, { useState } from 'react';
import { AlertCircle, CheckCircle2, ChevronDown, ChevronUp, Cpu, Filter, Info, ShieldCheck } from 'lucide-react';
import { FEATURE_IMPORTANCE } from '../ml/randomForestModel';
import { ClassificationResult, RiskFactor } from '../types';

interface DeepInspectionProps {
  result: ClassificationResult;
}

type FilterCategory = 'all' | 'flagged' | 'structural' | 'deceptive' | 'lexical' | 'protocol';

export const DeepInspection: React.FC<DeepInspectionProps> = ({ result }) => {
  const { features, riskFactors, components } = result;
  const [activeFilter, setActiveFilter] = useState<FilterCategory>('all');
  const [expandedCard, setExpandedCard] = useState<string | null>(null);

  // Map of 18 full features with descriptions, baselines, and categorization
  const fullFeatureSpecs = [
    {
      key: 'hasAtSymbol',
      category: 'deceptive',
      name: 'Embedded "@" Symbol',
      val: features.hasAtSymbol ? 'Detected (@)' : 'Absent',
      isFlagged: features.hasAtSymbol,
      severity: 'high',
      baseline: 'Absent in clean URLs',
      importance: FEATURE_IMPORTANCE.hasAtSymbol?.importance || 0.145,
      explanation: 'Browsers interpret content before the "@" as authentication userinfo, routing the browser to whatever follows it. Attackers trick users into believing they are visiting a trusted service.',
    },
    {
      key: 'hasIpAddress',
      category: 'protocol',
      name: 'Raw IP Hostname',
      val: features.hasIpAddress ? `${components.hostname} (Direct IP)` : 'Domain Name Used',
      isFlagged: features.hasIpAddress,
      severity: 'high',
      baseline: 'Standard DNS Domain Name',
      importance: FEATURE_IMPORTANCE.hasIpAddress?.importance || 0.138,
      explanation: 'Using direct numerical IP addresses bypasses domain registration identity records (WHOIS) and allows malware servers to spin up and down rapidly.',
    },
    {
      key: 'suspiciousKeywordCount',
      category: 'deceptive',
      name: 'Phishing / Sensitive Keywords',
      val: `${features.suspiciousKeywordCount} (${features.suspiciousKeywordsFound.length > 0 ? features.suspiciousKeywordsFound.join(', ') : 'None'})`,
      isFlagged: features.suspiciousKeywordCount > 0,
      severity: features.suspiciousKeywordCount >= 2 ? 'high' : 'medium',
      baseline: '0 sensitive keywords',
      importance: FEATURE_IMPORTANCE.suspiciousKeywordCount?.importance || 0.125,
      explanation: 'Keywords like login, verify, banking, security, and update are common social engineering lures designed to panic users into sharing passwords.',
    },
    {
      key: 'subdomainCount',
      category: 'structural',
      name: 'Subdomain Depth',
      val: `${features.subdomainCount} subdomains (${components.subdomain || 'none'})`,
      isFlagged: features.subdomainCount >= 2,
      severity: features.subdomainCount >= 3 ? 'high' : 'medium',
      baseline: '0 to 1 subdomain (e.g., www)',
      importance: FEATURE_IMPORTANCE.subdomainCount?.importance || 0.102,
      explanation: 'Excessive subdomain stacking (e.g. paypal.com.secure.login.example.com) hides the true root domain, especially on narrow mobile address bars.',
    },
    {
      key: 'entropy',
      category: 'lexical',
      name: 'Shannon Character Entropy',
      val: `${features.entropy} bits/char`,
      isFlagged: features.entropy > 4.35,
      severity: 'medium',
      baseline: 'Natural URLs: 3.2 - 4.1',
      importance: FEATURE_IMPORTANCE.entropy?.importance || 0.088,
      explanation: 'Shannon entropy measures character unpredictability. High values signal automated Domain Generation Algorithms (DGA) or encoded malware parameters.',
    },
    {
      key: 'isShortened',
      category: 'deceptive',
      name: 'URL Shortener Service',
      val: features.isShortened ? `${components.hostname} (Shortener)` : 'Direct Destination',
      isFlagged: features.isShortened,
      severity: 'medium',
      baseline: 'Direct full URL',
      importance: FEATURE_IMPORTANCE.isShortened?.importance || 0.082,
      explanation: 'Link shorteners mask the real destination server, hiding phishing domains from email security gateways and user previews.',
    },
    {
      key: 'urlLength',
      category: 'lexical',
      name: 'URL Total Length',
      val: `${features.urlLength} characters`,
      isFlagged: features.urlLength > 75,
      severity: features.urlLength > 120 ? 'high' : 'medium',
      baseline: 'Typical benign URL: < 55 chars',
      importance: FEATURE_IMPORTANCE.urlLength?.importance || 0.075,
      explanation: 'Long URLs are used to push suspicious domain names off-screen on mobile devices and carry base64 encoded tracking payloads.',
    },
    {
      key: 'isSuspiciousTld',
      category: 'structural',
      name: 'Top-Level Domain Reputation',
      val: `.${components.tld}`,
      isFlagged: features.isSuspiciousTld,
      severity: 'medium',
      baseline: 'Standard commercial TLD (.com, .org, .gov)',
      importance: FEATURE_IMPORTANCE.isSuspiciousTld?.importance || 0.065,
      explanation: 'Certain TLDs (.xyz, .top, .buzz, .tk) offer low-cost or free registrations with minimal identity verification, making them attractive for disposable scam campaigns.',
    },
    {
      key: 'hyphenCount',
      category: 'structural',
      name: 'Domain Hyphen Count',
      val: `${features.hyphenCount} hyphens in domain`,
      isFlagged: features.hyphenCount >= 2,
      severity: 'medium',
      baseline: '0 to 1 hyphen',
      importance: FEATURE_IMPORTANCE.hyphenCount?.importance || 0.058,
      explanation: 'Multiple hyphens are a classic typosquatting hallmark (e.g., "bank-secure-update-login") designed to spoof authentic brand names.',
    },
    {
      key: 'hasDoubleSlashRedirect',
      category: 'deceptive',
      name: 'Path Double Slash (//)',
      val: features.hasDoubleSlashRedirect ? 'Present in path' : 'Absent',
      isFlagged: features.hasDoubleSlashRedirect,
      severity: 'high',
      baseline: 'Standard single slashes',
      importance: FEATURE_IMPORTANCE.hasDoubleSlashRedirect?.importance || 0.046,
      explanation: 'A double slash in the path component can cause URL parsers to misidentify the domain and redirect users to an external attacker-controlled server.',
    },
    {
      key: 'specialCharCount',
      category: 'lexical',
      name: 'Special Character Count',
      val: `${features.specialCharCount} characters (? = & % _ -)`,
      isFlagged: features.specialCharCount > 5,
      severity: 'medium',
      baseline: '0 to 4 special characters',
      importance: FEATURE_IMPORTANCE.specialCharCount?.importance || 0.038,
      explanation: 'Excessive punctuation characters are often used to pass obfuscated instructions, session tokens, or exploit payloads.',
    },
    {
      key: 'digitRatio',
      category: 'lexical',
      name: 'Digit-to-Letter Ratio',
      val: `${(features.digitRatio * 100).toFixed(1)}% numeric`,
      isFlagged: features.digitRatio > 0.18,
      severity: 'medium',
      baseline: '< 10% numeric digits',
      importance: FEATURE_IMPORTANCE.digitRatio?.importance || 0.030,
      explanation: 'High proportion of numerical digits indicates automated randomized naming or encoded hex parameters rather than human-readable text.',
    },
    {
      key: 'hasPort',
      category: 'protocol',
      name: 'Non-Standard Web Port',
      val: features.hasPort ? `Port :${components.port}` : 'Default Port (80 / 443)',
      isFlagged: features.hasPort,
      severity: 'medium',
      baseline: 'Standard HTTP/HTTPS ports',
      importance: FEATURE_IMPORTANCE.hasPort?.importance || 0.026,
      explanation: 'Web applications standardly run on port 80 or 443. Non-standard ports (e.g., 8080, 8443) frequently host rogue listeners or malware droppers.',
    },
    {
      key: 'hasHttps',
      category: 'protocol',
      name: 'TLS / HTTPS Protocol',
      val: features.hasHttps ? 'HTTPS Enabled (TLS)' : 'Unencrypted HTTP',
      isFlagged: !features.hasHttps,
      severity: 'medium',
      baseline: 'HTTPS with TLS encryption',
      importance: FEATURE_IMPORTANCE.hasHttps?.importance || 0.012,
      explanation: 'Unencrypted HTTP exposes data to eavesdropping. Note: Modern phishing sites also use free SSL certificates, so HTTPS alone does NOT prove a website is safe.',
    },
    {
      key: 'domainLength',
      category: 'structural',
      name: 'Domain Character Length',
      val: `${features.domainLength} chars`,
      isFlagged: features.domainLength > 28,
      severity: 'low',
      baseline: 'Average clean domain: 8 - 20 chars',
      importance: 0.022,
      explanation: 'Long domain names frequently embed brand names alongside deceptive qualifiers to confuse victims.',
    },
    {
      key: 'dotCount',
      category: 'structural',
      name: 'Total Period (.) Count',
      val: `${features.dotCount} dots`,
      isFlagged: features.dotCount > 3,
      severity: 'low',
      baseline: '1 to 2 dots',
      importance: 0.020,
      explanation: 'A high count of periods indicates deep domain hierarchy, complex file extensions, or IP address notation.',
    },
    {
      key: 'pathDepth',
      category: 'structural',
      name: 'Directory Path Depth',
      val: `${features.pathDepth} levels`,
      isFlagged: features.pathDepth > 4,
      severity: 'low',
      baseline: '1 to 3 path segments',
      importance: 0.018,
      explanation: 'Deep directory hierarchies are often used in shared hosting environments where attackers hide phishing kits in user accounts.',
    },
    {
      key: 'queryLength',
      category: 'lexical',
      name: 'Query Parameter Length',
      val: `${features.queryLength} chars`,
      isFlagged: features.queryLength > 45,
      severity: 'low',
      baseline: 'Clean URL query: 0 - 30 chars',
      importance: 0.015,
      explanation: 'Overextended query parameters can conceal tracking tokens, redirect parameters, or malicious scripts.',
    },
  ];

  const filteredFeatures = fullFeatureSpecs.filter((item) => {
    if (activeFilter === 'all') return true;
    if (activeFilter === 'flagged') return item.isFlagged;
    return item.category === activeFilter;
  });

  const flaggedCount = fullFeatureSpecs.filter((f) => f.isFlagged).length;

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Extracted Feature Dimensions</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">18 Indicators</div>
          <div className="text-xs text-slate-500 mt-1">Lexical, structural & heuristic vectors</div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Active Threat Indicators</div>
          <div className={`text-2xl font-bold font-mono mt-1 ${flaggedCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {flaggedCount} Flagged
          </div>
          <div className="text-xs text-slate-500 mt-1">Deviations from normal safety baseline</div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Shannon Character Entropy</div>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">{features.entropy} bits</div>
          <div className="text-xs text-slate-500 mt-1">Randomness measure (DGA detection)</div>
        </div>
      </div>

      {/* Shannon Entropy Visualizer Bar */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-300">Shannon Entropy Meter (Randomness vs Natural Words)</span>
          <span className="font-mono text-slate-400">{features.entropy} / 5.0 bits</span>
        </div>
        <div className="relative w-full h-3 rounded-full bg-slate-800 overflow-hidden">
          {/* Safe Zone */}
          <div className="absolute left-0 top-0 bottom-0 w-[60%] bg-emerald-500/20" />
          {/* Moderate Zone */}
          <div className="absolute left-[60%] top-0 bottom-0 w-[20%] bg-amber-500/20" />
          {/* High Entropy Zone */}
          <div className="absolute left-[80%] top-0 bottom-0 w-[20%] bg-rose-500/20" />

          {/* Current Value Marker */}
          <div
            className="absolute top-0 bottom-0 w-2 bg-indigo-400 rounded-full shadow-lg transition-all"
            style={{ left: `${Math.min(100, Math.max(0, (features.entropy / 5.0) * 100))}%` }}
          />
        </div>
        <div className="flex justify-between text-[11px] text-slate-500 font-mono">
          <span>0.0 (Uniform)</span>
          <span>3.2 - 4.1 (Natural Text)</span>
          <span>4.3+ (Algorithmic DGA / Obfuscated)</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-2 pt-2 border-t border-slate-800">
        <div className="flex items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800 overflow-x-auto max-w-full">
          <button
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'all' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Features ({fullFeatureSpecs.length})
          </button>
          <button
            onClick={() => setActiveFilter('flagged')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'flagged' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Flagged Warnings ({flaggedCount})
          </button>
          <button
            onClick={() => setActiveFilter('structural')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'structural' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Domain Structure
          </button>
          <button
            onClick={() => setActiveFilter('deceptive')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'deceptive' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Deceptive Patterns
          </button>
          <button
            onClick={() => setActiveFilter('lexical')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'lexical' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Lexical & Entropy
          </button>
          <button
            onClick={() => setActiveFilter('protocol')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeFilter === 'protocol' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Protocol & IP
          </button>
        </div>
      </div>

      {/* Feature Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredFeatures.map((feat) => {
          const isExpanded = expandedCard === feat.key;
          return (
            <div
              key={feat.key}
              className={`p-4 rounded-xl border transition-all ${
                feat.isFlagged
                  ? 'bg-slate-900/90 border-amber-500/30'
                  : 'bg-slate-900/40 border-slate-800'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  {feat.isFlagged ? (
                    <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="text-sm font-semibold text-white">{feat.name}</div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">{feat.val}</div>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <div className="text-[11px] font-mono text-slate-400">
                    RF Weight: <span className="text-indigo-400 font-semibold">{(feat.importance * 100).toFixed(1)}%</span>
                  </div>
                  <span
                    className={`inline-block text-[10px] font-medium uppercase px-2 py-0.5 rounded mt-1 ${
                      feat.isFlagged
                        ? feat.severity === 'high'
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-amber-500/20 text-amber-300'
                        : 'bg-emerald-500/10 text-emerald-300'
                    }`}
                  >
                    {feat.isFlagged ? `${feat.severity} risk` : 'clean'}
                  </span>
                </div>
              </div>

              {/* Baseline vs Current */}
              <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <span>Baseline: <span className="text-slate-300 font-mono">{feat.baseline}</span></span>
                <button
                  onClick={() => setExpandedCard(isExpanded ? null : feat.key)}
                  className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300 transition-colors text-xs"
                >
                  <span>{isExpanded ? 'Less' : 'Why it matters'}</span>
                  {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* Expanded Explanation */}
              {isExpanded && (
                <div className="mt-3 p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-300 space-y-1 animate-fadeIn">
                  <div className="flex items-center gap-1.5 text-indigo-300 font-medium">
                    <Info className="w-3.5 h-3.5" />
                    <span>Cybersecurity Context</span>
                  </div>
                  <p className="leading-relaxed">{feat.explanation}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
