/**
 * AI-Based Malicious URL Detection System
 * Cybersecurity Dashboard for College Hackathon
 */

import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  BookOpen,
  CheckCircle,
  Code2,
  Cpu,
  Database,
  FileCode,
  Info,
  Lock,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
} from 'lucide-react';
import { DatasetPipelineView } from './components/DatasetPipelineView';

interface ExtractedFeatures {
  urlLength: number;
  domainLength: number;
  dotCount: number;
  subdomainCount: number;
  hasIpAddress: boolean;
  hasAtSymbol: boolean;
  hasDoubleSlashRedirect: boolean;
  hyphenCount: number;
  isShortened: boolean;
  suspiciousKeywordsFound: string[];
  hasHttps: boolean;
  entropy: number;
  tld: string;
}

interface RiskIndicator {
  id: string;
  title: string;
  value: string;
  severity: 'clean' | 'warning' | 'danger';
  description: string;
}

interface ScanResult {
  url: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  confidenceText: string;
  maliciousProbability?: number;
  legitimateProbability?: number;
  confidencePercentage?: number;
  decisionThresholds?: Record<string, string>;
  indicators: RiskIndicator[];
  recommendations: string[];
  features?: Record<string, number>;
  consensus?: { total_trees: number; trees_voting_malicious: number; trees_voting_legitimate: number };
  scannedAt: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'dataset' | 'feature_info' | 'vanilla_code'>('dashboard');
  const [urlInput, setUrlInput] = useState<string>('http://192.168.1.104/paypal.com/login.php');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [selectedCodeFile, setSelectedCodeFile] = useState<'html' | 'css' | 'js'>('html');
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  // Initial scan on load for instant demonstration
  useEffect(() => {
    executeScan('http://192.168.1.104/paypal.com/login.php');
  }, []);

  const validateUrl = (raw: string): { isValid: boolean; error?: string } => {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { isValid: false, error: 'Please enter a website URL to scan.' };
    }
    if (trimmed.length < 3) {
      return { isValid: false, error: 'URL is too short to be evaluated.' };
    }
    if (!trimmed.includes('.') && !trimmed.includes(':')) {
      return {
        isValid: false,
        error: 'Invalid format: A valid URL must contain a domain (e.g. example.com) or an IP address.',
      };
    }
    return { isValid: true };
  };

  const handleScanSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const check = validateUrl(urlInput);
    if (!check.isValid) {
      setValidationError(check.error || 'Invalid URL');
      return;
    }
    setValidationError(null);
    executeScan(urlInput.trim());
  };

  const executeScan = async (rawUrl: string) => {
    setIsLoading(true);
    setValidationError(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ url: rawUrl }),
      });

      if (response.status === 400) {
        const errData = await response.json().catch(() => ({}));
        setValidationError(errData.error || 'Invalid URL format');
        setIsLoading(false);
        return;
      }

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();

      const indicators: RiskIndicator[] = (data.risk_factors || []).map((factor: any, idx: number) => {
        if (typeof factor === 'string') {
          const isDanger = data.verdict === 'MALICIOUS';
          const isWarning = data.verdict === 'SUSPICIOUS';
          return {
            id: `factor-${idx}`,
            title: factor.includes('IPv4') || factor.includes('IP address')
              ? 'Raw IP Hostname'
              : factor.includes('@')
              ? 'Credential Confusion (@)'
              : factor.includes('HTTPS')
              ? 'Unencrypted HTTP Protocol'
              : factor.includes('keyword')
              ? 'Sensitive Keyword Density'
              : factor.includes('subdomain')
              ? 'Subdomain Nesting'
              : factor.includes('hyphen')
              ? 'Domain Hyphens'
              : factor.includes('length')
              ? 'Abnormal Length'
              : 'Threat Feature',
            value: factor,
            severity: isDanger ? 'danger' : isWarning ? 'warning' : 'clean',
            description: factor,
          };
        }
        return {
          id: factor.id || `factor-${idx}`,
          title: factor.title || 'Risk Factor',
          value: factor.value || '',
          severity: factor.status === 'critical' ? 'danger' : factor.status === 'warning' ? 'warning' : 'clean',
          description: factor.desc || factor.description || '',
        };
      });

      if (indicators.length === 0) {
        indicators.push({
          id: 'clean_baseline',
          title: 'Standard Lexical Structure',
          value: data.url,
          severity: 'clean',
          description: 'No malicious features detected by the Random Forest classifier.',
        });
      }

      setResult({
        url: data.url || rawUrl,
        verdict: data.verdict,
        confidenceText: `${data.confidence_percentage}% Confidence (Random Forest)`,
        maliciousProbability: data.malicious_probability,
        legitimateProbability: data.legitimate_probability,
        confidencePercentage: data.confidence_percentage,
        decisionThresholds: data.decision_thresholds,
        indicators,
        recommendations: data.recommendations || [],
        features: data.features,
        consensus: data.ensemble_consensus,
        scannedAt: new Date().toLocaleTimeString(),
      });
    } catch (apiErr) {
      console.warn('API error, executing client-side heuristic fallback:', apiErr);
      runLocalFallback(rawUrl);
    } finally {
      setIsLoading(false);
    }
  };

  const runLocalFallback = (rawUrl: string) => {
    try {
      let normalized = rawUrl.trim();
      if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
        normalized = 'https://' + normalized;
      }

      let parsed: URL;
      try {
        parsed = new URL(normalized);
      } catch {
        setValidationError('Malformed URL structure. Please check input formatting.');
        setIsLoading(false);
        return;
      }

      const hostname = parsed.hostname.toLowerCase();
      const urlLower = normalized.toLowerCase();

      const isIp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname);
      const hasAt = normalized.includes('@');
      const hasDoubleSlash = normalized.replace(/^[a-zA-Z]+:\/\//, '').includes('//');
      const isShortened = /bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly/.test(hostname);
      
      const suspiciousWords = ['login', 'verify', 'account', 'banking', 'secure', 'update', 'paypal', 'appleid', 'wallet', 'bonus', 'claim', 'recover'];
      const matchedKeywords = suspiciousWords.filter((kw) => urlLower.includes(kw));

      const hostParts = hostname.split('.');
      const tld = hostParts.length >= 2 ? hostParts[hostParts.length - 1] : '';
      const isSuspiciousTld = ['xyz', 'top', 'buzz', 'tk', 'ml', 'cf', 'gq', 'rest', 'icu'].includes(tld);
      const subdomainCount = Math.max(0, hostParts.length - 2);
      const hyphenCount = (hostname.match(/-/g) || []).length;
      const hasHttps = parsed.protocol === 'https:';

      const indicators: RiskIndicator[] = [];

      if (isIp) {
        indicators.push({
          id: 'ip',
          title: 'Raw IP Hostname',
          value: hostname,
          severity: 'danger',
          description: 'Direct IP usage bypasses domain name registration identity records (WHOIS) and is heavily favored by malware hosts.',
        });
      }

      if (hasAt) {
        indicators.push({
          id: 'at_symbol',
          title: 'Embedded "@" Credential Spoofing',
          value: 'Detected in URL',
          severity: 'danger',
          description: 'Browsers treat strings before the "@" as username authentication and route traffic to the server that follows.',
        });
      }

      if (hasDoubleSlash) {
        indicators.push({
          id: 'double_slash',
          title: 'Path Double-Slash (//)',
          value: 'Detected in URL path',
          severity: 'danger',
          description: 'Used to confuse URL parsers and execute open redirection attacks.',
        });
      }

      if (matchedKeywords.length > 0) {
        indicators.push({
          id: 'keywords',
          title: 'Deceptive Security/Banking Keywords',
          value: matchedKeywords.join(', '),
          severity: matchedKeywords.length >= 2 ? 'danger' : 'warning',
          description: `URL contains targeted terms ("${matchedKeywords.join('", "')}") frequently used in credential harvesting scams.`,
        });
      }

      if (isShortened) {
        indicators.push({
          id: 'shortener',
          title: 'Known URL Shortening Service',
          value: hostname,
          severity: 'warning',
          description: 'Shortened URLs mask the true destination domain, preventing inspection before click.',
        });
      }

      if (isSuspiciousTld) {
        indicators.push({
          id: 'tld',
          title: `High-Abuse Domain Extension (.${tld})`,
          value: `.${tld}`,
          severity: 'warning',
          description: 'This top-level domain has statistically high association with disposable phishing campaigns.',
        });
      }

      if (subdomainCount >= 2) {
        indicators.push({
          id: 'subdomains',
          title: `Nested Subdomain Depth (${subdomainCount})`,
          value: `${subdomainCount} subdomains`,
          severity: subdomainCount >= 3 ? 'danger' : 'warning',
          description: 'Attackers nest multiple subdomains to mimic trusted institutions and hide the true domain on mobile browsers.',
        });
      }

      if (hyphenCount >= 2) {
        indicators.push({
          id: 'hyphens',
          title: `Multiple Domain Hyphens (${hyphenCount})`,
          value: `${hyphenCount} hyphens`,
          severity: 'warning',
          description: 'Multiple hyphens often signal typosquatting brands (e.g. bank-verify-login).',
        });
      }

      if (!hasHttps) {
        indicators.push({
          id: 'http',
          title: 'Unencrypted HTTP Protocol',
          value: 'http://',
          severity: 'warning',
          description: 'Traffic is unencrypted cleartext. (Note: HTTPS only encrypts communication; it does not prove legitimacy).',
        });
      }

      if (indicators.length === 0) {
        indicators.push({
          id: 'clean_domain',
          title: 'Standard Domain Structure',
          value: hostname,
          severity: 'clean',
          description: 'Standard domain name with verified hierarchical structure and conventional top-level domain.',
        });
      }

      let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';
      let confidenceText = 'Local Heuristic Analysis';
      const recommendations: string[] = [];

      if (isIp || hasAt || (matchedKeywords.length >= 2 && isSuspiciousTld) || hasDoubleSlash) {
        verdict = 'MALICIOUS';
        confidenceText = 'High Threat Signature Match';
        recommendations.push(
          'DO NOT open or visit this URL. It exhibits classic indicators of malicious phishing or malware delivery.',
          'Never enter login credentials, passwords, or one-time verification passcodes on this page.',
          'If this link was received in an email or SMS, report it to your security administrator or spam filter.'
        );
      } else if (isShortened || isSuspiciousTld || matchedKeywords.length > 0 || subdomainCount >= 2 || !hasHttps) {
        verdict = 'SUSPICIOUS';
        confidenceText = 'Anomalous Patterns Detected';
        recommendations.push(
          'Exercise high caution. Inspect the domain carefully before taking any action.',
          'If this is a shortened link, expand it with a URL expander to verify the real destination.',
          'Remember: A padlock icon (HTTPS) only encrypts transit; it does NOT mean the website is safe.'
        );
      } else {
        verdict = 'SAFE';
        confidenceText = 'Standard Baseline Match';
        recommendations.push(
          'This URL displays clean lexical and structural properties consistent with legitimate web services.',
          'Always verify the website address in your browser address bar matches your intended destination.'
        );
      }

      setResult({
        url: normalized,
        verdict,
        confidenceText,
        indicators,
        recommendations,
        scannedAt: new Date().toLocaleTimeString(),
      });
    } catch (err) {
      console.error('Local fallback scan error:', err);
    }
  };

  const sampleLinks = [
    { label: 'Clean Search', url: 'https://www.google.com/search?q=machine+learning+cybersecurity' },
    { label: 'Shortened Link', url: 'http://bit.ly/3xY9PqL-security-notice' },
    { label: 'Direct IP Phishing', url: 'http://192.168.1.104/paypal.com/login.php' },
    { label: 'Credential "@" Spoof', url: 'https://paypal.com@verify-account-update.xyz/auth' },
  ];

  const handleSelectSample = (url: string) => {
    setUrlInput(url);
    setValidationError(null);
    executeScan(url);
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* 1. HEADER SECTION */}
      <header className="sticky top-0 z-40 bg-[#0b0f19]/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between gap-6">
          {/* Brand & Subtitle */}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-white leading-tight">
                AI-Based Malicious URL Detection System
              </h1>
              <p className="text-xs text-slate-400 font-medium">Intelligent URL Threat Analysis</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-6 text-xs sm:text-sm font-medium text-slate-400">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`hover:text-white transition-colors pb-1 ${
                activeTab === 'dashboard' ? 'text-white border-b-2 border-indigo-500 font-semibold' : ''
              }`}
            >
              Threat Scanner
            </button>
            <button
              onClick={() => setActiveTab('dataset')}
              className={`hover:text-white transition-colors pb-1 flex items-center gap-1.5 ${
                activeTab === 'dataset' ? 'text-white border-b-2 border-indigo-500 font-semibold' : ''
              }`}
            >
              <Database className="w-3.5 h-3.5 text-indigo-400" />
              <span>Dataset Pipeline</span>
            </button>
            <button
              onClick={() => setActiveTab('feature_info')}
              className={`hover:text-white transition-colors pb-1 flex items-center gap-1.5 ${
                activeTab === 'feature_info' ? 'text-white border-b-2 border-indigo-500 font-semibold' : ''
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Feature Information</span>
            </button>
            <button
              onClick={() => setActiveTab('vanilla_code')}
              className={`hover:text-white transition-colors pb-1 flex items-center gap-1.5 ${
                activeTab === 'vanilla_code' ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold' : ''
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>HTML/CSS/JS Files</span>
            </button>
          </nav>

          {/* College Hackathon Badge */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Hackathon Build</span>
          </div>
        </div>
      </header>

      {/* Mobile Tab Navigation */}
      <div className="md:hidden bg-slate-900 border-b border-slate-800 px-4 py-2 flex items-center gap-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap ${
            activeTab === 'dashboard' ? 'bg-indigo-600 text-white' : 'text-slate-400'
          }`}
        >
          Scanner Dashboard
        </button>
        <button
          onClick={() => setActiveTab('dataset')}
          className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap ${
            activeTab === 'dataset' ? 'bg-indigo-600 text-white' : 'text-slate-400'
          }`}
        >
          Dataset Pipeline
        </button>
        <button
          onClick={() => setActiveTab('feature_info')}
          className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap ${
            activeTab === 'feature_info' ? 'bg-indigo-600 text-white' : 'text-slate-400'
          }`}
        >
          Feature Info
        </button>
        <button
          onClick={() => setActiveTab('vanilla_code')}
          className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap ${
            activeTab === 'vanilla_code' ? 'bg-indigo-600 text-white' : 'text-slate-400'
          }`}
        >
          HTML/CSS/JS Source
        </button>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-8 animate-fadeIn">
            {/* 2. MAIN URL CHECKER SECTION */}
            <section className="p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-5">
              <div>
                <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">Inspect Website URL</h2>
                <p className="text-sm text-slate-400 mt-1">
                  Enter any website URL to extract lexical features, evaluate threat indicators, and view classification results.
                </p>
              </div>

              {/* Large Input Field & Scan URL Button */}
              <form onSubmit={handleScanSubmit} className="space-y-3">
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
                      <Search className="w-5 h-5 text-slate-400" />
                    </div>
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => {
                        setUrlInput(e.target.value);
                        if (validationError) setValidationError(null);
                      }}
                      placeholder="Enter website URL (e.g., https://example.com or suspicious link)..."
                      className="w-full pl-12 pr-10 py-3.5 rounded-xl bg-slate-950 border border-slate-700 text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all shadow-inner"
                      spellCheck={false}
                      autoComplete="off"
                    />
                    {urlInput && (
                      <button
                        type="button"
                        onClick={() => {
                          setUrlInput('');
                          setValidationError(null);
                        }}
                        className="absolute inset-y-0 right-3 flex items-center text-slate-400 hover:text-slate-200 transition-colors"
                        title="Clear input"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition-all disabled:opacity-50 shadow-lg shadow-indigo-600/25 shrink-0"
                  >
                    {isLoading ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        <span>Scanning URL...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4" />
                        <span>Scan URL</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Input Validation Error */}
                {validationError && (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs">
                    <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>{validationError}</span>
                  </div>
                )}
              </form>

              {/* Sample Test Chips for Quick Judging */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center gap-2 flex-wrap text-xs text-slate-400">
                <span className="font-semibold text-slate-300">Quick Test Samples:</span>
                {sampleLinks.map((item, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleSelectSample(item.url)}
                    className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-all font-mono text-[11px]"
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </section>

            {/* Loading Indicator */}
            {isLoading && (
              <div className="p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center space-y-3 animate-pulse">
                <div className="w-8 h-8 mx-auto border-3 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin" />
                <h3 className="text-base font-semibold text-white">Extracting URL Threat Vectors</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Parsing domain anatomy, lexical character frequencies, and checking for phishing patterns...
                </p>
              </div>
            )}

            {/* 3. RESULTS SECTION (SAFE in Green, SUSPICIOUS in Orange/Yellow, MALICIOUS in Red) */}
            {result && !isLoading && (
              <section className="space-y-6">
                {/* Result Card: SAFE (Green) */}
                {result.verdict === 'SAFE' && (
                  <div className="p-6 sm:p-8 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border border-emerald-500/40 shadow-xl space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <ShieldCheck className="w-8 h-8" />
                        </div>
                        <div>
                          <div className="text-2xl font-extrabold tracking-tight text-emerald-400">
                            SAFE
                          </div>
                          <p className="text-xs text-slate-400">Classified as Legitimate Website</p>
                        </div>
                      </div>
                      <span className="text-xs font-mono px-3 py-1 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300 self-start sm:self-auto">
                        {result.confidenceText}
                      </span>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
                      This URL adheres to standard domain registration conventions, clean lexical distributions, and contains no recognized phishing or credential evasion signatures.
                    </p>
                  </div>
                )}

                {/* Result Card: SUSPICIOUS (Yellow/Orange) */}
                {result.verdict === 'SUSPICIOUS' && (
                  <div className="p-6 sm:p-8 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border border-amber-500/40 shadow-xl space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          <AlertTriangle className="w-8 h-8" />
                        </div>
                        <div>
                          <div className="text-2xl font-extrabold tracking-tight text-amber-400">
                            SUSPICIOUS
                          </div>
                          <p className="text-xs text-slate-400">Anomalous Properties Detected</p>
                        </div>
                      </div>
                      <span className="text-xs font-mono px-3 py-1 rounded bg-amber-950/60 border border-amber-500/30 text-amber-300 self-start sm:self-auto">
                        {result.confidenceText}
                      </span>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
                      This link contains warning traits such as a link shortener, high-abuse TLD, multiple hyphens, or deep subdomains. High caution is advised; never enter passwords or sensitive payment info.
                    </p>
                  </div>
                )}

                {/* Result Card: MALICIOUS (Red) */}
                {result.verdict === 'MALICIOUS' && (
                  <div className="p-6 sm:p-8 rounded-2xl bg-gradient-to-r from-rose-950/50 via-slate-900 to-slate-900 border border-rose-500/50 shadow-xl space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="p-3 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/30">
                          <ShieldAlert className="w-8 h-8" />
                        </div>
                        <div>
                          <div className="text-2xl font-extrabold tracking-tight text-rose-400">
                            MALICIOUS
                          </div>
                          <p className="text-xs text-slate-400">Critical Threat Signatures Identified</p>
                        </div>
                      </div>
                      <span className="text-xs font-mono px-3 py-1 rounded bg-rose-950/60 border border-rose-500/30 text-rose-300 self-start sm:self-auto">
                        {result.confidenceText}
                      </span>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
                      Critical attack vectors identified (such as direct raw IP host routing, credential '@' obfuscation, path redirection, or deceptive banking mimicry). Do not visit or open this link.
                    </p>
                  </div>
                )}

                {/* ML Model Probability & Ensemble Consensus Card */}
                {result.maliciousProbability !== undefined && (
                  <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/80 border border-indigo-500/30 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-indigo-400" />
                        <span className="text-xs font-bold text-white uppercase tracking-wider">
                          Scikit-learn Random Forest Model Inference
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className="text-slate-400">Decision Thresholds:</span>
                        <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/20 text-[10px]">Safe &lt; 0.35</span>
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-500/20 text-[10px]">Suspicious 0.35 - 0.70</span>
                        <span className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-500/20 text-[10px]">Malicious &ge; 0.70</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      {/* Malicious Probability */}
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                        <div className="text-[11px] text-slate-400 font-medium">Malicious Probability</div>
                        <div className="text-lg font-mono font-bold text-rose-400">
                          {(result.maliciousProbability * 100).toFixed(1)}%
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                          <div
                            className="bg-rose-500 h-full rounded-full transition-all duration-500"
                            style={{ width: `${Math.min(100, Math.max(0, result.maliciousProbability * 100))}%` }}
                          />
                        </div>
                      </div>

                      {/* Legitimate Probability */}
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                        <div className="text-[11px] text-slate-400 font-medium">Legitimate Probability</div>
                        <div className="text-lg font-mono font-bold text-emerald-400">
                          {((result.legitimateProbability ?? (1 - result.maliciousProbability)) * 100).toFixed(1)}%
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                          <div
                            className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                            style={{ width: `${Math.min(100, Math.max(0, (result.legitimateProbability ?? (1 - result.maliciousProbability)) * 100))}%` }}
                          />
                        </div>
                      </div>

                      {/* Ensemble Voting Consensus */}
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                        <div className="text-[11px] text-slate-400 font-medium">Ensemble Consensus</div>
                        <div className="text-lg font-mono font-bold text-indigo-300">
                          {result.consensus
                            ? `${result.consensus.trees_voting_malicious}/${result.consensus.total_trees} Trees Threat`
                            : '100 Ensemble Trees'}
                        </div>
                        <p className="text-[10px] text-slate-500 truncate">
                          Majority vote across sub-sampled lexical feature trees
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Inspected URL Ribbon */}
                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-slate-500 font-semibold uppercase">Inspected URL:</span>
                    <code className="text-indigo-400 font-mono truncate">{result.url}</code>
                  </div>
                  <span className="text-slate-500 shrink-0 font-mono">{result.scannedAt}</span>
                </div>

                {/* Detected Risk Indicators Section */}
                <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-bold text-white">Detected Risk Indicators</h3>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Extracted structural, lexical, and heuristic features
                      </p>
                    </div>
                    <span className="text-xs font-mono font-medium px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {result.indicators.length} Indicators
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {result.indicators.map((ind) => (
                      <div
                        key={ind.id}
                        className={`p-4 rounded-xl border space-y-2 transition-all ${
                          ind.severity === 'danger'
                            ? 'bg-rose-950/20 border-rose-500/30'
                            : ind.severity === 'warning'
                            ? 'bg-amber-950/20 border-amber-500/30'
                            : 'bg-slate-950/40 border-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-bold text-white truncate">{ind.title}</span>
                          <span
                            className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                              ind.severity === 'danger'
                                ? 'bg-rose-500/20 text-rose-300'
                                : ind.severity === 'warning'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-emerald-500/10 text-emerald-300'
                            }`}
                          >
                            {ind.severity === 'clean' ? 'Clean' : ind.severity}
                          </span>
                        </div>
                        <div className="font-mono text-xs text-indigo-300 truncate">{ind.value}</div>
                        <p className="text-xs text-slate-400 leading-relaxed">{ind.description}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Safety Recommendations Section */}
                <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-indigo-400" />
                    <h3 className="text-base font-bold text-white">Safety Recommendations</h3>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {result.recommendations.map((rec, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80"
                      >
                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-indigo-500/15 text-indigo-400 font-mono text-xs font-bold shrink-0 mt-0.5">
                          {i + 1}
                        </span>
                        <p className="text-xs text-slate-300 leading-relaxed">{rec}</p>
                      </div>
                    ))}
                  </div>

                  {/* HTTPS Callout Notice */}
                  <div className="pt-3 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-400">
                    <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <span>
                      <strong className="text-slate-300">Important Cybersecurity Note:</strong> An active HTTPS padlock means transit encryption is active, but does NOT guarantee the website is authentic. Attackers frequently register free TLS certificates for phishing sites.
                    </span>
                  </div>
                </div>
              </section>
            )}
          </div>
        )}

        {/* DATASET PREPARATION PIPELINE SECTION */}
        {activeTab === 'dataset' && (
          <DatasetPipelineView />
        )}

        {/* 4. FEATURE INFORMATION SECTION */}
        {activeTab === 'feature_info' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="border-b border-slate-800 pb-4">
              <h2 className="text-xl font-bold text-white">How This Detection System Works</h2>
              <p className="text-xs text-slate-400 mt-1">
                Machine Learning fundamentals and URL feature extraction explained in simple English.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* ML Explanation Card */}
              <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                <div className="flex items-center gap-2.5 text-indigo-400 font-bold text-base">
                  <Cpu className="w-5 h-5" />
                  <span>1. Why Machine Learning?</span>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Traditional web filters rely on static blacklists of known malicious URLs. However, attackers register thousands of brand-new domains every hour (known as <em>zero-day phishing links</em>).
                </p>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Our system uses a <strong>Random Forest Classifier</strong>. Instead of checking if a link is on a blacklist, it analyzes the mathematical patterns of how the URL is constructed—allowing it to catch brand-new scam links that have never been seen before.
                </p>
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono">
                  Ensemble Learning: Multiple decision trees vote on whether the combination of length, symbols, and host structure matches known attacks.
                </div>
              </div>

              {/* URL Feature Extraction Card */}
              <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                <div className="flex items-center gap-2.5 text-indigo-400 font-bold text-base">
                  <FileCode className="w-5 h-5" />
                  <span>2. URL Feature Extraction in Simple English</span>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Before the model can classify a URL, the string must be translated into numerical measurements called <em>features</em>:
                </p>
                <ul className="space-y-2.5 text-xs text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-indigo-400 font-bold">·</span>
                    <span><strong>URL Length:</strong> Phishers build long links to push the fake domain off-screen on mobile phones.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-indigo-400 font-bold">·</span>
                    <span><strong>Raw IP Addresses:</strong> Attackers often use direct numbers like 192.168.1.1 to avoid domain identity checks.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-indigo-400 font-bold">·</span>
                    <span><strong>Credential Spoofing (@):</strong> Browsers ignore text before an '@' and navigate to what follows.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-indigo-400 font-bold">·</span>
                    <span><strong>Subdomain Stacking:</strong> Stacking words like paypal.com.verify.login.attacker.net to mislead users.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-indigo-400 font-bold">·</span>
                    <span><strong>Shannon Entropy:</strong> Measures character randomness to identify machine-generated attack domains.</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* 5. STANDALONE VANILLA HTML/CSS/JS FILES VIEW */}
        {activeTab === 'vanilla_code' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <span>Standalone Frontend Source Code</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Complete vanilla HTML5, CSS3, and JavaScript files created in <code className="text-indigo-300 font-mono">/standalone_frontend</code>.
                </p>
              </div>

              {/* Code File Switcher */}
              <div className="flex items-center gap-1.5 p-1 bg-slate-950 rounded-lg border border-slate-800 shrink-0">
                <button
                  onClick={() => setSelectedCodeFile('html')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedCodeFile === 'html' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  index.html
                </button>
                <button
                  onClick={() => setSelectedCodeFile('css')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedCodeFile === 'css' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  style.css
                </button>
                <button
                  onClick={() => setSelectedCodeFile('js')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedCodeFile === 'js' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  script.js
                </button>
              </div>
            </div>

            {/* Terminal Instructions on Running Locally */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 space-y-2">
              <div className="text-indigo-400 font-bold"># How to run these frontend files on your local computer:</div>
              <div className="text-slate-400">cd standalone_frontend</div>
              <div className="text-emerald-400 font-semibold">python3 -m http.server 8000</div>
              <div className="text-slate-500"># Then open http://localhost:8000 in any web browser</div>
            </div>
          </div>
        )}
      </main>

      {/* 5. FOOTER SECTION */}
      <footer className="mt-auto border-t border-slate-800 bg-[#080c14] py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-center sm:text-left">
          <div>
            <strong className="text-slate-300 font-semibold">AI-Based Malicious URL Detection System</strong>
            <span className="mx-2">·</span>
            <span>Intelligent URL Threat Analysis</span>
          </div>
          <div className="text-[11px] text-slate-500 max-w-xl">
            <strong>Disclaimer:</strong> Predictions generated by this system are based on statistical URL feature extraction and machine learning heuristics. They do not constitute a guaranteed security verdict. Legitimate sites can be compromised, and HTTPS does not ensure site safety.
          </div>
        </div>
      </footer>
    </div>
  );
}
