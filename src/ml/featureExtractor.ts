/**
 * URL Feature Extractor for Machine Learning Classification
 * Extracts 18 lexical, structural, and heuristic indicators.
 */

import { RiskFactor, UrlComponents, UrlFeatures } from '../types';

// Curated list of known URL shortening domains
export const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'bit.do',
  'tiny.cc',
  'shorte.st',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
  'bl.ink',
  'lnkd.in',
  'qr.net',
  'v.gd',
]);

// Suspicious keywords frequently used in phishing and social engineering
export const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'log-in',
  'verify',
  'verification',
  'security',
  'account',
  'banking',
  'secure',
  'update',
  'paypal',
  'appleid',
  'support',
  'wallet',
  'recover',
  'billing',
  'authenticate',
  'confirm',
  'passcode',
  'password',
  'webscr',
  'ebayisapi',
  'free-gift',
  'claim',
  'bonus',
  'unlock',
  'suspended',
];

// High-abuse top-level domains frequently associated with spam and disposable phishing
export const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'work',
  'click',
  'loan',
  'gq',
  'cf',
  'ml',
  'ga',
  'tk',
  'buzz',
  'fit',
  'surf',
  'racing',
  'date',
  'icu',
  'cam',
  'rest',
]);

// IPv4 address detection regex
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * Validates whether an input string has a plausible URL / domain format
 */
export function validateUrlFormat(rawInput: string): { isValid: boolean; error?: string } {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { isValid: false, error: 'URL input cannot be empty.' };
  }

  // Prevent absurdly short inputs or plain words without dot or IP
  if (trimmed.length < 3) {
    return { isValid: false, error: 'URL is too short to be evaluated.' };
  }

  // Check if it's plain text without any dot or colon
  if (!trimmed.includes('.') && !trimmed.includes(':')) {
    return {
      isValid: false,
      error: 'Invalid format: A valid URL must contain a domain with an extension (e.g., example.com) or an IP address.',
    };
  }

  // Try parsing with URL constructor
  try {
    let urlToTest = trimmed;
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      urlToTest = 'https://' + trimmed;
    }
    const parsed = new URL(urlToTest);
    if (!parsed.hostname || parsed.hostname.length < 2) {
      return { isValid: false, error: 'Invalid hostname format.' };
    }
    return { isValid: true };
  } catch {
    return {
      isValid: false,
      error: 'Malformed URL: Could not parse standard URL components. Please verify formatting.',
    };
  }
}

/**
 * Parses URL into structural sub-components
 */
export function parseUrlComponents(rawInput: string): UrlComponents {
  const trimmed = rawInput.trim();
  let normalized = trimmed;
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    normalized = 'https://' + trimmed;
  }

  const parsed = new URL(normalized);
  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port;

  // Split hostname into subdomains, domain name, and TLD
  const hostParts = hostname.split('.');
  let tld = '';
  let domain = hostname;
  let subdomain = '';

  if (IPV4_REGEX.test(hostname)) {
    tld = 'IPv4';
    domain = hostname;
    subdomain = '';
  } else if (hostParts.length >= 2) {
    tld = hostParts[hostParts.length - 1];
    domain = hostParts[hostParts.length - 2] + '.' + tld;
    if (hostParts.length > 2) {
      subdomain = hostParts.slice(0, hostParts.length - 2).join('.');
    }
  }

  return {
    originalUrl: trimmed,
    normalizedUrl: normalized,
    protocol: parsed.protocol.replace(':', ''),
    hostname,
    subdomain,
    domain,
    tld,
    port,
    pathname: parsed.pathname || '/',
    search: parsed.search || '',
    hash: parsed.hash || '',
  };
}

/**
 * Calculates Shannon Entropy of a string to measure character randomness.
 * Formula: H(X) = - sum( P(x) * log2(P(x)) )
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Extracts 18 core features from a URL
 */
export function extractUrlFeatures(rawInput: string): { features: UrlFeatures; components: UrlComponents } {
  const components = parseUrlComponents(rawInput);
  const url = components.normalizedUrl;
  const lowerUrl = url.toLowerCase();
  const hostname = components.hostname;

  // 1. URL Length
  const urlLength = url.length;

  // 2. Domain Length
  const domainLength = hostname.length;

  // 3. Dot Count
  const dotCount = (url.match(/\./g) || []).length;

  // 4. Subdomain Count
  const hostParts = hostname.split('.');
  const subdomainCount = Math.max(0, hostParts.length - 2);

  // 5. Raw IP Address in Hostname
  const hasIpAddress = IPV4_REGEX.test(hostname) || /\[[0-9a-fA-F:]+\]/.test(hostname);

  // 6. Embedded '@' symbol (Credential confusion / browser redirect exploit)
  const hasAtSymbol = url.includes('@');

  // 7. Double Slash redirect in path (e.g., http://trusted.com//malicious.com)
  const afterScheme = url.replace(/^[a-zA-Z]+:\/\//, '');
  const hasDoubleSlashRedirect = afterScheme.includes('//');

  // 8. Hyphen Count in Domain
  const hyphenCount = (hostname.match(/-/g) || []).length;

  // 9. URL Shortener Service Check
  const isShortened = KNOWN_SHORTENERS.has(hostname);

  // 10. Suspicious Keywords
  const matchedKeywords: string[] = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lowerUrl.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  const suspiciousKeywordCount = matchedKeywords.length;

  // 11. HTTPS Protocol (1 for https, 0 for http)
  const hasHttps = components.protocol === 'https';

  // 12. Digit Ratio
  const digitCount = (url.match(/\d/g) || []).length;
  const digitRatio = Number((digitCount / Math.max(1, urlLength)).toFixed(3));

  // 13. Special Characters Count
  const specialChars = (url.match(/[?=&%_~;+!-]/g) || []).length;

  // 14. Path Depth
  const pathSegments = components.pathname.split('/').filter(Boolean);
  const pathDepth = pathSegments.length;

  // 15. Query Length
  const queryLength = components.search.length;

  // 16. Shannon Entropy
  const entropy = calculateShannonEntropy(url);

  // 17. Non-standard Port
  const hasPort = Boolean(components.port && components.port !== '80' && components.port !== '443');

  // 18. High-Risk / Suspicious TLD
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(components.tld.toLowerCase());

  const features: UrlFeatures = {
    urlLength,
    domainLength,
    dotCount,
    subdomainCount,
    hasIpAddress,
    hasAtSymbol,
    hasDoubleSlashRedirect,
    hyphenCount,
    isShortened,
    suspiciousKeywordCount,
    suspiciousKeywordsFound: matchedKeywords,
    hasHttps,
    digitRatio,
    specialCharCount: specialChars,
    pathDepth,
    queryLength,
    entropy,
    hasPort,
    isSuspiciousTld,
  };

  return { features, components };
}

/**
 * Evaluates extracted features and generates explainable risk factors
 */
export function identifyRiskFactors(features: UrlFeatures, components: UrlComponents): RiskFactor[] {
  const factors: RiskFactor[] = [];

  // IP Address
  if (features.hasIpAddress) {
    factors.push({
      id: 'ip_address',
      category: 'protocol',
      title: 'Raw IP Address Used Instead of Domain',
      value: components.hostname,
      baseline: 'Legitimate sites use registered domain names',
      severity: 'high',
      description: 'The URL uses a direct IP address rather than a domain name.',
      whyItMatters:
        'Attackers often host malware or phishing pages directly on IP addresses to bypass domain registration and identity checks.',
    });
  }

  // At Symbol
  if (features.hasAtSymbol) {
    factors.push({
      id: 'at_symbol',
      category: 'deceptive',
      title: 'Embedded "@" Character Detected',
      value: 'Present in URL',
      baseline: 'Absent in clean URLs',
      severity: 'high',
      description: 'Browsers treat strings before the "@" as userinfo and route traffic to the server after it.',
      whyItMatters:
        'Phishers disguise destinations by putting trusted brand names before the "@" (e.g., https://paypal.com@evil-site.net), tricking unsuspecting victims.',
    });
  }

  // Double Slash Redirect
  if (features.hasDoubleSlashRedirect) {
    factors.push({
      id: 'double_slash',
      category: 'deceptive',
      title: 'Path Double-Slash (//) Redirection Attempt',
      value: 'Detected in path',
      baseline: 'Single slashes only',
      severity: 'high',
      description: 'The path contains a double forward slash after the domain protocol.',
      whyItMatters:
        'This technique is used to bypass URL filters or trigger open-redirect vulnerabilities on target servers.',
    });
  }

  // Suspicious TLD
  if (features.isSuspiciousTld) {
    factors.push({
      id: 'suspicious_tld',
      category: 'structural',
      title: `High-Risk Top-Level Domain (.${components.tld})`,
      value: `.${components.tld}`,
      baseline: 'Standard commercial TLD (.com, .org, .edu, .gov)',
      severity: 'medium',
      description: `The domain extension .${components.tld} is frequently abused for spam campaigns due to cheap or free registrations.`,
      whyItMatters:
        'Disposable TLDs are statistically overrepresented in phishing and malicious spam datasets.',
    });
  }

  // Suspicious Keywords
  if (features.suspiciousKeywordCount > 0) {
    const severity = features.suspiciousKeywordCount >= 3 ? 'high' : 'medium';
    factors.push({
      id: 'suspicious_keywords',
      category: 'deceptive',
      title: `Security/Financial Keywords Found (${features.suspiciousKeywordCount})`,
      value: features.suspiciousKeywordsFound.join(', '),
      baseline: 'No deceptive keywords',
      severity,
      description: `URL contains targeted terms: "${features.suspiciousKeywordsFound.join('", "')}".`,
      whyItMatters:
        'Phishing pages mimic legitimate bank, wallet, and security recovery portals to manipulate users into submitting credentials.',
    });
  }

  // URL Shortener
  if (features.isShortened) {
    factors.push({
      id: 'shortener',
      category: 'deceptive',
      title: 'Known URL Shortening Service',
      value: components.hostname,
      baseline: 'Direct full destination URL',
      severity: 'medium',
      description: 'The URL uses a redirect service that obscures the real destination.',
      whyItMatters:
        'Attackers leverage link shorteners to hide malicious target domains from email scanners and preview banners.',
    });
  }

  // Subdomain Depth
  if (features.subdomainCount >= 3) {
    factors.push({
      id: 'subdomain_count',
      category: 'structural',
      title: `Excessive Subdomain Levels (${features.subdomainCount})`,
      value: `${features.subdomainCount} levels (${components.subdomain})`,
      baseline: '0 to 1 subdomain (e.g., www or api)',
      severity: features.subdomainCount >= 4 ? 'high' : 'medium',
      description: 'Deep nested subdomains were detected.',
      whyItMatters:
        'Phishing kits often stack subdomains like "paypal.com.verification.login.attacker.com" to mislead users on mobile viewports.',
    });
  }

  // Hyphen Count
  if (features.hyphenCount >= 3) {
    factors.push({
      id: 'hyphen_count',
      category: 'structural',
      title: `High Hyphen Count in Hostname (${features.hyphenCount})`,
      value: `${features.hyphenCount} hyphens`,
      baseline: '0 to 1 hyphen',
      severity: 'medium',
      description: 'Multiple hyphens were found in the hostname.',
      whyItMatters:
        'Hyphens are commonly used in typosquatting and deceptive mimicry (e.g., "bank-login-security-portal").',
    });
  }

  // URL Length
  if (features.urlLength > 75) {
    factors.push({
      id: 'url_length',
      category: 'lexical',
      title: `Abnormally Long URL (${features.urlLength} characters)`,
      value: `${features.urlLength} chars`,
      baseline: 'Average clean URL is under 55 chars',
      severity: features.urlLength > 120 ? 'high' : 'medium',
      description: 'The URL length is unusually extended.',
      whyItMatters:
        'Attackers elongate URLs with embedded payloads, deep paths, or tracking tokens to push the suspicious domain off-screen on mobile screens.',
    });
  }

  // Entropy (Shannon Randomness)
  if (features.entropy > 4.35) {
    factors.push({
      id: 'entropy',
      category: 'lexical',
      title: `High Character Entropy (${features.entropy})`,
      value: `${features.entropy} bits/char`,
      baseline: 'Natural language URLs typically score 3.2 - 4.1',
      severity: 'medium',
      description: 'High character randomness detected.',
      whyItMatters:
        'Domain Generation Algorithms (DGA) and automated obfuscation tools generate pseudorandom strings with elevated entropy.',
    });
  }

  // Plain HTTP (No Encryption)
  if (!features.hasHttps) {
    factors.push({
      id: 'no_https',
      category: 'protocol',
      title: 'Unencrypted HTTP Protocol (No TLS/SSL)',
      value: 'http://',
      baseline: 'https:// with TLS encryption',
      severity: 'medium',
      description: 'Traffic to this website is transmitted in cleartext without encryption.',
      whyItMatters:
        'While HTTPS does NOT guarantee a website is legitimate (many phishing sites use free SSL), unencrypted HTTP leaves traffic open to interception and tamper.',
    });
  }

  // Non-standard Port
  if (features.hasPort) {
    factors.push({
      id: 'non_standard_port',
      category: 'protocol',
      title: `Non-Standard Web Port (:${components.port})`,
      value: `Port ${components.port}`,
      baseline: 'Standard ports 80 (HTTP) or 443 (HTTPS)',
      severity: 'medium',
      description: 'The URL specifies a custom port number.',
      whyItMatters:
        'Attackers frequently run transient malicious servers or proxies on arbitrary ports like 8080, 8443, or 3000.',
    });
  }

  return factors;
}
