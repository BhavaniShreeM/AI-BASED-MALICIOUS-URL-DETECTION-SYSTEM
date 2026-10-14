/**
 * Data types for AI-Based Malicious URL Detection System
 */

export interface UrlFeatures {
  urlLength: number;
  domainLength: number;
  dotCount: number;
  subdomainCount: number;
  hasIpAddress: boolean;
  hasAtSymbol: boolean;
  hasDoubleSlashRedirect: boolean;
  hyphenCount: number;
  isShortened: boolean;
  suspiciousKeywordCount: number;
  suspiciousKeywordsFound: string[];
  hasHttps: boolean;
  digitRatio: number;
  specialCharCount: number;
  pathDepth: number;
  queryLength: number;
  entropy: number;
  hasPort: boolean;
  isSuspiciousTld: boolean;
}

export type RiskSeverity = 'low' | 'medium' | 'high';

export interface RiskFactor {
  id: string;
  category: 'structural' | 'deceptive' | 'lexical' | 'protocol';
  title: string;
  value: string | number;
  baseline: string;
  severity: RiskSeverity;
  description: string;
  whyItMatters: string;
}

export type UrlVerdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';

export interface ProbabilityDistribution {
  safe: number;
  suspicious: number;
  malicious: number;
}

export interface TreeVoteResult {
  safeVotes: number;
  suspiciousVotes: number;
  maliciousVotes: number;
  totalTrees: number;
}

export interface UrlComponents {
  originalUrl: string;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  subdomain: string;
  domain: string;
  tld: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
}

export interface ClassificationResult {
  url: string;
  components: UrlComponents;
  features: UrlFeatures;
  verdict: UrlVerdict;
  confidenceScore: number;
  probabilities: ProbabilityDistribution;
  treeVotes: TreeVoteResult;
  riskScore: number; // 0 to 100
  riskFactors: RiskFactor[];
  recommendations: string[];
  executionTimeMs: number;
  analyzedAt: string;
}

export interface BenchmarkSample {
  url: string;
  label: UrlVerdict;
  category: 'Legitimate' | 'Phishing' | 'Malware' | 'Defacement' | 'Shortener';
  source: string;
  notes: string;
}
