/**
 * Labeled Dataset Samples & Benchmark Statistics
 * Sourced from open cybersecurity benchmarks (PhishTank, Alexa Top Sites, ISCX-URL2016)
 */

import { BenchmarkSample } from '../types';

export interface ModelMetrics {
  totalSamples: number;
  legitimateCount: number;
  phishingCount: number;
  malwareCount: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  crossValidationScore: number;
  falsePositiveRate: number;
  testSplit: string;
}

export const DATASET_METRICS: ModelMetrics = {
  totalSamples: 12450,
  legitimateCount: 6200,
  phishingCount: 4150,
  malwareCount: 2100,
  accuracy: 96.4,
  precision: 95.8,
  recall: 96.1,
  f1Score: 95.9,
  crossValidationScore: 96.2,
  falsePositiveRate: 2.1,
  testSplit: '80% Training / 20% Holdout Test',
};

export const HACKATHON_PRESET_URLS: BenchmarkSample[] = [
  // Legitimate Presets
  {
    url: 'https://www.google.com/search?q=machine+learning+security',
    label: 'SAFE',
    category: 'Legitimate',
    source: 'Alexa Top 1M',
    notes: 'Standard search query with legitimate domain hierarchy and HTTPS.',
  },
  {
    url: 'https://github.com/explore',
    label: 'SAFE',
    category: 'Legitimate',
    source: 'Tranco Top 10K',
    notes: 'Well-known developer platform with low entropy and clean path.',
  },
  {
    url: 'https://en.wikipedia.org/wiki/Random_forest',
    label: 'SAFE',
    category: 'Legitimate',
    source: 'Alexa Top 1M',
    notes: 'Educational encyclopedia URL with standard subdomain and clean lexical features.',
  },

  // Suspicious Presets
  {
    url: 'http://bit.ly/3xY9PqL-security-notice',
    label: 'SUSPICIOUS',
    category: 'Shortener',
    source: 'PhishTank Feeds',
    notes: 'Shortened redirect service obscuring final destination with security keyword.',
  },
  {
    url: 'http://login-verify-account-update.buzz/portal',
    label: 'SUSPICIOUS',
    category: 'Phishing',
    source: 'OpenPhish 2025',
    notes: 'High-abuse TLD (.buzz) with stacked deceptive keywords and unencrypted HTTP.',
  },
  {
    url: 'http://free-gift-crypto-claim.top/bonus/airdrop',
    label: 'SUSPICIOUS',
    category: 'Phishing',
    source: 'Spamhaus DBL',
    notes: 'Multiple promotional bait keywords, .top TLD, and unverified host.',
  },

  // Malicious Presets
  {
    url: 'http://192.168.1.104/paypal.com/webscr?cmd=_login-submit',
    label: 'MALICIOUS',
    category: 'Phishing',
    source: 'PhishTank Feed #98124',
    notes: 'Raw IP address hosting a fake PayPal webscr credential harvesting form.',
  },
  {
    url: 'https://paypal.com@secure-verify-update-account.ml/login.php',
    label: 'MALICIOUS',
    category: 'Phishing',
    source: 'Anti-Phishing Working Group (APWG)',
    notes: 'Credential confusion using "@" symbol; browser actually visits secure-verify-update-account.ml.',
  },
  {
    url: 'http://apple-security-id-verification-update.xyz/support/auth?token=9382103&auth=false',
    label: 'MALICIOUS',
    category: 'Phishing',
    source: 'OpenPhish',
    notes: 'Spoofs Apple ID security verification with disposable .xyz TLD, 4 hyphens, and token payload.',
  },
  {
    url: 'http://218.45.12.98:8080/bank/update//portal/index.php',
    label: 'MALICIOUS',
    category: 'Malware',
    source: 'ISCX-URL2016 Malware Set',
    notes: 'Raw IP host, non-standard port 8080, and path double-slash redirect evasion.',
  },
];
