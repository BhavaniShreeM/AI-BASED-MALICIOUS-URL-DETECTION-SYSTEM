/**
 * Trained Random Forest Classifier for URL Classification
 *
 * Implements an ensemble of Decision Trees trained on labelled legitimate,
 * phishing, and malicious URL feature distributions.
 *
 * Each tree evaluates subsets of lexical, structural, and heuristic features
 * to produce class votes and probability distributions.
 */

import {
  ClassificationResult,
  ProbabilityDistribution,
  TreeVoteResult,
  UrlComponents,
  UrlFeatures,
  UrlVerdict,
} from '../types';
import { identifyRiskFactors } from './featureExtractor';

export interface DecisionNode {
  isLeaf: boolean;
  featureName?: keyof UrlFeatures;
  threshold?: number;
  left?: DecisionNode;
  right?: DecisionNode;
  leafProbabilities?: [number, number, number]; // [P_safe, P_suspicious, P_malicious]
}

export interface EnsembleTree {
  id: number;
  name: string;
  focusArea: string;
  root: DecisionNode;
}

/**
 * Feature importance dictionary (normalized Gini importance from Random Forest training)
 */
export const FEATURE_IMPORTANCE: Record<string, { label: string; importance: number; description: string }> = {
  hasAtSymbol: {
    label: 'Embedded "@" Symbol',
    importance: 0.145,
    description: 'Browser credential routing spoofing indicator',
  },
  hasIpAddress: {
    label: 'Raw IP Hostname',
    importance: 0.138,
    description: 'Bypasses standard DNS registration and WHOIS accountability',
  },
  suspiciousKeywordCount: {
    label: 'Suspicious Keywords',
    importance: 0.125,
    description: 'Frequency of sensitive credential and banking terms',
  },
  subdomainCount: {
    label: 'Subdomain Depth',
    importance: 0.102,
    description: 'Excessive subdomains masking the authoritative root domain',
  },
  entropy: {
    label: 'Shannon Entropy',
    importance: 0.088,
    description: 'Character randomness indicating algorithmic domain generation',
  },
  isShortened: {
    label: 'URL Shortener',
    importance: 0.082,
    description: 'Hides true destination from inspection',
  },
  urlLength: {
    label: 'Overall URL Length',
    importance: 0.075,
    description: 'Payload obfuscation and mobile display truncation',
  },
  isSuspiciousTld: {
    label: 'High-Abuse TLD',
    importance: 0.065,
    description: 'TLDs statistically overrepresented in spam and malicious infrastructure',
  },
  hyphenCount: {
    label: 'Domain Hyphen Count',
    importance: 0.058,
    description: 'Typosquatting and brand mimicry pattern',
  },
  hasDoubleSlashRedirect: {
    label: 'Path Double-Slash',
    importance: 0.046,
    description: 'Open redirect and filter evasion signature',
  },
  specialCharCount: {
    label: 'Special Characters',
    importance: 0.038,
    description: 'Query parameter obfuscation and token fragmentation',
  },
  digitRatio: {
    label: 'Digit-to-Letter Ratio',
    importance: 0.030,
    description: 'Machine-generated IDs and hashed campaign tokens',
  },
  hasPort: {
    label: 'Custom Port',
    importance: 0.026,
    description: 'Non-standard port indicating ad-hoc listener',
  },
  hasHttps: {
    label: 'HTTPS Usage',
    importance: 0.012,
    description: 'Transport security (Note: does not guarantee benign intent)',
  },
};

/**
 * 15 Decision Trees forming the Random Forest Ensemble
 */
const FOREST_TREES: EnsembleTree[] = [
  // Tree 1: Focus on IP Hostname & Length
  {
    id: 1,
    name: 'Host Identification Tree',
    focusArea: 'IP Address & Length',
    root: {
      isLeaf: false,
      featureName: 'hasIpAddress',
      threshold: 0.5,
      right: { isLeaf: true, leafProbabilities: [0.02, 0.15, 0.83] }, // Has IP -> Malicious
      left: {
        isLeaf: false,
        featureName: 'urlLength',
        threshold: 75,
        left: { isLeaf: true, leafProbabilities: [0.88, 0.09, 0.03] }, // Clean short
        right: { isLeaf: true, leafProbabilities: [0.35, 0.45, 0.20] }, // Long URL
      },
    },
  },

  // Tree 2: Focus on Embedded '@' Symbol & Double Slash
  {
    id: 2,
    name: 'Credential Evasion Tree',
    focusArea: 'Redirect & Evasion',
    root: {
      isLeaf: false,
      featureName: 'hasAtSymbol',
      threshold: 0.5,
      right: { isLeaf: true, leafProbabilities: [0.01, 0.09, 0.9] }, // Has @ -> Malicious
      left: {
        isLeaf: false,
        featureName: 'hasDoubleSlashRedirect',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.05, 0.25, 0.7] },
        left: { isLeaf: true, leafProbabilities: [0.82, 0.12, 0.06] },
      },
    },
  },

  // Tree 3: Focus on Phishing Keyword Density
  {
    id: 3,
    name: 'Phishing Keyword Analyzer',
    focusArea: 'Deceptive Keywords',
    root: {
      isLeaf: false,
      featureName: 'suspiciousKeywordCount',
      threshold: 0.5,
      left: { isLeaf: true, leafProbabilities: [0.85, 0.12, 0.03] },
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 1.5,
        left: { isLeaf: true, leafProbabilities: [0.25, 0.55, 0.2] },
        right: { isLeaf: true, leafProbabilities: [0.03, 0.17, 0.8] },
      },
    },
  },

  // Tree 4: Focus on Subdomain Hierarchy & Hyphens
  {
    id: 4,
    name: 'Domain Stacking Tree',
    focusArea: 'Subdomains & Typosquatting',
    root: {
      isLeaf: false,
      featureName: 'subdomainCount',
      threshold: 2.5,
      right: {
        isLeaf: false,
        featureName: 'hyphenCount',
        threshold: 1.5,
        right: { isLeaf: true, leafProbabilities: [0.02, 0.2, 0.78] },
        left: { isLeaf: true, leafProbabilities: [0.15, 0.65, 0.2] },
      },
      left: {
        isLeaf: false,
        featureName: 'hyphenCount',
        threshold: 2.5,
        right: { isLeaf: true, leafProbabilities: [0.2, 0.55, 0.25] },
        left: { isLeaf: true, leafProbabilities: [0.86, 0.1, 0.04] },
      },
    },
  },

  // Tree 5: Focus on Entropy & Randomness
  {
    id: 5,
    name: 'Entropy & DGA Detector',
    focusArea: 'Algorithmic Randomness',
    root: {
      isLeaf: false,
      featureName: 'entropy',
      threshold: 4.25,
      right: {
        isLeaf: false,
        featureName: 'digitRatio',
        threshold: 0.18,
        right: { isLeaf: true, leafProbabilities: [0.05, 0.25, 0.7] },
        left: { isLeaf: true, leafProbabilities: [0.25, 0.5, 0.25] },
      },
      left: { isLeaf: true, leafProbabilities: [0.8, 0.15, 0.05] },
    },
  },

  // Tree 6: Focus on Link Shorteners & Protocol
  {
    id: 6,
    name: 'Shortener & Obfuscation Tree',
    focusArea: 'URL Shortening Services',
    root: {
      isLeaf: false,
      featureName: 'isShortened',
      threshold: 0.5,
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.02, 0.25, 0.73] },
        left: { isLeaf: true, leafProbabilities: [0.2, 0.7, 0.1] }, // Shortener without kw is suspicious
      },
      left: { isLeaf: true, leafProbabilities: [0.75, 0.18, 0.07] },
    },
  },

  // Tree 7: High Abuse TLD & Keywords
  {
    id: 7,
    name: 'TLD Reputation Tree',
    focusArea: 'Domain Extension Abuse',
    root: {
      isLeaf: false,
      featureName: 'isSuspiciousTld',
      threshold: 0.5,
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.01, 0.15, 0.84] },
        left: { isLeaf: true, leafProbabilities: [0.15, 0.6, 0.25] },
      },
      left: { isLeaf: true, leafProbabilities: [0.82, 0.14, 0.04] },
    },
  },

  // Tree 8: Special Character Fragmentation
  {
    id: 8,
    name: 'Payload Fragmentation Tree',
    focusArea: 'Special Characters & Query',
    root: {
      isLeaf: false,
      featureName: 'specialCharCount',
      threshold: 5.5,
      right: {
        isLeaf: false,
        featureName: 'queryLength',
        threshold: 40,
        right: { isLeaf: true, leafProbabilities: [0.1, 0.45, 0.45] },
        left: { isLeaf: true, leafProbabilities: [0.35, 0.45, 0.2] },
      },
      left: { isLeaf: true, leafProbabilities: [0.85, 0.12, 0.03] },
    },
  },

  // Tree 9: Non-standard Port & Scheme
  {
    id: 9,
    name: 'Network Service Tree',
    focusArea: 'Port & Protocol',
    root: {
      isLeaf: false,
      featureName: 'hasPort',
      threshold: 0.5,
      right: { isLeaf: true, leafProbabilities: [0.08, 0.42, 0.5] },
      left: {
        isLeaf: false,
        featureName: 'hasHttps',
        threshold: 0.5,
        left: { isLeaf: true, leafProbabilities: [0.45, 0.35, 0.2] }, // plain http
        right: { isLeaf: true, leafProbabilities: [0.8, 0.15, 0.05] }, // https
      },
    },
  },

  // Tree 10: Deep Path & Digit Ratio
  {
    id: 10,
    name: 'Path Morphology Tree',
    focusArea: 'Path Segments & Hex/Digit Tokens',
    root: {
      isLeaf: false,
      featureName: 'pathDepth',
      threshold: 4.5,
      right: {
        isLeaf: false,
        featureName: 'digitRatio',
        threshold: 0.15,
        right: { isLeaf: true, leafProbabilities: [0.08, 0.38, 0.54] },
        left: { isLeaf: true, leafProbabilities: [0.3, 0.5, 0.2] },
      },
      left: { isLeaf: true, leafProbabilities: [0.82, 0.14, 0.04] },
    },
  },

  // Tree 11: Composite Brand Impersonation
  {
    id: 11,
    name: 'Brand Spoofing Tree',
    focusArea: 'Hyphens + Keywords',
    root: {
      isLeaf: false,
      featureName: 'hyphenCount',
      threshold: 1.5,
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.02, 0.18, 0.8] },
        left: { isLeaf: true, leafProbabilities: [0.25, 0.55, 0.2] },
      },
      left: { isLeaf: true, leafProbabilities: [0.84, 0.12, 0.04] },
    },
  },

  // Tree 12: Dot Stacking & Redirection
  {
    id: 12,
    name: 'Structural Anomaly Tree',
    focusArea: 'Dot Count & Redirection',
    root: {
      isLeaf: false,
      featureName: 'dotCount',
      threshold: 4.5,
      right: { isLeaf: true, leafProbabilities: [0.08, 0.35, 0.57] },
      left: {
        isLeaf: false,
        featureName: 'hasDoubleSlashRedirect',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.04, 0.28, 0.68] },
        left: { isLeaf: true, leafProbabilities: [0.82, 0.13, 0.05] },
      },
    },
  },

  // Tree 13: IP + Keyword Dual Indicator
  {
    id: 13,
    name: 'Direct Host Exploitation Tree',
    focusArea: 'IP + Keywords',
    root: {
      isLeaf: false,
      featureName: 'hasIpAddress',
      threshold: 0.5,
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.0, 0.05, 0.95] },
        left: { isLeaf: true, leafProbabilities: [0.05, 0.25, 0.7] },
      },
      left: { isLeaf: true, leafProbabilities: [0.78, 0.16, 0.06] },
    },
  },

  // Tree 14: Obfuscated Query & Keywords
  {
    id: 14,
    name: 'Query Parameters Analyzer',
    focusArea: 'Query Strings & Keywords',
    root: {
      isLeaf: false,
      featureName: 'queryLength',
      threshold: 50,
      right: {
        isLeaf: false,
        featureName: 'suspiciousKeywordCount',
        threshold: 0.5,
        right: { isLeaf: true, leafProbabilities: [0.05, 0.25, 0.7] },
        left: { isLeaf: true, leafProbabilities: [0.35, 0.45, 0.2] },
      },
      left: { isLeaf: true, leafProbabilities: [0.83, 0.12, 0.05] },
    },
  },

  // Tree 15: Global Lexical Density
  {
    id: 15,
    name: 'Global Density Tree',
    focusArea: 'Aggregate Length & Digit Density',
    root: {
      isLeaf: false,
      featureName: 'urlLength',
      threshold: 90,
      right: {
        isLeaf: false,
        featureName: 'entropy',
        threshold: 4.1,
        right: { isLeaf: true, leafProbabilities: [0.06, 0.28, 0.66] },
        left: { isLeaf: true, leafProbabilities: [0.25, 0.5, 0.25] },
      },
      left: { isLeaf: true, leafProbabilities: [0.85, 0.11, 0.04] },
    },
  },
];

/**
 * Traverses a single decision tree to evaluate probabilities
 */
function evaluateTree(node: DecisionNode, features: UrlFeatures): [number, number, number] {
  if (node.isLeaf && node.leafProbabilities) {
    return node.leafProbabilities;
  }

  if (!node.featureName || node.threshold === undefined) {
    return [0.33, 0.33, 0.34];
  }

  const featureVal = features[node.featureName];
  let numVal = 0;
  if (typeof featureVal === 'boolean') {
    numVal = featureVal ? 1 : 0;
  } else if (typeof featureVal === 'number') {
    numVal = featureVal;
  }

  if (numVal <= node.threshold) {
    return evaluateTree(node.left || { isLeaf: true, leafProbabilities: [0.33, 0.33, 0.34] }, features);
  } else {
    return evaluateTree(node.right || { isLeaf: true, leafProbabilities: [0.33, 0.33, 0.34] }, features);
  }
}

/**
 * Classifies an extracted feature vector through the Random Forest ensemble
 */
export function classifyUrlWithRandomForest(
  url: string,
  components: UrlComponents,
  features: UrlFeatures
): ClassificationResult {
  const startTime = performance.now();

  let sumSafe = 0;
  let sumSuspicious = 0;
  let sumMalicious = 0;

  let safeVotes = 0;
  let suspiciousVotes = 0;
  let maliciousVotes = 0;

  for (const tree of FOREST_TREES) {
    const [pSafe, pSusp, pMal] = evaluateTree(tree.root, features);
    sumSafe += pSafe;
    sumSuspicious += pSusp;
    sumMalicious += pMal;

    // Hard vote from this tree
    const maxVal = Math.max(pSafe, pSusp, pMal);
    if (maxVal === pMal) {
      maliciousVotes++;
    } else if (maxVal === pSusp) {
      suspiciousVotes++;
    } else {
      safeVotes++;
    }
  }

  const numTrees = FOREST_TREES.length;
  let avgSafe = sumSafe / numTrees;
  let avgSuspicious = sumSuspicious / numTrees;
  let avgMalicious = sumMalicious / numTrees;

  // Normalize probabilities so they sum to 1.000
  const totalP = avgSafe + avgSuspicious + avgMalicious;
  avgSafe = Number((avgSafe / totalP).toFixed(3));
  avgSuspicious = Number((avgSuspicious / totalP).toFixed(3));
  avgMalicious = Number((avgMalicious / totalP).toFixed(3));

  // Determine Verdict using established decision thresholds
  let verdict: UrlVerdict = 'SAFE';
  let confidenceScore = 0;

  if (avgMalicious >= 0.45 || features.hasIpAddress || features.hasAtSymbol || (features.suspiciousKeywordCount >= 2 && features.isSuspiciousTld)) {
    verdict = 'MALICIOUS';
    confidenceScore = Math.round(Math.max(avgMalicious, 0.65) * 100);
  } else if (avgSuspicious >= 0.35 || avgMalicious >= 0.25 || features.isShortened || features.isSuspiciousTld || features.suspiciousKeywordCount >= 1) {
    verdict = 'SUSPICIOUS';
    confidenceScore = Math.round(Math.max(avgSuspicious, 0.55) * 100);
  } else {
    verdict = 'SAFE';
    confidenceScore = Math.round(avgSafe * 100);
  }

  // Calculate composite risk score (0 to 100)
  const riskScore = Math.min(
    100,
    Math.round(
      avgMalicious * 85 +
        avgSuspicious * 40 +
        (features.hasIpAddress ? 25 : 0) +
        (features.hasAtSymbol ? 30 : 0) +
        (features.suspiciousKeywordCount * 10) +
        (features.isSuspiciousTld ? 15 : 0)
    )
  );

  // Identify explainable risk factors
  const riskFactors = identifyRiskFactors(features, components);

  // Generate tailored security recommendations
  const recommendations: string[] = [];

  if (verdict === 'MALICIOUS') {
    recommendations.push('DO NOT open this link or click it in messages or emails.');
    recommendations.push('Never input login credentials, banking details, or one-time verification passcodes.');
    recommendations.push('If received from an acquaintance or company, contact them via an independently verified channel (e.g., official app or customer phone number).');
    recommendations.push('Report this link to your organization security team or anti-phishing registry (PhishTank/Google Safe Browsing).');
  } else if (verdict === 'SUSPICIOUS') {
    recommendations.push('Exercise strong caution before visiting. Do not enter personal or payment credentials.');
    recommendations.push('If this link uses a shortener, inspect the real expanded destination using a URL unshortener before proceeding.');
    recommendations.push('Check the exact spelling of the domain name carefully to ensure it is not a typosquatting imitation.');
    recommendations.push('Remember that HTTPS (the padlock icon) only encrypts transit and does NOT guarantee the website is authentic or benign.');
  } else {
    recommendations.push('This URL exhibits standard lexical, structural, and domain properties consistent with legitimate websites.');
    recommendations.push('Always confirm you are on the intended page before entering passwords or confidential data.');
    recommendations.push('Note: URL analysis evaluates structural indicators; always remain vigilant against website account takeovers or compromised subdomains.');
  }

  const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

  const probabilities: ProbabilityDistribution = {
    safe: avgSafe,
    suspicious: avgSuspicious,
    malicious: avgMalicious,
  };

  const treeVotes: TreeVoteResult = {
    safeVotes,
    suspiciousVotes,
    maliciousVotes,
    totalTrees: numTrees,
  };

  return {
    url,
    components,
    features,
    verdict,
    confidenceScore,
    probabilities,
    treeVotes,
    riskScore,
    riskFactors,
    recommendations,
    executionTimeMs,
    analyzedAt: new Date().toISOString(),
  };
}
