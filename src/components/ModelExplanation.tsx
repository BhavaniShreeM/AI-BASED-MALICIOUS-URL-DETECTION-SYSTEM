import React, { useState } from 'react';
import { BarChart3, Binary, Brain, GitBranch, Layers, ShieldCheck, Sparkles, TrendingUp } from 'lucide-react';
import { DATASET_METRICS } from '../ml/datasetSamples';
import { FEATURE_IMPORTANCE } from '../ml/randomForestModel';

export const ModelExplanation: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'architecture' | 'trees' | 'metrics'>('architecture');

  return (
    <div className="space-y-6">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Brain className="w-5 h-5 text-indigo-400" />
            <h3 className="text-lg font-semibold text-white">How the Random Forest Classifier Works</h3>
          </div>
          <p className="text-sm text-slate-400">
            A beginner-friendly guide to ensemble machine learning, decision tree mechanics, and mathematical feature evaluation.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 shrink-0">
          <button
            onClick={() => setActiveTab('architecture')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'architecture' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Ensemble Architecture
          </button>
          <button
            onClick={() => setActiveTab('trees')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'trees' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Decision Tree Anatomy
          </button>
          <button
            onClick={() => setActiveTab('metrics')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'metrics' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Trained Metrics
          </button>
        </div>
      </div>

      {activeTab === 'architecture' && (
        <div className="space-y-6">
          {/* Conceptual Explanation */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
                <Layers className="w-4 h-4" />
                <span>1. What is an Ensemble?</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Rather than relying on a single algorithm, Random Forest constructs multiple diverse Decision Trees. Each tree analyzes different subsets of features to form independent assessments.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                <GitBranch className="w-4 h-4" />
                <span>2. Democratic Majority Voting</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                When a URL is submitted, all 15 trees evaluate its feature vector simultaneously. The model aggregates their votes and class probabilities to reach a consensus verdict.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
                <ShieldCheck className="w-4 h-4" />
                <span>3. Overfitting Prevention</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                A single tree might memorize specific URLs. By bagging features and averaging predictions across an entire forest, the classifier generalizes effectively to detect novel zero-day phishing links.
              </p>
            </div>
          </div>

          {/* Feature Importance Ranking Chart */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-semibold text-white">Random Forest Gini Feature Importance</h4>
                <p className="text-xs text-slate-400">Relative contribution of each feature in splitting tree nodes</p>
              </div>
              <span className="text-xs font-mono text-indigo-400">Sum = 100%</span>
            </div>

            <div className="space-y-2.5">
              {Object.entries(FEATURE_IMPORTANCE)
                .sort((a, b) => b[1].importance - a[1].importance)
                .map(([key, item]) => {
                  const pct = Math.round(item.importance * 100);
                  return (
                    <div key={key} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-slate-300">{item.label}</span>
                        <span className="text-indigo-400 font-bold">{pct}%</span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-indigo-500 to-indigo-400 rounded-full"
                          style={{ width: `${pct * 3.5}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'trees' && (
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div>
            <h4 className="text-sm font-semibold text-white">Decision Tree Traversal Simulation</h4>
            <p className="text-xs text-slate-400">
              See how a sample malicious URL (`http://192.168.1.1/paypal/login`) travels down a decision tree.
            </p>
          </div>

          {/* ASCII / Box-drawn tree visualization */}
          <div className="p-4 rounded-lg bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto space-y-3 border border-slate-800">
            <div className="text-indigo-400 font-semibold">[ROOT NODE] Is hostname a raw IP address? (hasIpAddress &gt; 0.5)</div>
            <div className="pl-6 border-l-2 border-slate-700 space-y-2">
              <div className="text-emerald-400">
                ├─► YES (Branch Right): Hostname is direct IP (192.168.1.1)
              </div>
              <div className="pl-6 border-l-2 border-slate-800 space-y-2">
                <div className="text-amber-400">
                  └─► [SUB-NODE] Are sensitive keywords present? (suspiciousKeywordCount &gt; 0.5)
                </div>
                <div className="pl-6 border-l-2 border-slate-850 space-y-1">
                  <div className="text-rose-400">
                    └─► YES: Keywords &apos;paypal&apos; and &apos;login&apos; found!
                  </div>
                  <div className="p-2 rounded bg-rose-950/40 border border-rose-500/30 text-rose-300 text-[11px]">
                    <strong>[LEAF NODE REACHED]:</strong>
                    <br />
                    Class Probabilities: P(Safe)=0.00, P(Suspicious)=0.05, <strong>P(Malicious)=0.95</strong>
                    <br />
                    Vote from Tree #13: <strong>MALICIOUS</strong>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'metrics' && (
        <div className="space-y-4">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400">Test Accuracy</div>
              <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{DATASET_METRICS.accuracy}%</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Holdout 20% validation</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400">Precision (Phishing)</div>
              <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">{DATASET_METRICS.precision}%</div>
              <div className="text-[11px] text-slate-500 mt-0.5">True positive precision</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400">Recall (Sensitivity)</div>
              <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{DATASET_METRICS.recall}%</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Catches 96.1% threats</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs text-slate-400">F1-Score</div>
              <div className="text-2xl font-bold font-mono text-purple-400 mt-1">{DATASET_METRICS.f1Score}%</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Harmonic balance</div>
            </div>
          </div>

          {/* Dataset Breakdown */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-white">Benchmark Dataset Composition ({DATASET_METRICS.totalSamples.toLocaleString()} URLs)</h4>
              <span className="text-xs text-slate-400">ISCX-URL2016 / PhishTank / Tranco</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20">
                <div className="text-slate-400">Legitimate Samples</div>
                <div className="text-lg font-bold text-emerald-400 mt-1">{DATASET_METRICS.legitimateCount.toLocaleString()}</div>
                <div className="text-[11px] text-slate-500">49.8% of corpus</div>
              </div>
              <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/20">
                <div className="text-slate-400">Phishing URLs</div>
                <div className="text-lg font-bold text-amber-400 mt-1">{DATASET_METRICS.phishingCount.toLocaleString()}</div>
                <div className="text-[11px] text-slate-500">33.3% of corpus</div>
              </div>
              <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/20">
                <div className="text-slate-400">Malware / Droppers</div>
                <div className="text-lg font-bold text-rose-400 mt-1">{DATASET_METRICS.malwareCount.toLocaleString()}</div>
                <div className="text-[11px] text-slate-500">16.9% of corpus</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
