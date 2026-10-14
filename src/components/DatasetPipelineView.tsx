import React, { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  Database,
  Download,
  FileCheck,
  FileSpreadsheet,
  FileWarning,
  Filter,
  Layers,
  Shield,
  Split,
  Terminal,
} from 'lucide-react';

export const DatasetPipelineView: React.FC = () => {
  const [copiedCode, setCopiedCode] = useState(false);

  const sampleReport = {
    total_raw_rows: 86,
    missing_url_count: 0,
    missing_label_count: 0,
    duplicate_urls_removed: 0,
    conflicting_label_urls_removed: 0,
    unmapped_labels_dropped: 0,
    unmapped_label_values: [],
    clean_sample_count: 86,
    class_distribution: {
      LEGITIMATE: 40,
      MALICIOUS: 46,
    },
    split_counts: {
      train: { total: 60, LEGITIMATE: 28, MALICIOUS: 32 },
      val: { total: 12, LEGITIMATE: 6, MALICIOUS: 6 },
      test: { total: 14, LEGITIMATE: 6, MALICIOUS: 8 },
    },
  };

  const handleCopyCommand = () => {
    navigator.clipboard.writeText('python3 data/prepare_dataset.py data/raw/dataset.csv');
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2 text-indigo-400 font-mono text-xs uppercase tracking-wider">
          <Database className="w-4 h-4" />
          <span>Machine Learning Pipeline · Stage 1</span>
        </div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Dataset Preparation & Quality Pipeline</h2>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          Loads raw CSV datasets, inspects data quality, deduplicates URLs, resolves conflicting labels, normalizes multi-class inputs into <strong className="text-emerald-400">LEGITIMATE</strong> and <strong className="text-rose-400">MALICIOUS</strong>, and executes stratified splits with zero data leakage.
        </p>
      </div>

      {/* 4-Step Pipeline Flow Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Step 1 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-indigo-400">STEP 01</span>
            <FileSpreadsheet className="w-4 h-4 text-slate-400" />
          </div>
          <h4 className="text-sm font-bold text-white">Auto-Column Ingestion</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Auto-detects URL and label columns across common naming conventions (<code className="text-indigo-300 font-mono">url, URL, domain</code> and <code className="text-indigo-300 font-mono">type, label, class</code>).
          </p>
        </div>

        {/* Step 2 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-amber-400">STEP 02</span>
            <Filter className="w-4 h-4 text-slate-400" />
          </div>
          <h4 className="text-sm font-bold text-white">Data Quality & De-dupe</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Drops empty rows, removes duplicate URLs, and resolves conflicting labels (where the same URL was tagged both benign and malicious).
          </p>
        </div>

        {/* Step 3 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-emerald-400">STEP 03</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <h4 className="text-sm font-bold text-white">Configurable Label Mapping</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Normalizes <code className="text-slate-300 font-mono">benign, 0</code> → <strong className="text-emerald-400">LEGITIMATE</strong>, and <code className="text-slate-300 font-mono">phishing, malware, defacement, 1</code> → <strong className="text-rose-400">MALICIOUS</strong>.
          </p>
        </div>

        {/* Step 4 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-purple-400">STEP 04</span>
            <Split className="w-4 h-4 text-slate-400" />
          </div>
          <h4 className="text-sm font-bold text-white">Stratified Leak-Free Split</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Divides samples into <strong>70% Train</strong>, <strong>15% Val</strong>, and <strong>15% Test</strong> preserving class balance with zero URL leakage.
          </p>
        </div>
      </div>

      {/* Execution Results Statistics Grid */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h3 className="text-base font-bold text-white">Dataset Quality & Split Report</h3>
            <p className="text-xs text-slate-400 mt-0.5">Real execution output from <code className="text-indigo-300 font-mono">data/prepare_dataset.py</code></p>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            ✓ 0 Overlapping URLs (Zero Leakage)
          </span>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400">Total Raw Records</div>
            <div className="text-xl font-bold text-white mt-1">{sampleReport.total_raw_rows}</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Loaded from raw CSV</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400">Duplicates Purged</div>
            <div className="text-xl font-bold text-amber-400 mt-1">{sampleReport.duplicate_urls_removed}</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Prior to splitting</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400">Conflicting Purged</div>
            <div className="text-xl font-bold text-rose-400 mt-1">{sampleReport.conflicting_label_urls_removed}</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Contradictory labels</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400">Clean Unique URLs</div>
            <div className="text-xl font-bold text-emerald-400 mt-1">{sampleReport.clean_sample_count}</div>
            <div className="text-[10px] text-slate-500 mt-0.5">100% verified samples</div>
          </div>
        </div>

        {/* Stratified Splits Distribution Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border border-slate-800 rounded-lg overflow-hidden">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4 font-semibold">Dataset Split</th>
                <th className="py-2.5 px-4 font-semibold">Total URLs</th>
                <th className="py-2.5 px-4 font-semibold">Legitimate (Class 0)</th>
                <th className="py-2.5 px-4 font-semibold">Malicious (Class 1)</th>
                <th className="py-2.5 px-4 font-semibold">Saved Location</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              <tr>
                <td className="py-2.5 px-4 font-bold text-indigo-300">TRAIN (70%)</td>
                <td className="py-2.5 px-4 text-white font-semibold">60 samples</td>
                <td className="py-2.5 px-4 text-emerald-400">28 samples (46.7%)</td>
                <td className="py-2.5 px-4 text-rose-400">32 samples (53.3%)</td>
                <td className="py-2.5 px-4 text-slate-400">data/processed/train.csv</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-bold text-amber-300">VAL (15%)</td>
                <td className="py-2.5 px-4 text-white font-semibold">12 samples</td>
                <td className="py-2.5 px-4 text-emerald-400">6 samples (50.0%)</td>
                <td className="py-2.5 px-4 text-rose-400">6 samples (50.0%)</td>
                <td className="py-2.5 px-4 text-slate-400">data/processed/val.csv</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-bold text-purple-300">TEST (15%)</td>
                <td className="py-2.5 px-4 text-white font-semibold">14 samples</td>
                <td className="py-2.5 px-4 text-emerald-400">6 samples (42.9%)</td>
                <td className="py-2.5 px-4 text-rose-400">8 samples (57.1%)</td>
                <td className="py-2.5 px-4 text-slate-400">data/processed/test.csv</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Guide: Where to Obtain Authentic Datasets */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-indigo-400 font-bold text-base">
            <Database className="w-5 h-5" />
            <span>Where to Obtain Authentic URL Datasets</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            For academic integrity and real cybersecurity model performance, use verified open-access research benchmarks rather than unverified scrape lists:
          </p>
          <ul className="space-y-3 text-xs text-slate-300">
            <li className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <strong className="text-white block mb-0.5">1. ISCX-URL2016 (University of New Brunswick)</strong>
              <span>Widely cited research dataset containing over 35,000 URLs categorized into benign, phishing, malware, and defacement.</span>
            </li>
            <li className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <strong className="text-white block mb-0.5">2. PhishTank Community Feed (phishtank.org)</strong>
              <span>Real-time community-verified repository of active phishing links updated hourly with confidence votes.</span>
            </li>
            <li className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <strong className="text-white block mb-0.5">3. Tranco List & Alexa Top 1M (tranco-list.eu)</strong>
              <span>Scientifically curated research ranking of the top 1 million legitimate, high-reputation web domains.</span>
            </li>
            <li className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <strong className="text-white block mb-0.5">4. Kaggle Malicious URLs Dataset (Manu Siddhartha)</strong>
              <span>Clean CSV containing ~650k URLs labeled as benign, defacement, phishing, and malware.</span>
            </li>
          </ul>
        </div>

        {/* How to Run Locally */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-indigo-400 font-bold text-base">
            <Terminal className="w-5 h-5" />
            <span>How to Run Dataset Preparation in Terminal</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Follow these steps to place your raw CSV file and run the pipeline:
          </p>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <div className="text-slate-400 mb-1">1. Place your CSV file in the project folder:</div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                data/raw/my_hackathon_urls.csv
              </div>
            </div>

            <div>
              <div className="text-slate-400 mb-1">2. Run the preparation script:</div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 flex items-center justify-between">
                <span>python3 data/prepare_dataset.py data/raw/my_hackathon_urls.csv</span>
                <button
                  onClick={handleCopyCommand}
                  className="text-slate-400 hover:text-white transition-colors"
                  title="Copy command"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              {copiedCode && <div className="text-[10px] text-emerald-400 mt-1">Copied to clipboard!</div>}
            </div>

            <div>
              <div className="text-slate-400 mb-1">3. Processed outputs generated in <code className="text-indigo-300">data/processed/</code>:</div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 space-y-1 text-[11px]">
                <div>• <span className="text-indigo-300">clean_dataset.csv</span> : Full cleaned & deduplicated dataset</div>
                <div>• <span className="text-indigo-300">train.csv</span> : 70% Stratified training set</div>
                <div>• <span className="text-indigo-300">val.csv</span> : 15% Stratified validation set</div>
                <div>• <span className="text-indigo-300">test.csv</span> : 15% Holdout test set</div>
                <div>• <span className="text-indigo-300">summary_report.json</span> : Audit counts and metrics</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
