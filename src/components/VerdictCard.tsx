import React from 'react';
import { AlertTriangle, Clock, Gauge, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ClassificationResult } from '../types';

interface VerdictCardProps {
  result: ClassificationResult;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({ result }) => {
  const { verdict, confidenceScore, probabilities, treeVotes, riskScore, components, executionTimeMs } = result;

  // Status configuration
  const config = {
    SAFE: {
      badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      bannerBg: 'bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border-emerald-500/40',
      textColor: 'text-emerald-400',
      icon: ShieldCheck,
      headline: 'Classified as SAFE',
      summary:
        'This URL displays standard domain hierarchy, low character entropy, and no typical phishing tokens. Always verify the domain name matches your intended destination.',
    },
    SUSPICIOUS: {
      badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      bannerBg: 'bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border-amber-500/40',
      textColor: 'text-amber-400',
      icon: AlertTriangle,
      headline: 'Classified as SUSPICIOUS',
      summary:
        'Anomalous patterns detected (e.g., URL shortener, high-abuse TLD, or nested subdomains). High caution is strongly advised; do not enter sensitive credentials.',
    },
    MALICIOUS: {
      badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      bannerBg: 'bg-gradient-to-r from-rose-950/50 via-slate-900 to-slate-900 border-rose-500/50',
      textColor: 'text-rose-400',
      icon: ShieldAlert,
      headline: 'Classified as MALICIOUS',
      summary:
        'Critical threat indicators identified (e.g., raw IP address, embedded "@" redirect token, or brand spoofing keywords). Do not open or interact with this link.',
    },
  }[verdict];

  const VerdictIcon = config.icon;

  return (
    <div className={`p-6 rounded-2xl border ${config.bannerBg} space-y-6 transition-all shadow-xl`}>
      {/* Top Banner Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className={`p-3.5 rounded-xl border ${config.badgeBg}`}>
            <VerdictIcon className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <span className={`text-2xl font-extrabold tracking-tight ${config.textColor}`}>
                {config.headline}
              </span>
              <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Random Forest Model
              </span>
            </div>
            <p className="text-sm text-slate-300 mt-1 max-w-2xl leading-relaxed">{config.summary}</p>
          </div>
        </div>

        {/* Confidence & Speed Stats */}
        <div className="flex items-center gap-6 self-start md:self-auto border-t md:border-t-0 md:border-l border-slate-800 pt-3 md:pt-0 md:pl-6 shrink-0">
          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Gauge className="w-3.5 h-3.5 text-slate-400" />
              <span>Confidence</span>
            </div>
            <div className="text-xl font-bold font-mono text-white mt-0.5 tabular-nums">
              {confidenceScore}%
            </div>
          </div>
          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>Latency</span>
            </div>
            <div className="text-xl font-bold font-mono text-white mt-0.5 tabular-nums">
              {executionTimeMs} ms
            </div>
          </div>
        </div>
      </div>

      {/* URL Anatomy Breakdown Ribbon */}
      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Deconstructed URL Anatomy
        </div>
        <div className="font-mono text-xs break-all flex flex-wrap items-center gap-1.5">
          <span className="px-2 py-1 rounded bg-slate-800/80 text-indigo-300 border border-slate-700">
            {components.protocol}://
          </span>
          {components.subdomain && (
            <span className="px-2 py-1 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
              {components.subdomain}.
            </span>
          )}
          <span className="px-2 py-1 rounded bg-slate-800 text-white font-medium border border-slate-700">
            {components.domain}
          </span>
          {components.port && (
            <span className="px-2 py-1 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
              :{components.port}
            </span>
          )}
          {components.pathname !== '/' && (
            <span className="px-2 py-1 rounded bg-slate-900 text-slate-300 border border-slate-800">
              {components.pathname}
            </span>
          )}
          {components.search && (
            <span className="px-2 py-1 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 truncate max-w-xs">
              {components.search}
            </span>
          )}
        </div>
      </div>

      {/* Probability Distribution & Tree Voting Grids */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
        {/* Probability Bars */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-300">Class Probability Distribution</span>
            <span className="text-slate-500">Softmax Normalized</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-emerald-400 font-medium">Safe</span>
                <span className="text-slate-300 tabular-nums">{(probabilities.safe * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                  style={{ width: `${probabilities.safe * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-amber-400 font-medium">Suspicious</span>
                <span className="text-slate-300 tabular-nums">{(probabilities.suspicious * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full transition-all duration-500"
                  style={{ width: `${probabilities.suspicious * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-rose-400 font-medium">Malicious</span>
                <span className="text-slate-300 tabular-nums">{(probabilities.malicious * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-rose-500 rounded-full transition-all duration-500"
                  style={{ width: `${probabilities.malicious * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Tree Votes */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-300">Ensemble Tree Consensus</span>
            <span className="text-slate-500">{treeVotes.totalTrees} Decision Trees</span>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-1 text-center font-mono">
            <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20">
              <div className="text-lg font-bold text-emerald-400 tabular-nums">{treeVotes.safeVotes}</div>
              <div className="text-[11px] text-slate-400">Voted Safe</div>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20">
              <div className="text-lg font-bold text-amber-400 tabular-nums">{treeVotes.suspiciousVotes}</div>
              <div className="text-[11px] text-slate-400">Voted Suspicious</div>
            </div>
            <div className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/20">
              <div className="text-lg font-bold text-rose-400 tabular-nums">{treeVotes.maliciousVotes}</div>
              <div className="text-[11px] text-slate-400">Voted Malicious</div>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 text-center">
            Composite Risk Score:{' '}
            <span
              className={`font-mono font-bold ${
                riskScore > 60 ? 'text-rose-400' : riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {riskScore} / 100
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
