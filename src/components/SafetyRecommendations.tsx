import React from 'react';
import { AlertOctagon, CheckCircle, Info, Lock, Shield, ShieldCheck } from 'lucide-react';
import { ClassificationResult } from '../types';

interface SafetyRecommendationsProps {
  result: ClassificationResult;
}

export const SafetyRecommendations: React.FC<SafetyRecommendationsProps> = ({ result }) => {
  const { verdict, recommendations } = result;

  return (
    <div className="space-y-6">
      {/* Dynamic Action Checklist */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-indigo-400" />
          <h3 className="text-base font-semibold text-white">Recommended Security Actions</h3>
        </div>

        <div className="space-y-2.5">
          {recommendations.map((rec, idx) => (
            <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-indigo-500/10 text-indigo-400 font-mono text-xs font-bold shrink-0 mt-0.5">
                {idx + 1}
              </span>
              <p className="text-sm text-slate-300 leading-relaxed">{rec}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Critical Cybersecurity Education Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Callout 1: The HTTPS Myth */}
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
            <Lock className="w-4 h-4 shrink-0" />
            <span>Why HTTPS Does Not Guarantee Safety</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            HTTPS encrypts data in transit between your browser and the server, preventing Wi-Fi eavesdropping. However,{' '}
            <strong className="text-white">anyone can obtain a free SSL/TLS certificate</strong>. Modern phishing websites routinely use HTTPS to display the padlock icon and fool victims into a false sense of security.
          </p>
        </div>

        {/* Callout 2: Machine Learning Detection Scope */}
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
            <Info className="w-4 h-4 shrink-0" />
            <span>URL-Based Detection Scope & Limits</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Lexical and structural Machine Learning analyzes URL patterns without fetching the web page. While highly effective at stopping known phishing patterns and spoofed domains, legitimate compromised websites or zero-day exploits may present normal URL structures.
          </p>
        </div>
      </div>

      {/* Safe Sandbox Statement */}
      <div className="p-4 rounded-xl bg-slate-900/20 border border-slate-800/60 flex items-center gap-3 text-xs text-slate-400">
        <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
        <span>
          <strong className="text-slate-300">Safe Sandbox Assurance:</strong> This system inspects URL strings in an isolated environment. It never connects to, visits, downloads, or executes code from submitted URLs.
        </span>
      </div>
    </div>
  );
};
