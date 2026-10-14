import React, { useState } from 'react';
import { AlertCircle, CheckCircle, Search, Sparkles, X } from 'lucide-react';
import { HACKATHON_PRESET_URLS } from '../ml/datasetSamples';
import { validateUrlFormat } from '../ml/featureExtractor';
import { BenchmarkSample } from '../types';

interface UrlDetectorProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
  currentUrl: string;
}

export const UrlDetector: React.FC<UrlDetectorProps> = ({ onAnalyze, isLoading, currentUrl }) => {
  const [inputUrl, setInputUrl] = useState<string>(currentUrl);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = inputUrl.trim();
    if (!trimmed) {
      setValidationError('Please enter a URL to inspect.');
      return;
    }

    const validation = validateUrlFormat(trimmed);
    if (!validation.isValid) {
      setValidationError(validation.error || 'Invalid URL structure.');
      return;
    }

    setValidationError(null);
    onAnalyze(trimmed);
  };

  const handlePresetSelect = (preset: BenchmarkSample) => {
    setInputUrl(preset.url);
    setValidationError(null);
    onAnalyze(preset.url);
  };

  const handleClear = () => {
    setInputUrl('');
    setValidationError(null);
  };

  return (
    <div className="space-y-6">
      {/* Search Input Box */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
            <Search className="w-5 h-5 text-slate-400" />
          </div>
          <input
            type="text"
            value={inputUrl}
            onChange={(e) => {
              setInputUrl(e.target.value);
              if (validationError) setValidationError(null);
            }}
            placeholder="Paste or type URL to inspect (e.g., https://example.com, suspicious link, or raw IP)..."
            className="w-full pl-12 pr-28 py-3.5 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all shadow-inner"
            spellCheck={false}
            autoComplete="off"
          />

          <div className="absolute inset-y-0 right-2 flex items-center gap-1.5">
            {inputUrl && (
              <button
                type="button"
                onClick={handleClear}
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                title="Clear input"
              >
                <X className="w-4 h-4" />
              </button>
            )}
            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold tracking-wide transition-all disabled:opacity-50 shadow-md shadow-indigo-600/20"
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <span>Inspect URL</span>
              )}
            </button>
          </div>
        </div>

        {/* Validation Error Banner */}
        {validationError && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs animate-fadeIn">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{validationError}</span>
          </div>
        )}
      </form>

      {/* Preset Library for Hackathon Demonstrations */}
      <div className="space-y-3 pt-1">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-1.5 font-medium text-slate-300">
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            <span>Hackathon Presets (Click to test instantly):</span>
          </div>
          <span className="text-[11px] text-slate-500">Curated from PhishTank & Tranco</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Safe Column */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400 px-1">
              Legitimate Links
            </div>
            {HACKATHON_PRESET_URLS.filter((p) => p.label === 'SAFE').map((preset, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handlePresetSelect(preset)}
                className="w-full text-left p-2.5 rounded-lg bg-slate-900/50 hover:bg-slate-800/80 border border-slate-800 hover:border-emerald-500/30 transition-all text-xs group"
              >
                <div className="font-mono text-slate-300 truncate group-hover:text-emerald-300">
                  {preset.url}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5 truncate">{preset.notes}</div>
              </button>
            ))}
          </div>

          {/* Suspicious Column */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-amber-400 px-1">
              Suspicious Links
            </div>
            {HACKATHON_PRESET_URLS.filter((p) => p.label === 'SUSPICIOUS').map((preset, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handlePresetSelect(preset)}
                className="w-full text-left p-2.5 rounded-lg bg-slate-900/50 hover:bg-slate-800/80 border border-slate-800 hover:border-amber-500/30 transition-all text-xs group"
              >
                <div className="font-mono text-slate-300 truncate group-hover:text-amber-300">
                  {preset.url}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5 truncate">{preset.notes}</div>
              </button>
            ))}
          </div>

          {/* Malicious Column */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-rose-400 px-1">
              Malicious & Phishing
            </div>
            {HACKATHON_PRESET_URLS.filter((p) => p.label === 'MALICIOUS').slice(0, 3).map((preset, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handlePresetSelect(preset)}
                className="w-full text-left p-2.5 rounded-lg bg-slate-900/50 hover:bg-slate-800/80 border border-slate-800 hover:border-rose-500/30 transition-all text-xs group"
              >
                <div className="font-mono text-slate-300 truncate group-hover:text-rose-300">
                  {preset.url}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5 truncate">{preset.notes}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
