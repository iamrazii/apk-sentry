import React, { useState } from 'react';
import { AlertTriangle, RefreshCw, Cpu, Search, Layers } from 'lucide-react';

export default function ResultsScreen({ result, onReset }) {
  const [activeTab, setActiveTab] = useState('all');

  const triggeredRules = result?.triggered_rules || [];
  const filteredRules = activeTab === 'all' 
    ? triggeredRules 
    : triggeredRules.filter(r => (r.category || '').toLowerCase().includes(activeTab));

  const staticScorePct = Math.round((result?.static_score || 0) * 100);
  const mlScorePct = Math.round((result?.ml_score || 0) * 100);

  return (
    <div className="w-full max-w-5xl py-4 space-y-8 animate-fade-in">
      <div className="bg-[#191514] border border-[#2B2321] text-stone-100 rounded-3xl p-6 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative z-10">
          <div className="flex items-start space-x-4">
            <div className="p-3.5 bg-[#FF7E67]/20 rounded-2xl text-[#FF9B85] shrink-0">
              <AlertTriangle className="w-8 h-8" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center space-x-3 flex-wrap gap-y-2">
                <h2 className="font-serif text-2xl font-bold text-white">Analysis Verdict: {result?.verdict || 'UNKNOWN'}</h2>
                <span className="px-3 py-0.5 text-xs font-semibold bg-[#FF7E67]/20 text-[#FFB3A3] border border-[#FF7E67]/30 rounded-full font-mono">
                  Risk Tier: {result?.risk_tier || 'N/A'}
                </span>
              </div>
              <p className="text-stone-300 text-sm leading-relaxed max-w-2xl">
                File <span className="text-[#FFB3A3] font-semibold">{result?.filename}</span> evaluated successfully. Total threat score: <span className="text-[#FF7E67] font-semibold">{((result?.total_score || 0) * 100).toFixed(1)}%</span>.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={onReset}
              className="px-4 py-2.5 bg-[#FF7E67] hover:bg-[#E0533C] text-white rounded-xl text-xs font-bold transition flex items-center space-x-2"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Scan New File</span>
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-[#191514] text-stone-200 border border-[#2B2321] rounded-3xl p-6 space-y-5 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 bg-teal-500/10 rounded-xl text-teal-400">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-serif font-bold text-lg text-white">Machine Learning Model</h3>
                <span className="text-xs text-stone-400 font-mono">Random Forest / XGBoost</span>
              </div>
            </div>
            <span className="px-3 py-1 bg-teal-500/20 text-teal-300 rounded-full text-xs font-mono font-bold">
              CONFIDENCE: {((result?.confidence || 0) * 100).toFixed(1)}%
            </span>
          </div>

          <p className="text-stone-400 text-sm leading-relaxed">
            Evaluated feature matrices and API call structures using trained model artifacts.
          </p>

          <div className="space-y-2 pt-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-stone-400">ML Threat Score</span>
              <span className="text-teal-400 font-bold">{mlScorePct} / 100</span>
            </div>
            <div className="w-full h-2.5 bg-stone-900 rounded-full overflow-hidden">
              <div className="h-full bg-teal-400 rounded-full" style={{ width: `${mlScorePct}%` }} />
            </div>
          </div>
        </div>

        <div className="bg-[#191514] text-stone-200 border border-[#2B2321] rounded-3xl p-6 space-y-5 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 bg-[#FF7E67]/20 rounded-xl text-[#FF9B85]">
                <Search className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-serif font-bold text-lg text-white">Heuristic Rules Engine</h3>
                <span className="text-xs text-stone-400 font-mono">YARA Entropy Classifier</span>
              </div>
            </div>
            <span className="px-3 py-1 bg-[#FF7E67]/20 text-[#FFB3A3] rounded-full text-xs font-mono font-bold">
              STATIC SCORE
            </span>
          </div>

          <p className="text-stone-400 text-sm leading-relaxed">
            Scanned binary signatures and YARA rules against unpacked app assets.
          </p>

          <div className="space-y-2 pt-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-stone-400">Static Threat Score</span>
              <span className="text-[#FF7E67] font-bold">{staticScorePct} / 100</span>
            </div>
            <div className="w-full h-2.5 bg-stone-900 rounded-full overflow-hidden">
              <div className="h-full bg-[#FF7E67] rounded-full" style={{ width: `${staticScorePct}%` }} />
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#191514] text-stone-200 border border-[#2B2321] rounded-3xl p-6 space-y-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-stone-800 pb-4">
          <div className="flex items-center space-x-3">
            <Layers className="w-5 h-5 text-[#FF7E67]" />
            <h3 className="font-serif font-bold text-lg text-white">Triggered Rules & Indicators</h3>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredRules.length > 0 ? filteredRules.map((item, idx) => (
            <div key={idx} className="p-4 bg-[#14100F] border border-stone-800 rounded-2xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-[#FF9B85] bg-[#FF7E67]/10 px-2.5 py-0.5 rounded-md">
                  {item.rule || item.category || 'Trigger'}
                </span>
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#FF7E67]/20 text-[#FFB3A3]">
                  Matched
                </span>
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{item.description || item.name || 'Signature Match'}</div>
              </div>
            </div>
          )) : (
            <div className="col-span-2 text-center py-8 text-stone-400 font-mono text-sm">
              No matching rule triggers returned or file is clean.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}