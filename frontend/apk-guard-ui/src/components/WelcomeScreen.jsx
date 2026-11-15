import React from 'react';
import { Sparkles, ArrowRight, Cpu, Search, ShieldCheck } from 'lucide-react';

export default function WelcomeScreen({ onStart }) {
  return (
    <div className="w-full max-w-4xl py-6 space-y-12 text-center animate-fade-in">

      <div className="space-y-4 max-w-3xl mx-auto">
        <h1 className="font-serif text-5xl sm:text-6xl font-extrabold tracking-tight text-[#1C1817] leading-[1.15]">
          Unveil Mobile Threats with <br />
          <span className="text-[#D84328] underline decoration-[#D84328]/30">
            Precision Dual Engines
          </span>
        </h1>
        <p className="text-stone-800 font-medium text-lg sm:text-xl leading-relaxed max-w-2xl mx-auto">
          Dissect Android binaries using deep Random Forest/XGBoost classification models combined with real-time heuristic entropy evaluation.
        </p>
      </div>

      <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-4">
        <button
          onClick={onStart}
          className="group relative inline-flex items-center space-x-3 px-8 py-4 bg-[#FF7E67] hover:bg-[#E0533C] text-stone-950 font-bold text-base rounded-2xl shadow-xl shadow-[#FF7E67]/25 transition-all duration-300 hover:scale-[1.02] active:scale-[0.98]"
        >
          <span className="tracking-wide text-white">Launch Inspection Console</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform duration-300 text-white" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-8 text-left">
        <div className="p-6 bg-[#191514] text-stone-200 border border-[#2B2321] rounded-2xl shadow-xl transition-all duration-300 group">
          <div className="p-3 bg-[#FF7E67]/20 text-[#FF9B85] rounded-xl w-fit mb-4">
            <Cpu className="w-6 h-6" />
          </div>
          <h3 className="font-serif font-bold text-lg text-white mb-1">Dual ML Architecture</h3>
          <p className="text-stone-400 text-sm leading-relaxed">
            Calculates benign vs malicious feature matrices using ensemble XGBoost algorithms.
          </p>
        </div>

        <div className="p-6 bg-[#191514] text-stone-200 border border-[#2B2321] rounded-2xl shadow-xl transition-all duration-300 group">
          <div className="p-3 bg-[#FF7E67]/20 text-[#FF9B85] rounded-xl w-fit mb-4">
            <Search className="w-6 h-6" />
          </div>
          <h3 className="font-serif font-bold text-lg text-white mb-1">Static Entropy Scanner</h3>
          <p className="text-stone-400 text-sm leading-relaxed">
            Detects embedded `.tflite` blobs, packed DEX files, and hidden input controller assets.
          </p>
        </div>

        <div className="p-6 bg-[#191514] text-stone-200 border border-[#2B2321] rounded-2xl shadow-xl transition-all duration-300 group">
          <div className="p-3 bg-[#FF7E67]/20 text-[#FF9B85] rounded-xl w-fit mb-4">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h3 className="font-serif font-bold text-lg text-white mb-1">Discrepancy Intelligence</h3>
          <p className="text-stone-400 text-sm leading-relaxed">
            Resolves false positives by cross-correlating model predictions with structural indicators.
          </p>
        </div>
      </div>
    </div>
  );
}