import React, { useState, useEffect, useRef } from 'react';
import { RefreshCw, Terminal, CheckCircle2, FileCode, Search, Layers, Activity, Cpu } from 'lucide-react';

const scanStages = [
  { label: "Unpacking APK DEX & Asset Blobs", icon: FileCode },
  { label: "Extracting AndroidManifest.xml & Permissions", icon: Search },
  { label: "Static Entropy & Signature Evaluation", icon: Layers },
  { label: "Evaluating ML XGBoost Feature Matrix", icon: Cpu },
  { label: "Correlating Dual-Engine Threat Metrics", icon: Activity }
];

export default function ScanningScreen({ file, auditTrail = [] }) {
  const [scanStep, setScanStep] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const terminalEndRef = useRef(null);

  // Handle step progression animation
  useEffect(() => {
    let currentStage = 0;
    const interval = setInterval(() => {
      if (currentStage < scanStages.length - 1) {
        currentStage++;
        setScanStep(currentStage);
      } else {
        clearInterval(interval);
      }
    }, 800);

    return () => clearInterval(interval);
  }, []);

  // Handle incoming audit logs safely without triggering dependency loops
  useEffect(() => {
    if (auditTrail && auditTrail.length > 0) {
      setTerminalLogs(auditTrail);
    } else {
      setTerminalLogs([
        `[INFO] Initializing package dissection for ${file?.name || 'binary'}...`
      ]);
    }
  }, [file]); // Removed auditTrail from dependencies to prevent infinite re-renders

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  return (
    <div className="w-full max-w-4xl py-6 space-y-8 mx-auto animate-fade-in">
      <div className="text-center space-y-2">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-[#191514] text-[#FFB3A3] rounded-full text-xs font-mono shadow-md">
          <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#FF7E67]" />
          <span>Live Binary Dissection Active</span>
        </div>
        <h2 className="font-serif text-3xl font-bold text-[#1C1817]">Analyzing Package Structures</h2>
        <p className="text-stone-800 font-mono text-sm">
          {file?.name} ({((file?.size || 0) / (1024 * 1024)).toFixed(2)} MB)
        </p>
      </div>

      <div className="max-w-2xl mx-auto space-y-3">
        {scanStages.map((stage, index) => {
          const Icon = stage.icon;
          const isCurrent = index === scanStep;
          const isDone = index < scanStep;

          return (
            <div 
              key={index} 
              className={`p-4 rounded-2xl border transition-all duration-300 flex items-center justify-between ${
                isCurrent 
                  ? 'bg-[#251F1D] border-[#FF7E67] shadow-xl translate-x-1' 
                  : isDone 
                  ? 'bg-[#191514] border-stone-800 opacity-90' 
                  : 'bg-[#191514]/60 border-stone-900 opacity-50'
              }`}
            >
              <div className="flex items-center space-x-4">
                <div className={`p-2.5 rounded-xl ${
                  isDone 
                    ? 'bg-[#FF7E67]/20 text-[#FFB3A3]' 
                    : isCurrent 
                    ? 'bg-[#FF7E67] text-white animate-pulse' 
                    : 'bg-stone-900 text-stone-600'
                }`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <div className={`text-sm font-semibold ${isCurrent ? 'text-[#FFB3A3]' : 'text-white'}`}>
                    {stage.label}
                  </div>
                  <div className="text-xs text-stone-400 font-mono">
                    {isDone ? 'Completed' : isCurrent ? 'Extracting telemetry...' : 'Queued'}
                  </div>
                </div>
              </div>

              <div>
                {isDone && <CheckCircle2 className="w-5 h-5 text-[#FF9B85]" />}
                {isCurrent && <RefreshCw className="w-5 h-5 text-[#FF7E67] animate-spin" />}
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-[#14100F] border border-stone-800 rounded-2xl p-4 font-mono text-xs space-y-2 shadow-2xl">
        <div className="flex items-center justify-between border-b border-stone-800 pb-2 text-stone-400">
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-[#FF7E67]" />
            <span className="text-[#FFB3A3] font-semibold">Live Inspection Stream</span>
          </div>
          <span className="text-[10px] text-stone-500">STDIO / LOG_OUTPUT</span>
        </div>
        
        <div className="h-32 overflow-y-auto space-y-1 text-stone-300 custom-scrollbar pr-2">
          {terminalLogs.map((log, idx) => (
            <div key={idx} className="leading-relaxed flex space-x-2">
              <span className="text-[#FF7E67] select-none">&gt;</span>
              <span className={log.includes('WARN') ? 'text-amber-400' : log.includes('MATCH') ? 'text-[#FFB3A3]' : 'text-stone-300'}>
                {log}
              </span>
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}