import React from 'react';
import { ShieldCheck } from 'lucide-react';

export default function Navbar({ setScreen }) {
  return (
    <header className="max-w-7xl w-full mx-auto flex items-center justify-between px-6 py-5 border-b border-[#E0533C]/15 relative z-20">
      <div 
        onClick={() => setScreen('welcome')}
        className="flex items-center space-x-3 cursor-pointer group"
      >
        <div className="p-2.5 bg-[#191514] text-[#FF9B85] rounded-xl shadow-lg shadow-[#191514]/10 group-hover:bg-[#251F1D] transition-all duration-300">
          <ShieldCheck className="w-6 h-6 text-[#FF9B85] group-hover:scale-110 transition-transform duration-300" />
        </div>
        <div className="flex flex-col">
          <span className="font-serif font-bold text-xl tracking-wide text-[#1C1817]">
            APKGuard
          </span>
          <span className="text-[10px] uppercase tracking-widest text-[#D84328] font-bold">
            Threat Intelligence Platform
          </span>
        </div>
      </div>

    </header>
  );
}