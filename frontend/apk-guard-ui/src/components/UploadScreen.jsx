import React, { useState } from 'react';
import { UploadCloud, FileCode, FileText } from 'lucide-react';

export default function UploadScreen({ onFileUpload }) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="w-full max-w-xl py-8 space-y-6 animate-fade-in">
      <div className="text-center space-y-2">
        <h2 className="font-serif text-3xl font-bold text-[#1C1817]">Upload Application Binary</h2>
        <p className="text-stone-800 font-medium text-sm">Select an `.apk` file for multi-stage static and predictive triage.</p>
      </div>

      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-3xl p-10 text-center transition-all duration-300 flex flex-col items-center justify-center space-y-5 bg-[#191514] text-stone-200 shadow-2xl ${
          isDragging ? 'border-[#FF7E67] scale-[1.01]' : 'border-[#2D2321]'
        }`}
      >
        <div className="p-5 bg-[#FF7E67]/20 rounded-2xl text-[#FF9B85] shadow-inner">
          <UploadCloud className="w-12 h-12 animate-bounce" style={{ animationDuration: '2.5s' }} />
        </div>

        <div className="space-y-1">
          <h3 className="text-lg font-semibold text-white">Drag & Drop APK File Here</h3>
          <p className="text-stone-400 text-xs font-mono">Accepts binary format (.apk up to 150MB)</p>
        </div>

        <div className="flex items-center space-x-3 w-full max-w-xs">
          <div className="h-[1px] bg-stone-800 flex-1" />
          <span className="text-xs text-stone-500 font-mono uppercase">or</span>
          <div className="h-[1px] bg-stone-800 flex-1" />
        </div>

        <label className="cursor-pointer group relative inline-flex items-center space-x-2 px-6 py-3 bg-[#FF7E67] hover:bg-[#E0533C] text-white font-bold text-sm rounded-xl transition-all duration-200 shadow-md">
          <FileText className="w-4 h-4 text-white" />
          <span>Browse Files</span>
          <input
            type="file"
            accept=".apk"
            className="hidden"
            onChange={(e) => e.target.files && e.target.files[0] && onFileUpload(e.target.files[0])}
          />
        </label>
      </div>


    </div>
  );
}