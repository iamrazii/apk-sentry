import React, { useState } from 'react';
import Navbar from './components/Navbar';
import WelcomeScreen from './components/WelcomeScreen';
import UploadScreen from './components/UploadScreen';
import ScanningScreen from './components/ScanningScreen';
import ResultsScreen from './components/ResultsScreen';
import { analyzeApk } from './services/api';

export default function App() {
  const [screen, setScreen] = useState('welcome');
  const [file, setFile] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleFileUpload = async (uploadedFile) => {
    if (!uploadedFile.name.endsWith('.apk')) {
      alert("Please upload a valid .apk file binary.");
      return;
    }

    setFile({
      name: uploadedFile.name,
      size: uploadedFile.size,
      raw: uploadedFile
    });
    setScreen('scanning');
    setErrorMsg(null);

    try {
      // backend endpoint
      const result = await analyzeApk(uploadedFile);
      setScanResult(result);
      
      // Delay slightly for smooth UX transition to results
      setTimeout(() => {
        setScreen('results');
      }, 1500);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.message || 'Error connecting to backend API.');
      alert(`Analysis failed: ${err.message || 'Check backend connection.'}`);
      setScreen('upload');
    }
  };

  const resetScanner = () => {
    setFile(null);
    setScanResult(null);
    setErrorMsg(null);
    setScreen('upload');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#FFF3EF] via-[#FCE3DC] to-[#FBD8CE] text-[#1C1817] flex flex-col justify-between selection:bg-[#FF7E67] selection:text-white relative font-sans overflow-x-hidden">
      
      {/* Background Soft Glow Effects */}
      <div className="fixed top-0 left-1/4 -translate-x-1/2 w-[500px] h-[500px] bg-[#FF9B85]/20 rounded-full blur-[140px] pointer-events-none" />
      <div className="fixed bottom-0 right-1/4 translate-x-1/2 w-[600px] h-[600px] bg-[#FF7E67]/15 rounded-full blur-[160px] pointer-events-none" />
      <div className="fixed inset-0 opacity-[0.04] bg-[radial-gradient(#E0533C_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none" />

      <Navbar setScreen={setScreen} />

      <main className="max-w-7xl w-full mx-auto px-6 py-8 flex-1 flex flex-col items-center justify-center relative z-10">
        {errorMsg && (
          <div className="mb-4 p-4 bg-red-500/20 border border-red-500 text-red-700 rounded-xl text-sm font-medium">
            {errorMsg}
          </div>
        )}

        {screen === 'welcome' && (
          <WelcomeScreen onStart={() => setScreen('upload')} />
        )}

        {screen === 'upload' && (
          <UploadScreen onFileUpload={handleFileUpload} />
        )}

        {screen === 'scanning' && (
          <ScanningScreen file={file} auditTrail={scanResult?.audit_trail} />
        )}

        {screen === 'results' && (
          <ResultsScreen result={scanResult} onReset={resetScanner} />
        )}
      </main>

    </div>
  );
}