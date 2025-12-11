import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Mic, Zap, Terminal, Upload, X, Cpu, Send, Wifi, Sparkles, Volume2 } from 'lucide-react';

// --- GEMINI API CONFIGURATION ---
const apiKey = ""; // API Key injected by environment

// Helper: Convert Base64 PCM to WAV for browser playback
const pcmToWav = (base64PCM, sampleRate = 24000) => {
  const binaryString = window.atob(base64PCM);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  // FIX: Corrected the loop condition from 'i = 0 < len' to 'i < len'
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const wavHeader = new ArrayBuffer(44);
  const view = new DataView(wavHeader);
  view.setUint32(0, 1179011410, false); // "RIFF"
  view.setUint32(4, 36 + len, true);    // file length
  view.setUint32(8, 1163280727, false); // "WAVE"
  view.setUint32(12, 544501094, false); // "fmt "
  view.setUint32(16, 16, true);         // sub-chunk size
  view.setUint16(20, 1, true);          // format (PCM)
  view.setUint16(22, 1, true);          // channels
  view.setUint32(24, sampleRate, true); // sample rate
  view.setUint32(28, sampleRate * 2, true); // byte rate
  view.setUint16(32, 2, true);          // block align
  view.setUint16(34, 16, true);         // bits per sample
  view.setUint32(36, 1635017060, false); // "data"
  view.setUint32(40, len, true);         // data size
  return new Blob([wavHeader, bytes], { type: 'audio/wav' });
};

// --- MAIN APPLICATION LOGIC ---

export default function AICompanion() {
  // State
  const [active, setActive] = useState(true); // Default to active
  const [isAudioUnlocked, setIsAudioUnlocked] = useState(false); 
  const [listening, setListening] = useState(false);
  const [speaking, setSpeaking] = useState(false);
  const [thinking, setThinking] = useState(false);
  const [useNetlink, setUseNetlink] = useState(true); 
  const [showDebug, setShowDebug] = useState(false);
  
  // Chat & History
  const [inputText, setInputText] = useState("");
  const [conversation, setConversation] = useState([{ sender: 'system', text: "MediVision Core operational. Ready for Diagnostic Input." }]);
  
  const [logs, setLogs] = useState([]);
  const [userFile, setUserFile] = useState(null);

  const recognitionRef = useRef(null);
  const synthRef = useRef(window.speechSynthesis);
  const audioRef = useRef(new Audio());
  const audioContextRef = useRef(null);
  const fileInputRef = useRef(null);
  const chatEndRef = useRef(null);

  // --- LOGGING & UTILS ---
  const addLog = useCallback((source, message) => {
    const logMessage = String(message);
    setLogs(prev => [...prev.slice(-9), { source, message: logMessage, time: new Date().toLocaleTimeString() }]);
  }, []);

  const addToConversation = (sender, text) => {
    const conversationText = String(text);
    setConversation(prev => [...prev, { sender, text: conversationText }]);
  };

  useEffect(() => {
    if (chatEndRef.current) {
        chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [conversation]);

  // --- IMAGE HANDLING ---
  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64Data = reader.result.split(',')[1]; 
        setUserFile({ base64: base64Data, mimeType: file.type, name: file.name });
        addToConversation('system', `Image loaded: ${file.name}`);
        addLog("Data Input", `Scan initialized: ${file.name}`);
      };
      reader.readAsDataURL(file);
    }
  };

  const clearFile = () => {
    setUserFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
    addToConversation('system', "Image data cleared.");
  };

  // --- AUDIO INIT ---
  const SILENT_WAV = "data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAAABkYXRhAAAAAA=="; 

  const unlockAudio = useCallback(async () => {
    if (isAudioUnlocked) return true;
    addLog("System", "Attempting audio output activation...");
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return false;
      
      if (audioContextRef.current === null) {
        audioContextRef.current = new AudioContext();
      }
      
      if (audioContextRef.current.state === 'suspended') {
        await audioContextRef.current.resume();
      }

      audioRef.current.src = SILENT_WAV; 
      audioRef.current.volume = 0; 
      await audioRef.current.play().catch(e => {});
      audioRef.current.pause(); 
      setIsAudioUnlocked(true);
      addLog("System", "Audio output successful.");
      return true;
    } catch (e) {
      addLog("Error", `Audio unlock failed: ${e.message}`);
      return false;
    }
  }, [isAudioUnlocked, addLog]);

  const stopSystem = () => {
    setActive(false);
    setListening(false);
    setThinking(false);
    setSpeaking(false);
    if (recognitionRef.current) recognitionRef.current.abort();
    if (synthRef.current) synthRef.current.cancel();
    audioRef.current.pause();
    
    if (audioContextRef.current) {
       const context = audioContextRef.current;
       if (context.state !== 'closed') {
           try { context.close(); addLog("System", "AudioContext closed."); } catch(e) { addLog("Error", `Failed to close AudioContext: ${e.message}`); }
       }
       audioContextRef.current = null; 
    }

    setIsAudioUnlocked(false);
    addToConversation('system', "System Offline. Session Terminated.");
    addLog("System", "Offline");
  };

  const handleMainButtonClick = () => {
    if (active) stopSystem();
    else {
      setActive(true);
      const activate = async () => {
        const success = await unlockAudio();
        if (success) {
          addToConversation('system', "System Online. Ready for Diagnostic Input.");
          addLog("System", "Fully Operational.");
        } else {
          addToConversation('system', "System Online (Voice Output Disabled). Ready for Diagnostic Input.");
          addLog("System", "Fully Operational (Audio Failure).");
        }
      }
      activate();
    }
  };
  
  const startListening = useCallback(() => {
    if (recognitionRef.current && !listening && !speaking && !thinking && active) {
      try {
        recognitionRef.current.start();
      } catch (e) {
        addLog("Error", `Recognition start failed: ${e.message}`);
      }
    }
  }, [listening, speaking, thinking, active, addLog]);


  // --- INITIALIZATION AND HANDLERS ---
  useEffect(() => {
    // --- AUTO-ACTIVATION ON MOUNT ---
    const activateOnMount = async () => {
      const success = await unlockAudio();
      if (!success) {
        addToConversation('system', "Warning: Voice Output failed to initialize. Using text only.");
      }
      setActive(true);
      addLog("System", "Interface Initialized.");
    };
    activateOnMount();
    
    // Audio Player setup
    audioRef.current.volume = 1.0; 
    audioRef.current.onplay = () => setSpeaking(true);
    audioRef.current.onended = () => {
      setSpeaking(false);
      if (active) setTimeout(() => startListening(), 500);
    };
    audioRef.current.onerror = () => { setSpeaking(false); if (active) startListening(); };

    // Speech Recognition setup
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onstart = () => { setListening(true); addLog("Sensors", "Listening"); };
      recognitionRef.current.onend = () => { setListening(false); };
      recognitionRef.current.onerror = (event) => { addLog("Sensors", `Recognition error: ${event.error}`); };

      recognitionRef.current.onresult = (event) => {
        const text = event.results[0][0].transcript;
        if (text.trim().length > 0) {
           addToConversation('user', text);
           addLog("Voice Input", text);
           recognitionRef.current.abort();
           processInput(text);
        }
      };
    }

    // Cleanup function
    return () => {
      if (recognitionRef.current) recognitionRef.current.abort();
      if (synthRef.current) synthRef.current.cancel();
      audioRef.current.pause();
      
      if (audioContextRef.current) {
         const context = audioContextRef.current;
         if (context.state !== 'closed') {
             try { context.close(); } catch(e) {} 
         }
      }
    };
  }, [active, addLog, startListening, unlockAudio]); 

  const speak = (text, audioBlob = null) => {
    if (useNetlink && audioBlob) {
      try {
        const url = URL.createObjectURL(audioBlob);
        audioRef.current.src = url;
        audioRef.current.play().catch(() => speakLocalFallback(text));
        addToConversation('ai', text);
        return;
      } catch (e) {
        speakLocalFallback(text);
        return;
      }
    }
    speakLocalFallback(text);
  };
  
  const speakLocalFallback = (text) => {
     if (!synthRef.current) return;
     synthRef.current.cancel();
     const utterance = new SpeechSynthesisUtterance(text);
     const voices = synthRef.current.getVoices();
     // Use a clear, professional-sounding voice
     const professionalVoice = voices.find(v => v.name.includes('Google US English') || v.name.includes('Alex') || v.lang === 'en-US');
     if (professionalVoice) utterance.voice = professionalVoice;
     utterance.pitch = 1.0; 
     utterance.rate = 1.05;  
     utterance.onstart = () => setSpeaking(true);
     utterance.onend = () => { setSpeaking(false); if (active) setTimeout(() => startListening(), 500); };
     synthRef.current.speak(utterance);
     addToConversation('ai', text);
  }

  // --- TEXT INPUT HANDLER ---
  const handleTextSubmit = (e) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    
    if (listening && recognitionRef.current) recognitionRef.current.abort();
    
    const text = inputText;
    setInputText("");
    addToConversation('user', text);
    addLog("Text Input", text);
    processInput(text);
  };

  // --- AI BRAIN ---
  const systemInstruction = `
    You are the MediVision Pro Core AI, a sophisticated diagnostic support system. You assist professional medical personnel (radiologists, physicians) by analyzing data, providing summaries, and responding to technical queries.
    Your tone must be highly professional, concise, clinical, and precise. Avoid any conversational filler, slang, or emojis.
    Keep all diagnostic summaries and responses brief (1-2 sentences maximum).
    If asked about your identity, state: "I am MediVision Pro Core, a multimodal diagnostic support platform."
    
    **CONTEXT: MediVision Pro**
    - **Purpose:** Accelerate and enhance the accuracy of medical diagnosis using deep-learning models.
    
    **CRITICAL RULE: IMAGE ANALYSIS**
    If the user uploads an image, analyze it as a medical scan. Provide a structured finding and state the system's confidence level (e.g., "Finding: Minor calcification detected in the lower right lobe. Confidence Score: 98.7%.").
    If the image is not medical, state: "Input Error: Non-diagnostic file format detected. Please upload a valid medical scan."
  `;

  const callGeminiBrain = async (userText) => {
    setThinking(true);
    let text = "System Error: Diagnostic core link failure. Data transfer interrupted.";
    try {
        const parts = [];
        if (userFile && userFile.base64) {
            parts.push({ inlineData: { mimeType: userFile.mimeType, data: userFile.base64 } });
        }
        parts.push({ text: userText });
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: parts }], systemInstruction: { parts: [{ text: systemInstruction }] } })
          }
        );
        const data = await response.json();
        text = String(data.candidates?.[0]?.content?.parts?.[0]?.text || text);
    } catch (e) {
        text = "Connection failure. Re-attempting handshake...";
    }
    setThinking(false);
    return text;
  };

  const callGeminiVoice = async (text) => {
    if (!isAudioUnlocked) return null;
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-tts:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: text }] }],
            generationConfig: {
              responseModalities: ["AUDIO"],
              speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: "Kore" } } } 
            }
          })
        }
      );
      const data = await response.json();
      const base64Audio = data.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
      if (base64Audio) return pcmToWav(base64Audio);
    } catch (e) {}
    return null;
  };

  const processInput = async (text) => {
    if (useNetlink) {
      const replyText = await callGeminiBrain(text);
      const audioBlob = await callGeminiVoice(replyText);
      speak(replyText, audioBlob);
      return;
    }
    let reply = "Local processing mode. Netlink is required for access to the full diagnostic core.";
    speakLocalFallback(reply);
  };

  return (
    <div className="min-h-screen bg-gray-950 font-sans text-white overflow-hidden flex flex-col relative selection:bg-cyan-500/30">
      
      {/* --- HEADER (Navigation & Controls) --- */}
      <nav className="relative z-50 px-6 py-4 flex justify-between items-center bg-gray-900/90 backdrop-blur-sm border-b border-cyan-800/50 shadow-2xl shadow-black/70">
        <div className="flex items-center gap-2">
           <Zap className={`w-5 h-5 ${active ? 'text-red-500' : 'text-gray-600'}`} />
           <span className="font-extrabold text-xl tracking-widest text-white">MEDI<span className="text-red-500">VISION</span> PRO</span>
        </div>
        <div className="flex items-center gap-6">
           {/* NETLINK TOGGLE */}
           <div className="flex items-center gap-2 text-xs font-semibold text-gray-400">
               <Wifi size={14} className={useNetlink ? 'text-cyan-400' : 'text-gray-600'} />
               NETLINK
               <button 
                 onClick={() => setUseNetlink(!useNetlink)}
                 className={`relative w-10 h-5 rounded-full p-0.5 transition-colors ${useNetlink ? 'bg-cyan-600' : 'bg-gray-700'}`}
               >
                 <span className={`block w-4 h-4 bg-white rounded-full shadow-md transform transition-transform ${useNetlink ? 'translate-x-4' : 'translate-x-0'}`}></span>
               </button>
           </div>
           
           {/* DEBUG TOGGLE */}
           <button 
             onClick={() => setShowDebug(!showDebug)}
             className={`p-2 rounded-lg transition-all border ${showDebug ? 'bg-gray-800 text-green-400 border-green-800 shadow-lg' : 'bg-gray-900 text-gray-500 border-gray-800 hover:bg-gray-800'}`}
           >
             <Terminal size={14} />
           </button>
        </div>
      </nav>

      {/* --- MAIN CONTENT AREA --- */}
      <main className="flex-1 flex flex-col items-center justify-end relative z-10 p-4">
        
        {/* Background Text */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <h1 className="text-8xl md:text-[12rem] lg:text-[18rem] font-black tracking-widest text-cyan-900/10 select-none">
                MEDI<span className="text-red-900/10">VISION</span> PRO
            </h1>
        </div>

        {/* Image Upload Status */}
        <div className="absolute top-4 right-4 z-50 flex items-start gap-4">
            <label htmlFor="image-upload" className={`cursor-pointer px-4 py-2 rounded-lg border transition-all flex items-center gap-2 text-xs font-bold uppercase tracking-wider shadow-lg ${userFile ? 'bg-cyan-800 text-white border-cyan-500 shadow-cyan-500/30' : 'bg-gray-800/80 text-cyan-400 border-cyan-900 hover:bg-cyan-900/30'}`}>
                <Upload size={14} />
                {userFile ? 'SCAN LOADED' : 'UPLOAD SCAN'}
                <input id="image-upload" type="file" accept="image/*" ref={fileInputRef} onChange={handleFileChange} className="hidden" disabled={thinking}/>
            </label>

            {userFile && (
                <div className="bg-gray-800 p-1 rounded-lg border border-cyan-500/50 shadow-xl relative">
                    <img src={`data:${userFile.mimeType};base64,${userFile.base64}`} alt="Scan" className="w-20 h-20 object-cover opacity-90 rounded-md" />
                    <button onClick={clearFile} className="absolute -top-2 -right-2 bg-red-700 text-white rounded-full p-1 border border-red-500 hover:bg-red-600 transition-transform hover:scale-110">
                        <X size={10} />
                    </button>
                </div>
            )}
        </div>

        {/* --- CHAT INTERFACE --- */}
        <div className="w-full max-w-3xl px-4 z-20 mb-8">
           <div className={`bg-gray-900/95 backdrop-blur-md rounded-xl shadow-2xl transition-all duration-300 flex flex-col gap-2 ${thinking ? 'border-2 border-cyan-400 shadow-cyan-500/40' : 'border border-gray-700/50 shadow-black'}`}>
              
              {/* STATUS BAR */}
              <div className="flex justify-between items-center text-[10px] font-bold tracking-[0.1em] uppercase p-3 border-b border-gray-700/30">
                 {/* Status Indicators */}
                 <div className="flex items-center gap-4">
                    <div className={`flex items-center gap-1 ${active ? 'text-red-500' : 'text-gray-600'}`}>
                        <Cpu size={10} className={active ? 'animate-pulse' : ''} />
                        CORE: {active ? 'OPERATIONAL' : 'INACTIVE'}
                    </div>
                    <div className={`flex items-center gap-1 ${listening ? 'text-cyan-400' : 'text-gray-600'}`}>
                        <Mic size={10} className={listening ? 'animate-pulse' : ''} />
                        VOICE INPUT
                    </div>
                    <div className={`flex items-center gap-1 ${speaking ? 'text-cyan-400' : 'text-gray-600'}`}>
                        <Volume2 size={10} className={speaking ? 'animate-pulse' : ''} />
                        VOICE OUTPUT
                    </div>
                 </div>
                 
                 {/* Thinking Indicator */}
                 <div className="flex items-center gap-1">
                    {thinking && <span className="text-cyan-400 animate-pulse flex items-center gap-1"><Sparkles size={10} /> ANALYZING DATA...</span>}
                 </div>
              </div>

              {/* CONVERSATION HISTORY */}
              <div className="h-56 overflow-y-auto px-4 py-3 space-y-3 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-transparent">
                 {conversation.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`max-w-[85%] rounded-xl p-3 text-sm border shadow-md ${
                            msg.sender === 'user' 
                            ? 'bg-gray-700/30 border-gray-600 text-gray-100 rounded-br-sm' 
                            : msg.sender === 'system'
                            ? 'bg-gray-800/50 border-gray-700 text-gray-400 italic text-xs rounded-tl-sm'
                            : 'bg-cyan-900/30 border-cyan-800/50 text-cyan-200 rounded-tl-sm'
                        }`}>
                           {msg.sender !== 'system' && <div className="text-[10px] uppercase opacity-50 mb-1 font-semibold">{msg.sender === 'user' ? 'OPERATOR' : 'MV CORE'}</div>}
                           {msg.text}
                        </div>
                    </div>
                 ))}
                 <div ref={chatEndRef} />
              </div>

              {/* INPUT AREA */}
              <div className="p-4 pt-0">
                 {/* Text Input Form */}
                 <form onSubmit={handleTextSubmit} className="flex gap-2 mb-3">
                    <input 
                       type="text" 
                       value={inputText}
                       onChange={(e) => setInputText(e.target.value)}
                       placeholder={active ? "Enter query or diagnostic command..." : "System is inactive"}
                       disabled={!active || thinking}
                       className="flex-1 bg-gray-950 border border-gray-800 text-white text-sm px-4 py-3 rounded-full focus:outline-none focus:border-cyan-500 disabled:opacity-50 transition-shadow shadow-inner shadow-black/40"
                    />
                    <button 
                       type="submit" 
                       disabled={!active || thinking || !inputText.trim()}
                       className="bg-cyan-700 text-white px-4 py-3 rounded-full hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-lg shadow-cyan-900/30"
                    >
                       <Send size={16} />
                    </button>
                 </form>

                 {/* Main Controls */}
                 <div className="flex justify-center gap-2">
                     <button 
                        onClick={handleMainButtonClick}
                        className={`flex-1 py-3 rounded-full font-bold tracking-widest transition-all active:scale-[0.99] flex justify-center items-center gap-2 border-2 shadow-lg ${
                           active 
                           ? 'bg-red-900/30 text-red-400 border-red-700 hover:bg-red-800/40 shadow-red-500/20' 
                           : 'bg-gray-700/30 text-white border-gray-600 hover:bg-gray-700/50 shadow-gray-500/20'
                        }`}
                     >
                        {active ? "TERMINATE SESSION" : "INITIATE SESSION"}
                     </button>
                     
                     {active && (
                       <button 
                         onClick={startListening}
                         disabled={listening || speaking || thinking}
                         className={`px-6 py-3 rounded-full border font-bold transition-colors active:scale-[0.99] shadow-lg ${
                            listening 
                            ? 'bg-red-500/30 border-red-500 text-red-200 shadow-red-500/30 animate-pulse' 
                            : 'bg-gray-800/50 border-gray-700 text-cyan-400 hover:bg-gray-700/50 shadow-cyan-500/20'
                         }`}
                       >
                         <Mic size={20} />
                       </button>
                     )}
                 </div>
              </div>
           </div>
        </div>
      </main>

      {/* --- TERMINAL LOG --- */}
      {showDebug && (
        <div className="absolute top-20 right-4 w-60 h-48 bg-black/90 text-green-500 text-[10px] font-mono p-3 rounded-lg border border-green-900/50 z-50 overflow-y-auto shadow-xl">
           <div className="border-b border-green-900/50 pb-1 mb-1 font-bold text-green-400 tracking-widest text-[11px] flex justify-between items-center">
             SYS.LOG
             <Terminal size={12} />
           </div>
           {logs.map((log, i) => (
             <div key={i} className="mb-0.5 break-words opacity-80 leading-tight">
               <span className="text-gray-500">[{log.time}]</span> <span className="text-cyan-600/70">{log.source}:</span> {log.message}
             </div>
           ))}
        </div>
      )}
    </div>
  );
}
