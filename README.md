🔬 MediVision Pro Core AI Companion

MediVision Pro Core AI Companion is a professional, multimodal diagnostic support interface built using React and Tailwind CSS. This application is designed to simulate a high-speed, voice-activated system for medical personnel (such as radiologists or physicians) to interact with an AI diagnostic engine.

It features image upload (for simulated scan analysis), real-time conversation history, TTS (Text-to-Speech) for AI responses, and integrated Speech Recognition for voice commands.

✨ Features

Multimodal Input: Supports text, voice (Speech Recognition), and image upload (Base64 encoding).

Voice Output (TTS): Utilizes the Gemini TTS API (gemini-2.5-flash-preview-tts) for clinical, clear AI responses.

Diagnostic Core: Uses the Gemini API (gemini-2.5-flash-preview-09-2025) for contextual, image-grounded text generation based on a medical analyst system persona.

WAV Audio Handling: Includes helper functions to correctly convert raw PCM audio data from the TTS API into a playable WAV blob.

Real-Time Status: Visual indicators for Core Status, Netlink connection, Listening, Speaking, and Data Analysis (Thinking) states.

Professional UI: Sleek, dark-mode, high-fidelity interface styled entirely with Tailwind CSS.

⚙️ Requirements & Setup

This project is a single React component (App.jsx) that relies on the Google Gemini API for all core intelligence and voice services.

1. API Key

You must provide your Gemini API Key in the designated variable within the code for the application to function.

In App.jsx, replace the placeholder in this line:

const apiKey = ""; // API Key injected by environment 


2. Dependencies

This is a single-file component, requiring a standard modern React environment.

React: react and react-dom.

Tailwind CSS: The application assumes Tailwind CSS utility classes are available in the running environment.

Lucide Icons: The code uses components from lucide-react for all iconography.

# Example installation for a typical React project:
npm install lucide-react


3. Running the Application

Save the provided code as App.jsx and place it in the src/ directory of your React project. Ensure it is imported and rendered by your main application file (e.g., main.jsx or index.js).

💻 Usage

Initial Activation: The system attempts to initialize audio on load. If it fails (due to browser restrictions), you can click the INITIATE SESSION button to manually activate the system core.

Toggle Netlink: Use the NETLINK switch in the header to enable/disable connections to the Gemini API services.

Upload Scan: Click UPLOAD SCAN (or the SCAN LOADED button) to select a medical image file. The AI will use this image as context for its diagnostic analysis.

Text Command: Type your query into the input field and press Send or Enter.

Voice Command: Click the Microphone button (🎙️) to activate the browser's Speech Recognition service and speak your command.

Debug Log

Click the Terminal icon (⚙️) in the header to reveal the system log, which shows real-time events, API call status, and voice input/output logging
