// src/components/Popup.tsx
import React, { useState } from "react";

const Popup = () => {
  const [darkMode, setDarkMode] = useState(false);

  return (
    <div className={`min-h-screen ${darkMode ? "bg-gray-900" : "bg-white"} transition-colors duration-300`}>
      <header className="p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold text-gray-800 dark:text-gray-100">My Extension</h1>
        <button 
          onClick={() => setDarkMode(!darkMode)} 
          className="px-3 py-1 border rounded"
        >
          {darkMode ? "Light Mode" : "Dark Mode"}
        </button>
      </header>
      <main className="p-4">
        <p className="text-gray-700 dark:text-gray-300">
          Welcome to the browser extension popup!
        </p>
      </main>
    </div>
  );
};

export default Popup;
