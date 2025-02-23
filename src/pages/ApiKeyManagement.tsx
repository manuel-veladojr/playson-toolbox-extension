// src/pages/ApiKeyManagement.tsx
import React, { useEffect, useState } from "react";

interface ApiKey {
  id: number;
  key: string;
  expiration: string;
}

const ApiKeyManagement = () => {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);

  useEffect(() => {
    // Fetch API keys from your backend API.
    // Example: fetch("/api/apikeys").then(...);
    setApiKeys([
      { id: 1, key: "abcdef123456", expiration: "2025-01-01" }
    ]);
  }, []);

  const handleRegenerate = (id: number) => {
    // Call API to regenerate the key.
    console.log("Regenerating API key for ID:", id);
  };

  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">API Key Management</h2>
      <ul>
        {apiKeys.map((apiKey) => (
          <li key={apiKey.id} className="mb-2 border p-2 rounded">
            <p><strong>Key:</strong> {apiKey.key}</p>
            <p><strong>Expires:</strong> {apiKey.expiration}</p>
            <button onClick={() => handleRegenerate(apiKey.id)} className="bg-blue-500 text-white p-1 rounded">
              Regenerate Key
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ApiKeyManagement;
