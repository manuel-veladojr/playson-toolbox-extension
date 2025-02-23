// src/pages/LoginPage.tsx
import React, { useState } from "react";

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Implement ISO-compliant security validations and API calls here.
    console.log("Logging in...", { username, email, password, rememberMe });
  };

  return (
    <form onSubmit={handleLogin} className="max-w-sm mx-auto p-4">
      <h2 className="text-xl font-bold mb-4">Login</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        className="border p-2 mb-2 w-full"
      />
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="border p-2 mb-2 w-full"
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="border p-2 mb-2 w-full"
      />
      <div className="flex items-center mb-4">
        <input
          type="checkbox"
          checked={rememberMe}
          onChange={() => setRememberMe(!rememberMe)}
          className="mr-2"
        />
        <label>Remember Me</label>
      </div>
      <button type="submit" className="bg-blue-500 text-white p-2 rounded">
        Login
      </button>
      <div className="mt-2">
        <a href="/forgot-password" className="text-blue-500">Forgot Password?</a>
      </div>
    </form>
  );
};

export default LoginPage;
