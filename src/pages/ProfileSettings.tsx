// src/pages/ProfileSettings.tsx
import React, { useState } from "react";

const ProfileSettings = () => {
  const [email, setEmail] = useState("john@example.com");
  // Similarly, add state for other fields

  const handleUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    // Send updated data to the server and trigger email notification on change.
    console.log("Profile updated", { email });
  };

  return (
    <form onSubmit={handleUpdate} className="max-w-md mx-auto p-4">
      <h2 className="text-xl font-bold mb-4">Update Profile Settings</h2>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="border p-2 mb-2 w-full"
      />
      {/* Include inputs for Password, Name, Surname, etc. */}
      <button type="submit" className="bg-green-500 text-white p-2 rounded">
        Update Profile
      </button>
    </form>
  );
};

export default ProfileSettings;
