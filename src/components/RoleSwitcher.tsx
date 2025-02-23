// src/components/RoleSwitcher.tsx
import React, { useState } from "react";

const RoleSwitcher = () => {
  // Sample roles – in a real application, these might be fetched from your API.
  const roles = ["Admin", "Account Manager", "Technical Support"];
  const [currentRole, setCurrentRole] = useState(roles[0]);

  return (
    <div className="p-4 border rounded">
      <label className="block mb-2 font-bold">Current Role:</label>
      <select
        value={currentRole}
        onChange={(e) => setCurrentRole(e.target.value)}
        className="border p-2"
      >
        {roles.map((role) => (
          <option key={role} value={role}>{role}</option>
        ))}
      </select>
      <p className="mt-2 text-gray-600">Role has been switched to: {currentRole}</p>
    </div>
  );
};

export default RoleSwitcher;
