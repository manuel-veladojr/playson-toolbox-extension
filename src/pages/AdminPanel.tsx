// src/pages/AdminPanel.tsx
import React from "react";

const AdminPanel = () => {
  // Placeholder data; in a real app, fetch this from your API.
  const users = [
    { id: 1, username: "user1", status: "active" },
    { id: 2, username: "user2", status: "inactive" },
  ];

  const handleAction = (action: string, userId: number) => {
    // Implement API calls here for activate, deactivate, reset, or delete.
    console.log(`Action: ${action} on user ${userId}`);
  };

  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">User Management</h2>
      <table className="min-w-full">
        <thead>
          <tr>
            <th className="border p-2">Username</th>
            <th className="border p-2">Status</th>
            <th className="border p-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td className="border p-2">{user.username}</td>
              <td className="border p-2">{user.status}</td>
              <td className="border p-2 space-x-2">
                <button onClick={() => handleAction("activate", user.id)} className="bg-green-500 text-white p-1 rounded">
                  Activate
                </button>
                <button onClick={() => handleAction("deactivate", user.id)} className="bg-yellow-500 text-white p-1 rounded">
                  Deactivate
                </button>
                <button onClick={() => handleAction("reset", user.id)} className="bg-blue-500 text-white p-1 rounded">
                  Reset Password
                </button>
                {/* Superadmin-only action */}
                <button onClick={() => handleAction("delete", user.id)} className="bg-red-500 text-white p-1 rounded">
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AdminPanel;
