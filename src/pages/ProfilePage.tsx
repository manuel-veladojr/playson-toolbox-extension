// src/pages/ProfilePage.tsx
import React from "react";
import Sidebar from "../components/Sidebar";

const ProfilePage = () => {
  // This data would normally come from your backend/API.
  const user = {
    name: "John",
    surname: "Doe",
    suffix: "Jr.",
    username: "john_doe",
    email: "john@example.com",
    phone: "123-456-7890"
  };

  return (
    <div className="flex">
      <Sidebar />
      <div className="flex-1 p-4">
        <h2 className="text-2xl font-bold">Profile</h2>
        <p><strong>Name:</strong> {user.name} {user.surname} {user.suffix}</p>
        <p><strong>Username:</strong> {user.username}</p>
        <p><strong>Email:</strong> {user.email}</p>
        <p><strong>Phone:</strong> {user.phone}</p>
      </div>
    </div>
  );
};

export default ProfilePage;
