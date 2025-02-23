// Example in ProfilePage.tsx
import React from "react";
import Sidebar from "../components/Sidebar";

const ProfilePage = () => {
  return (
    <div className="flex">
      <Sidebar />
      <div className="flex-1 p-4">
        <h2 className="text-2xl font-bold">Profile</h2>
        {/* Profile content goes here */}
      </div>
    </div>
  );
};

export default ProfilePage;
