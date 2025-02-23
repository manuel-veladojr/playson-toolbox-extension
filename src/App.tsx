// src/App.tsx
import React, { Suspense, lazy } from "react";
import Navigation from "./components/Navigation";

const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const AdminPanel = lazy(() => import("./pages/AdminPanel"));

const App = () => {
  return (
    <div>
      <Navigation />
      <Suspense fallback={<div>Loading...</div>}>
        {/* Use your routing logic here to load the correct page */}
        <ProfilePage />
      </Suspense>
    </div>
  );
};

export default App;
