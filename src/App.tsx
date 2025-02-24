// src/App.tsx
import React, { Suspense, lazy } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Navigation from "./components/Navigation";

const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const AdminPanel = lazy(() => import("./pages/AdminPanel"));
const notify = () => toast("Profile updated successfully!");

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

const App = () => {
  return (
    <div>
      {/* Your app components */}
      <button onClick={notify}>Notify</button>
      <ToastContainer />
    </div>
  );
};

export default App;
