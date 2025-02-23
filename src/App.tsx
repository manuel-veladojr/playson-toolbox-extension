// src/App.tsx
import React from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const notify = () => toast("Profile updated successfully!");

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
