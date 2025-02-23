// src/components/Navigation.tsx
import React from "react";
import { NavLink } from "react-router-dom";

const Navigation = () => {
  return (
    <nav className="bg-blue-500 p-4 text-white">
      <ul className="flex space-x-4">
        <li>
          <NavLink to="/" className="hover:underline">
            Home
          </NavLink>
        </li>
        <li>
          <NavLink to="/profile" className="hover:underline">
            Profile
          </NavLink>
        </li>
        <li>
          <NavLink to="/admin" className="hover:underline">
            Admin Panel
          </NavLink>
        </li>
      </ul>
    </nav>
  );
};

export default Navigation;
