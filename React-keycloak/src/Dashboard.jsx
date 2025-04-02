import React from "react";
import { getToken, clearToken } from "./auth";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";

const Dashboard = () => {
  const navigate = useNavigate();
  const token = getToken();

  const handleLogout = () => {
    clearToken();
    navigate("/");
  };
  const createAndSaveCookie = async () => {
    console.log("✅ NodeBB button clicked!");
    console.log("🔑 Token received:", token);

    try {
      if (token) {
        console.log("🔑 User authenticated! Storing cookie...");

        Cookies.set("token", token, {
          path: "/",
          secure: false, // Keep false since you're on HTTP locally
          httpOnly: false, // Can't set httpOnly from JS
          sameSite: "Lax",
        });
        Cookies.set("nbb_token", token, {
          path: "/",
          secure: false, // Keep false since you're on HTTP locally
          httpOnly: false, // Can't set httpOnly from JS
          sameSite: "Lax",
        });

        console.log("✅ Cookie set:", Cookies.get("token"));
        // 🔄 Redirect user to NodeBB forum
        window.location.href = "http://localhost:4567";
      }
    } catch (error) {
      console.error("❌ Error setting session cookie:", error);
    }
  };

  return (
    <div>
      <h1>Dashboard</h1>
      {token ? <p>Authenticated!</p> : <p>Not authenticated</p>}
      <button onClick={createAndSaveCookie}>NodeBB</button>

      <button onClick={handleLogout}>Logout</button>
    </div>
  );
};

export default Dashboard;
