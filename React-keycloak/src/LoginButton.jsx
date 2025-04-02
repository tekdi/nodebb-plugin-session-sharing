import Keycloak from "keycloak-js";
import Cookies from "js-cookie";
import { useContext } from "react";
import { AuthContext } from "./KeycloakProvider";
const keycloak = new Keycloak({
  url: "http://127.0.0.1:8080/auth", // Use 127.0.0.1 instead of localhost
  realm: "nodebb",
  clientId: "nodebb-client",
});

const LoginButton = () => {
  const { isAuthenticated, keycloak } = useContext(AuthContext);
  const handleLogin = async () => {
    console.log("✅ Login button clicked!");

    if (!keycloak) {
      console.error("❌ Keycloak is not initialized!");
      return;
    }

    try {
      // Check if user is already authenticated
      if (!keycloak.authenticated) {
        console.log("🔄 Redirecting to Keycloak login...");
        await keycloak.login();
      } else {
        console.log("🔑 User authenticated! Token:", keycloak.token);

        // Store the token in cookies for session-sharing with NodeBB
        Cookies.set("token", keycloak.token, {
          path: "/",
          secure: false,
          httpOnly: false,
          sameSite: "Lax",
        });

        console.log("✅ Cookie set:", Cookies.get("token"));
      }
    } catch (error) {
      console.error("❌ Keycloak login error:", error);
    }
  };

  return (
    <button onClick={handleLogin}>
      {isAuthenticated ? "Logged in" : "Login to NodeBB"}
    </button>
  );
};

export default LoginButton;
