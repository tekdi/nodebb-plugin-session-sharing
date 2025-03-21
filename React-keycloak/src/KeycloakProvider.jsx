import React, { createContext, useState, useEffect } from "react";
import Keycloak from "keycloak-js";
import Cookies from "js-cookie";

const keycloak = new Keycloak({
  url: "http://127.0.0.1:8080/auth",
  realm: "nodebb",
  clientId: "nodebb-client",
});

export const AuthContext = createContext();

const KeycloakProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(null);

  useEffect(() => {
    console.log("Initializing Keycloak...");

    keycloak
      .init({ onLoad: "login-required", checkLoginIframe: false }) // Disable iframe check
      .then((authenticated) => {
        console.log("Authentication status:", authenticated);
        setIsAuthenticated(authenticated);

        if (authenticated) {
          console.log("User authenticated:", keycloak.token);

          // Store token in cookies
          Cookies.set("token", keycloak.token, {
            secure: window.location.protocol === "https:", // Only secure in production
            sameSite: "Lax", // Prevents cross-site issues
            path: "/", // Available across pages
            expires: 1, // 1 day expiration
          });
        } else {
          console.warn("User is not authenticated.");
        }
      })
      .catch((err) => console.error("Keycloak Init Error", err));
  }, []);

  if (isAuthenticated === null) {
    return <h2>Loading Keycloak...</h2>;
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, keycloak }}>
      {children}
    </AuthContext.Provider>
  );
};

export default KeycloakProvider;
