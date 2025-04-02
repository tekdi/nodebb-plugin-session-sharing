import React from "react";
import ReactDOM from "react-dom/client";
import { ReactKeycloakProvider } from "@react-keycloak/web";
import keycloak from "./keycloak";
import App from "./App";
import { saveToken } from "./auth";

const eventLogger = (event, error) => {
  console.log("Keycloak Event:", event);
  if (event === "onAuthSuccess" && keycloak.token) {
    saveToken(keycloak.token);
  }
};

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <ReactKeycloakProvider authClient={keycloak} onEvent={eventLogger}>
    <App />
  </ReactKeycloakProvider>
);
