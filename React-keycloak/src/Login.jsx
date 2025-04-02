import React from "react";
import { useKeycloak } from "@react-keycloak/web";
import { saveToken, getToken, clearToken } from "./auth"; // Ensure these are defined
import { useNavigate, Link } from "react-router-dom";
import Cookies from "js-cookie"; // Make sure js-cookie is installed
import { Card, CardContent, Typography, Button, Box } from "@mui/material";

const Login = () => {
  const { keycloak } = useKeycloak();
  const navigate = useNavigate();
  const token = getToken();

  const handleLogout = () => {
    clearToken();
    keycloak.logout();
    navigate("/");
  };

  const handleLogin = async () => {
    try {
      await keycloak.login({
        idpHint: "google",
      });
      if (keycloak.authenticated && keycloak.token) {
        saveToken(keycloak.token);
        console.log("Token saved:", keycloak.token);
        navigate("/dashboard");
      } else {
        console.error("No token received after login.");
      }
    } catch (error) {
      console.error("Login Failed", error);
    }
  };

  const createAndSaveCookie = () => {
    if (!token) return;

    console.log("✅ NodeBB button clicked!");
    console.log("🔑 Token received:", token);

    Cookies.set("token", token, {
      path: "/",
      secure: false,
      httpOnly: false,
      sameSite: "Lax",
    });
    Cookies.set("nbb_token", token, {
      path: "/",
      secure: false,
      httpOnly: false,
      sameSite: "Lax",
    });

    console.log("✅ Cookie set:", Cookies.get("token"));
    window.location.href = "http://localhost:4567"; // Redirect to NodeBB
  };

  return (
    <Box
      display="flex"
      justifyContent="center"
      alignItems="center"
      minHeight="100vh"
      bgcolor="#f4f4f4"
    >
      <Card sx={{ maxWidth: 400, p: 3, boxShadow: 3 }}>
        <CardContent sx={{ textAlign: "center" }}>
          {!keycloak.authenticated ? (
            <>
              <Typography variant="h5" fontWeight="bold" gutterBottom>
                Login
              </Typography>
              <Button
                variant="contained"
                color="primary"
                fullWidth
                onClick={handleLogin}
              >
                Login with Keycloak
              </Button>
            </>
          ) : (
            <>
              <Typography variant="h5" fontWeight="bold" gutterBottom>
                Dashboard
              </Typography>
              <Typography color="textSecondary" mb={2}>
                Authenticated!
              </Typography>
              <Button
                variant="contained"
                color="success"
                fullWidth
                sx={{ mb: 1 }}
                onClick={createAndSaveCookie}
              >
                Access NodeBB
              </Button>
              <Button
                variant="contained"
                color="error"
                fullWidth
                onClick={handleLogout}
              >
                Logout
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default Login;
