export const saveToken = (token) => {
  if (token) {
    localStorage.setItem("authToken", token);
    console.log("Token successfully saved to localStorage.");
    return token;
  } else {
    console.error("Attempted to save an empty token!");
  }
};

export const getToken = () => {
  const token = localStorage.getItem("authToken");
  console.log("Retrieved token from storage:", token);
  return token;
};

export const clearToken = () => {
  localStorage.removeItem("authToken");
  console.log("Token removed from storage.");
};
