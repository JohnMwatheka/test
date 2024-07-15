// app/login/page.js
"use client";
import React, { useState } from "react";
import Link from 'next/link';

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
  
    // Check for empty email or password fields
    if (!email || !password) {
      setError("Please fill in all fields.");
      return;
    }
  
    // Check password length
    if (password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }
  
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });
  
      if (response.ok) {
        // Redirect to the dashboard page
        window.location.href = "/dashboard";
      } else {
        const data = await response.json();
        setError(data.message);
      }
    } catch (error) {
      console.error("Login error:", error);
      setError("An error occurred during login");
    }
  };

  return (
    <div className="container">
      <main style={{ 
        backgroundImage: `url('/login.jpg')`, // Replace with your image path
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
      }}>
        <div className="main-container form" style={{ 
          maxWidth: '600px', 
          padding: '20px', 
          backgroundColor: '#fff', 
          borderRadius: '8px', 
          boxShadow: '0 4px 8px rgba(0, 0, 0, 0.9)' 
        }}>
          <div className="form-wrapper" style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center' 
          }}>
            <h1>Login</h1>
            <form style={{ width: 'auto' }} onSubmit={handleLogin}>
              <div className="form-group" style={{ marginBottom: '20px' }}>
                <label htmlFor="email">Email:</label>
                <input
                  type="email"
                  name="email"
                  className="form-control"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div className="form-group" style={{ marginBottom: '20px' }}>
                <label htmlFor="password">Password:</label>
                <input
                  type="password"
                  name="password"
                  className="form-control"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              <button type="submit" className="btn btn-outline-success" style={{ width: 'auto' }}>
                Login
              </button>
              {error && <p style={{ color: 'red' }}>{error}</p>}
            </form>
            <p> Do not have an account? <a href="/register" className="text-success fs-5">Sign up</a></p>
          </div>
        </div>
      </main>
    </div>
  );
}
