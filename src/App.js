/**
 * App.js - Main Application Component
 * 
 * This file serves as the root component of the International Payments Portal application.
 * It implements a comprehensive routing system with role-based access control, distinguishing
 * between customer and employee user types. The application uses React Router for navigation
 * and a custom AuthContext for authentication state management.
 * 
 * Key Features:
 * - Role-based routing (Customer vs Employee access)
 * - Protected routes with authentication checks
 * - Centralized navigation with conditional rendering
 * - Persistent authentication state across page refreshes
 * 
 * @module App
 * @requires react
 * @requires react-router-dom
 * @requires ./context/AuthContext
 */

import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Register from './components/Register';
import Login from './components/Login';
import EmployeeLogin from './components/EmployeeLogin';
import CustomerDashboard from './components/CustomerDashboard';
import TransactionDashboard from './components/TransactionDashboard';
import './App.css';

/**
 * Navigation Component
 * 
 * Renders the main navigation bar with conditional menu items based on authentication
 * status and user role. Implements role-based UI rendering to show appropriate
 * navigation options for customers and employees.
 * 
 * Authentication States:
 * - Unauthenticated: Shows Login, Register, and Employee Login links
 * - Authenticated Customer: Shows Dashboard link and Logout button
 * - Authenticated Employee: Shows Transaction Portal link and Logout button
 * 
 * @component
 * @returns {JSX.Element} Navigation bar with role-appropriate menu items
 */
function Navigation() {
  // Destructure authentication state and methods from AuthContext
  const { user, logout, isAuthenticated } = useAuth();

  /**
   * Handles user logout with confirmation dialog
   * Prevents accidental logouts by requiring user confirmation
   */
  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      logout();
    }
  };

  // Determine user type based on user object properties
  // Employee identification: Check both userType and role fields for flexibility
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';
  
  // Customer identification: Must have accountNumber and not be an employee
  const isCustomer = user?.accountNumber && !isEmployee;

  return (
    <nav className="navbar">
      <div className="nav-container">
        {/* Application branding with emoji icon */}
        <Link to="/" className="nav-logo">
          🏦 International Payments Portal
        </Link>
        
        <div className="nav-menu">
          {/* Conditional rendering: Show different menu items based on authentication status */}
          {!isAuthenticated ? (
            // Unauthenticated users see public navigation links
            <>
              <Link to="/login" className="nav-link">Customer Login</Link>
              <Link to="/register" className="nav-link">Register</Link>
              <Link to="/employee-login" className="nav-link">Employee Login</Link>
            </>
          ) : (
            // Authenticated users see role-specific navigation
            <>
              {/* Customer-specific navigation */}
              {isCustomer && (
                <Link to="/dashboard" className="nav-link">Dashboard</Link>
              )}
              
              {/* Employee-specific navigation */}
              {isEmployee && (
                <Link to="/employee-dashboard" className="nav-link">Transaction Portal</Link>
              )}
              
              {/* Logout button with user name display */}
              <button onClick={handleLogout} className="nav-link logout-btn">
                Logout ({user?.fullName || user?.name})
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}

/**
 * ProtectedRoute Component
 * 
 * Higher-order component that wraps routes requiring authentication and/or
 * specific user roles. Implements authorization logic to prevent unauthorized
 * access to protected resources.
 * 
 * Security Features:
 * - Redirects unauthenticated users to login page
 * - Enforces role-based access control
 * - Handles loading states during authentication verification
 * - Prevents privilege escalation by validating user roles
 * 
 * @component
 * @param {Object} props - Component properties
 * @param {JSX.Element} props.children - Child components to render if authorized
 * @param {boolean} [props.requireEmployee=false] - Whether route requires employee role
 * @returns {JSX.Element} Protected content or redirect based on authorization
 */
function ProtectedRoute({ children, requireEmployee = false }) {
  // Access authentication state from context
  const { isAuthenticated, loading, user } = useAuth();
  
  // Display loading spinner while authentication state is being verified
  // Prevents flash of unauthorized content during initialization
  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  
  // Redirect unauthenticated users to login page
  // 'replace' prop prevents back button from returning to protected route
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Determine if current user has employee privileges
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';
  
  // Authorization check: Employee-only routes
  // Redirect non-employees attempting to access employee routes to customer dashboard
  if (requireEmployee && !isEmployee) {
    return <Navigate to="/dashboard" replace />;
  }
  
  // Authorization check: Customer-only routes
  // Redirect employees attempting to access customer routes to employee dashboard
  if (!requireEmployee && isEmployee) {
    return <Navigate to="/employee-dashboard" replace />;
  }
  
  // User is authorized - render protected content
  return children;
}

/**
 * AppRoutes Component
 * 
 * Defines the application's routing structure using React Router v6.
 * Implements a comprehensive routing system with role-based redirects,
 * protected routes, and conditional navigation flow.
 * 
 * Route Structure:
 * - Public routes: Home, Login, Register, Employee Login
 * - Customer protected routes: Customer Dashboard
 * - Employee protected routes: Transaction Dashboard
 * - Catch-all route: Redirects to home for undefined paths
 * 
 * @component
 * @returns {JSX.Element} Application routing structure
 */
function AppRoutes() {
  // Access authentication state for conditional routing logic
  const { isAuthenticated, user } = useAuth();
  
  // Determine user role for intelligent route redirects
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';

  return (
    <div className="App">
      {/* Persistent navigation bar across all routes */}
      <Navigation />
      
      <div className="main-content">
        <Routes>
          {/* 
            Home Route (/)
            Behavior depends on authentication status:
            - Authenticated employees: Redirect to employee dashboard
            - Authenticated customers: Redirect to customer dashboard
            - Unauthenticated users: Display landing page with features
          */}
          <Route path="/" element={
            isAuthenticated ? (
              // Intelligent redirect based on user role
              isEmployee ? <Navigate to="/employee-dashboard" replace /> : <Navigate to="/dashboard" replace />
            ) : (
              // Landing page for unauthenticated visitors
              <div className="home-page">
                <div className="home-content">
                  <h1>Welcome to International Payments Portal</h1>
                  <p className="home-subtitle">Secure, fast, and reliable international payment processing</p>
                  
                  {/* Feature cards highlighting application benefits */}
                  <div className="home-features">
                    <div className="feature-card">
                      <span className="feature-icon">🔒</span>
                      <h3>Secure</h3>
                      <p>Bank-level encryption and security</p>
                    </div>
                    <div className="feature-card">
                      <span className="feature-icon">⚡</span>
                      <h3>Fast</h3>
                      <p>Quick international transfers via SWIFT</p>
                    </div>
                    <div className="feature-card">
                      <span className="feature-icon">🌍</span>
                      <h3>Global</h3>
                      <p>Send money worldwide</p>
                    </div>
                  </div>
                  
                  {/* Call-to-action buttons for user onboarding */}
                  <div className="home-actions">
                    <Link to="/register" className="btn-primary">Get Started</Link>
                    <Link to="/login" className="btn-secondary">Customer Login</Link>
                    <Link to="/employee-login" className="btn-secondary">Employee Login</Link>
                  </div>
                </div>
              </div>
            )
          } />
          
          {/* 
            Registration Route (/register)
            Redirects authenticated users to dashboard to prevent duplicate registrations
          */}
          <Route path="/register" element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <Register />
          } />
          
          {/* 
            Customer Login Route (/login)
            Redirects authenticated users to prevent unnecessary re-authentication
          */}
          <Route path="/login" element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login />
          } />

          {/* 
            Employee Login Route (/employee-login)
            Separate authentication flow for employees with different credentials
          */}
          <Route path="/employee-login" element={
            isAuthenticated ? <Navigate to="/employee-dashboard" replace /> : <EmployeeLogin />
          } />
          
          {/* 
            Customer Dashboard Route (/dashboard)
            Protected route requiring customer authentication
            Automatically redirects employees to their appropriate dashboard
          */}
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <CustomerDashboard />
            </ProtectedRoute>
          } />

          {/* 
            Employee Dashboard Route (/employee-dashboard)
            Protected route requiring employee authentication
            Implements role-based access control via requireEmployee prop
          */}
          <Route path="/employee-dashboard" element={
            <ProtectedRoute requireEmployee={true}>
              <TransactionDashboard />
            </ProtectedRoute>
          } />
          
          {/* 
            Catch-all Route (*)
            Handles undefined routes by redirecting to home page
            Improves user experience by preventing 404 errors
          */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>

      {/* 
        Application Footer
        Displays copyright information and security features
        Visible across all routes for consistency
      */}
      <footer className="footer">
        <p>&copy; 2024 International Payments Portal. All rights reserved.</p>
        <p>🔒 Secured with SSL encryption, password hashing, and input validation</p>
      </footer>
    </div>
  );
}

/**
 * App Component (Root Component)
 * 
 * The top-level component that wraps the entire application with necessary providers.
 * Establishes the authentication context and routing infrastructure for all child components.
 * 
 * Component Hierarchy:
 * App (AuthProvider) → Router → AppRoutes → Various route components
 * 
 * Provider Responsibilities:
 * - AuthProvider: Manages global authentication state, user data, and auth methods
 * - Router: Enables client-side routing and navigation without page refreshes
 * 
 * @component
 * @returns {JSX.Element} Root application component with context providers
 */
function App() {
  return (
    // AuthProvider must wrap Router to make auth context available to all routes
    <AuthProvider>
      {/* BrowserRouter enables HTML5 history API for clean URLs */}
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  );
}

// Export App component as default export for use in index.js
export default App;