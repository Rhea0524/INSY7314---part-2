import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Register from './components/Register';
import Login from './components/Login';
import EmployeeLogin from './components/EmployeeLogin';
import CustomerDashboard from './components/CustomerDashboard';
import TransactionDashboard from './components/TransactionDashboard';
import './App.css';

// Navigation component
function Navigation() {
  const { user, logout, isAuthenticated } = useAuth();

  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      logout();
    }
  };

  // Check if user is employee or customer
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';
  const isCustomer = user?.accountNumber && !isEmployee;

  return (
    <nav className="navbar">
      <div className="nav-container">
        <Link to="/" className="nav-logo">
          🏦 International Payments Portal
        </Link>
        <div className="nav-menu">
          {!isAuthenticated ? (
            <>
              <Link to="/login" className="nav-link">Customer Login</Link>
              <Link to="/register" className="nav-link">Register</Link>
              <Link to="/employee-login" className="nav-link">Employee Login</Link>
            </>
          ) : (
            <>
              {isCustomer && (
                <Link to="/dashboard" className="nav-link">Dashboard</Link>
              )}
              {isEmployee && (
                <Link to="/employee-dashboard" className="nav-link">Transaction Portal</Link>
              )}
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

// Protected Route component
function ProtectedRoute({ children, requireEmployee = false }) {
  const { isAuthenticated, loading, user } = useAuth();
  
  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Check if user is employee or customer
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';
  
  // If route requires employee but user is not employee
  if (requireEmployee && !isEmployee) {
    return <Navigate to="/dashboard" replace />;
  }
  
  // If route is for customers but user is employee
  if (!requireEmployee && isEmployee) {
    return <Navigate to="/employee-dashboard" replace />;
  }
  
  return children;
}

// Main App Routes component
function AppRoutes() {
  const { isAuthenticated, user } = useAuth();
  
  const isEmployee = user?.userType === 'employee' || user?.role === 'employee';

  return (
    <div className="App">
      <Navigation />
      
      <div className="main-content">
        <Routes>
          <Route path="/" element={
            isAuthenticated ? (
              isEmployee ? <Navigate to="/employee-dashboard" replace /> : <Navigate to="/dashboard" replace />
            ) : (
              <div className="home-page">
                <div className="home-content">
                  <h1>Welcome to International Payments Portal</h1>
                  <p className="home-subtitle">Secure, fast, and reliable international payment processing</p>
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
                  <div className="home-actions">
                    <Link to="/register" className="btn-primary">Get Started</Link>
                    <Link to="/login" className="btn-secondary">Customer Login</Link>
                    <Link to="/employee-login" className="btn-secondary">Employee Login</Link>
                  </div>
                </div>
              </div>
            )
          } />
          
          <Route path="/register" element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <Register />
          } />
          
          <Route path="/login" element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login />
          } />

          <Route path="/employee-login" element={
            isAuthenticated ? <Navigate to="/employee-dashboard" replace /> : <EmployeeLogin />
          } />
          
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <CustomerDashboard />
            </ProtectedRoute>
          } />

          <Route path="/employee-dashboard" element={
            <ProtectedRoute requireEmployee={true}>
              <TransactionDashboard />
            </ProtectedRoute>
          } />
          
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>

      <footer className="footer">
        <p>&copy; 2024 International Payments Portal. All rights reserved.</p>
        <p>🔒 Secured with SSL encryption, password hashing, and input validation</p>
      </footer>
    </div>
  );
}

// Main App component with AuthProvider wrapper
function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  );
}

export default App;