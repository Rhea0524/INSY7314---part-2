/**
 * AuthContext.js
 * 
 * Authentication Context Provider for Customer and Employee Management System
 * 
 * This module implements a centralized authentication system that supports two distinct
 * user types: customers (using JWT with httpOnly cookies) and employees (using Firebase Auth).
 * It provides a React Context API interface for authentication state management across
 * the application.
 * 
 * Key Features:
 * - Dual authentication: Backend JWT for customers, Firebase Auth for employees
 * - Persistent sessions using localStorage for user data
 * - Security-enhanced token management with httpOnly cookies
 * - Automatic session restoration on page reload
 * - Unified authentication interface for different user types
 * 
 * Security Considerations:
 * - User tokens stored in httpOnly cookies (customer) or localStorage (employee)
 * - Non-sensitive user data persisted in localStorage
 * - Proper cleanup on logout for both authentication methods
 */

import React, { createContext, useState, useContext, useEffect, useMemo, useCallback } from 'react';
import { auth, db } from '../config/firebase';
import { signInWithEmailAndPassword } from 'firebase/auth';
import { collection, query, where, getDocs } from 'firebase/firestore';

/**
 * Authentication Context
 * 
 * Provides authentication state and methods to all child components.
 * Initial value is null and should only be accessed via useAuth hook.
 */
const AuthContext = createContext(null);

/**
 * AuthProvider Component
 * 
 * Root-level provider component that wraps the application to provide
 * authentication state and methods throughout the component tree.
 * 
 * @param {Object} props - Component props
 * @param {React.ReactNode} props.children - Child components to be wrapped
 * @returns {JSX.Element} Context provider with authentication state
 */
export const AuthProvider = ({ children }) => {
  // Current authenticated user object containing user details and role
  const [user, setUser] = useState(null);
  
  // Loading state to prevent premature rendering during session restoration
  const [loading, setLoading] = useState(true);

  /**
   * Effect: Session Restoration
   * 
   * Runs once on component mount to restore user session from localStorage.
   * This enables persistent login across page refreshes without requiring
   * re-authentication.
   * 
   * Security Note: Only non-sensitive user data is stored in localStorage.
   * Authentication tokens for customers are managed via httpOnly cookies,
   * while employee tokens are stored in localStorage for Firebase API calls.
   */
  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (error) {
        console.error('Failed to parse stored user data:', error);
        // Clear corrupted data
        localStorage.removeItem('user');
      }
    }
    
    // Mark loading as complete, allowing protected routes to render
    setLoading(false);
  }, []);

  /**
   * Customer Login Handler
   * 
   * Handles authentication for customer users. This method is called after
   * successful backend authentication and stores the user data locally.
   * 
   * Security Implementation:
   * - Authentication token is stored in httpOnly cookie (set by backend)
   * - Only user metadata is stored in localStorage
   * - Legacy token storage maintained for backward compatibility
   * 
   * @param {Object} userData - User information from backend authentication
   * @param {string} userData.customerId - Unique customer identifier
   * @param {string} userData.email - Customer email address
   * @param {string} userData.name - Customer full name
   * @param {string} userData.userType - Type of user ('customer')
   * @param {string} token - JWT authentication token (deprecated storage)
   */
  const login = useCallback((userData, token) => {
    setUser(userData);
    
    // Store non-sensitive user information for session persistence
    localStorage.setItem('user', JSON.stringify(userData));
    
    // DEPRECATED: Token storage maintained for backward compatibility
    // In production, remove this as token is in httpOnly cookie
    localStorage.setItem('token', token);
  }, []);

  /**
   * Employee Login Handler
   * 
   * Handles authentication for employee users using Firebase Authentication.
   * This method performs a two-step authentication process:
   * 1. Authenticate credentials with Firebase Auth
   * 2. Fetch employee details from Firestore database
   * 
   * Firebase Auth provides:
   * - Secure password hashing
   * - Rate limiting and brute force protection
   * - Token refresh mechanism
   * - Built-in session management
   * 
   * @param {string} email - Employee email address
   * @param {string} password - Employee password (plain text, hashed by Firebase)
   * @returns {Promise<Object>} Authentication result object
   * @returns {boolean} result.success - Whether authentication succeeded
   * @returns {string} result.message - Human-readable status message
   */
  const employeeLogin = useCallback(async (email, password) => {
    try {
      console.log('Attempting Firebase Auth with email:', email);

      // Step 1: Authenticate with Firebase Auth
      // This validates credentials and returns user credentials object
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      
      // Retrieve ID token for API authentication
      // This token is used for backend API calls and expires after 1 hour
      const idToken = await firebaseUser.getIdToken();

      console.log('Firebase Auth successful, UID:', firebaseUser.uid);

      // Step 2: Fetch employee profile from Firestore
      // Firebase Auth only provides authentication, not profile data
      const employeesRef = collection(db, 'employees');
      const q = query(employeesRef, where('uid', '==', firebaseUser.uid));
      const querySnapshot = await getDocs(q);
      
      // Validate that employee record exists in database
      if (querySnapshot.empty) {
        // Security: Sign out if no employee record found
        // This prevents authenticated but unauthorized access
        await auth.signOut();
        return {
          success: false,
          message: 'Employee record not found. Please contact administrator.'
        };
      }

      // Extract employee data from Firestore document
      const employeeDoc = querySnapshot.docs[0];
      const employeeData = employeeDoc.data();

      console.log('Found employee data:', employeeData);

      // Construct user object with combined Firebase and Firestore data
      const employeeUserData = {
        uid: firebaseUser.uid,                    // Firebase unique identifier
        employeeId: employeeData.employeeId,      // Business-specific employee ID
        email: employeeData.email,                // Employee email
        name: employeeData.name,                  // Full name
        role: employeeData.role,                  // Role/position (e.g., 'admin', 'support')
        userType: 'employee',                     // User type discriminator
        username: employeeData.employeeId         // Username for display purposes
      };

      // Update application state with authenticated user
      setUser(employeeUserData);
      
      // Persist user data and token for session management
      localStorage.setItem('user', JSON.stringify(employeeUserData));
      
      // Store Firebase ID token for API authentication
      // Note: Unlike customer tokens, employee tokens are stored in localStorage
      // because Firebase SDK requires client-side token management
      localStorage.setItem('token', idToken);

      console.log('Employee login successful:', employeeUserData);

      return {
        success: true,
        message: 'Login successful'
      };

    } catch (error) {
      console.error('Employee login error:', error);
      
      // Translate Firebase error codes to user-friendly messages
      // This improves UX by providing actionable feedback
      return {
        success: false,
        message: error.code === 'auth/wrong-password' || 
                 error.code === 'auth/user-not-found' || 
                 error.code === 'auth/invalid-credential'
          ? 'Invalid email or password'
          : error.code === 'auth/too-many-requests'
          ? 'Too many failed attempts. Please try again later.'
          : 'An error occurred during login. Please try again.'
      };
    }
  }, []);

  /**
   * Logout Handler
   * 
   * Securely logs out the user by:
   * 1. Clearing httpOnly cookie on backend (for customers)
   * 2. Signing out from Firebase (for employees)
   * 3. Clearing local storage and application state
   * 
   * This ensures complete session cleanup across all authentication methods.
   * 
   * Security Implementation:
   * - Server-side cookie clearing prevents token reuse
   * - credentials: 'include' ensures cookies are sent with request
   * - Local storage cleared to remove all client-side traces
   * - Firebase signOut invalidates the user session
   */
  const logout = useCallback(async () => {
    try {
      // Clear server-side httpOnly cookie for customer users
      // This is critical for security as it invalidates the session token
      await fetch('http://localhost:5000/api/logout', {
        method: 'POST',
        credentials: 'include', // CRITICAL: Include cookies in request
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      // Sign out from Firebase if user is an employee
      // This invalidates the Firebase session and tokens
      if (user?.userType === 'employee') {
        await auth.signOut();
      }
    } catch (error) {
      // Log error but continue with local cleanup
      // Network failures shouldn't prevent client-side logout
      console.error('Logout error:', error);
    }
    
    // Clear all local authentication state
    setUser(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  }, [user]);

  /**
   * Context Value Memoization
   * 
   * Memoizes the context value to prevent unnecessary re-renders of
   * consuming components. The value is only recomputed when dependencies change.
   * 
   * Dependencies:
   * - user: Current authenticated user state
   * - login: Customer login callback
   * - logout: Logout callback
   * - employeeLogin: Employee login callback
   * - loading: Initial loading state
   * 
   * Exposed Properties:
   * - user: Current user object or null
   * - token: Legacy token access (deprecated)
   * - login: Customer authentication function
   * - logout: Logout function for all user types
   * - employeeLogin: Employee authentication function
   * - isAuthenticated: Boolean indicating if user is logged in
   * - loading: Boolean indicating if session is being restored
   */
  const value = useMemo(() => ({
    user,
    token: localStorage.getItem('token'), // Backward compatibility
    login,
    logout,
    employeeLogin,
    isAuthenticated: !!user, // Convenient boolean check
    loading
  }), [user, login, logout, employeeLogin, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * useAuth Hook
 * 
 * Custom hook to access authentication context in any component.
 * This hook should be used instead of directly accessing the context.
 * 
 * Usage:
 * ```javascript
 * const { user, login, logout, isAuthenticated } = useAuth();
 * ```
 * 
 * @returns {Object} Authentication context value
 * @throws {Error} If used outside of AuthProvider
 * 
 * Why throw an error?
 * - Provides clear debugging information if hook is misused
 * - Fails fast rather than returning undefined
 * - Standard pattern for React context hooks
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
};