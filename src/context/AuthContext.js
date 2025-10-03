import React, { createContext, useState, useContext, useEffect, useMemo, useCallback } from 'react';
import { auth, db } from '../config/firebase';
import { signInWithEmailAndPassword } from 'firebase/auth';
import { collection, query, where, getDocs } from 'firebase/firestore';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // SECURITY FIX: Only store non-sensitive user data in localStorage
    // Tokens are now in httpOnly cookies (managed by backend)
    const storedUser = localStorage.getItem('user');
    
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  // Customer login (uses backend API with httpOnly cookies)
  const login = useCallback((userData, token) => {
    setUser(userData);
    // SECURITY: Only store user info, NOT the token
    // Token is in httpOnly cookie (set by server)
    localStorage.setItem('user', JSON.stringify(userData));
    
    // DEPRECATED: Keep for backward compatibility but token is in cookie
    localStorage.setItem('token', token);
  }, []);

  // Employee login (uses Firebase Auth)
  const employeeLogin = useCallback(async (email, password) => {
    try {
      console.log('Attempting Firebase Auth with email:', email);

      // Authenticate with Firebase using email and password
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      const idToken = await firebaseUser.getIdToken();

      console.log('Firebase Auth successful, UID:', firebaseUser.uid);

      // Fetch employee data from Firestore
      const employeesRef = collection(db, 'employees');
      const q = query(employeesRef, where('uid', '==', firebaseUser.uid));
      const querySnapshot = await getDocs(q);
      
      if (querySnapshot.empty) {
        await auth.signOut();
        return {
          success: false,
          message: 'Employee record not found. Please contact administrator.'
        };
      }

      const employeeDoc = querySnapshot.docs[0];
      const employeeData = employeeDoc.data();

      console.log('Found employee data:', employeeData);

      const employeeUserData = {
        uid: firebaseUser.uid,
        employeeId: employeeData.employeeId,
        email: employeeData.email,
        name: employeeData.name,
        role: employeeData.role,
        userType: 'employee',
        username: employeeData.employeeId
      };

      setUser(employeeUserData);
      
      // SECURITY: Store user data (non-sensitive)
      localStorage.setItem('user', JSON.stringify(employeeUserData));
      // SECURITY: Token for employees (Firebase) - needed for API calls
      localStorage.setItem('token', idToken);

      console.log('Employee login successful:', employeeUserData);

      return {
        success: true,
        message: 'Login successful'
      };

    } catch (error) {
      console.error('Employee login error:', error);
      
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

  // SECURITY: Enhanced logout with httpOnly cookie clearing
  const logout = useCallback(async () => {
    try {
      // Clear httpOnly cookie on server
      await fetch('http://localhost:5000/api/logout', {
        method: 'POST',
        credentials: 'include', // CRITICAL: Send cookies with request
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      // Sign out from Firebase if employee
      if (user?.userType === 'employee') {
        await auth.signOut();
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
    
    // Clear local state and storage
    setUser(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  }, [user]);

  const value = useMemo(() => ({
    user,
    token: localStorage.getItem('token'), // For compatibility
    login,
    logout,
    employeeLogin,
    isAuthenticated: !!user,
    loading
  }), [user, login, logout, employeeLogin, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};