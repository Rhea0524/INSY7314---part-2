import React, { createContext, useState, useContext, useEffect, useMemo, useCallback } from 'react';
import { auth, db } from '../config/firebase';
import { signInWithEmailAndPassword } from 'firebase/auth';
import { collection, query, where, getDocs } from 'firebase/firestore';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is logged in on mount
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('token');
    
    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
      setToken(storedToken);
    }
    setLoading(false);
  }, []); // Only run once on mount

  // Wrap login in useCallback
  const login = useCallback((userData, authToken) => {
    setUser(userData);
    setToken(authToken);
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('token', authToken);
  }, []);

  // Wrap logout in useCallback
  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  }, []);

  // FIXED: Now accepts email and password (instead of employeeId)
  const employeeLogin = useCallback(async (email, password) => {
    try {
      console.log('Attempting Firebase Auth with email:', email);

      // Authenticate with Firebase using email and password
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      const idToken = await firebaseUser.getIdToken();

      console.log('Firebase Auth successful, UID:', firebaseUser.uid);

      // Now fetch employee data from Firestore using the authenticated user's UID
      const employeesRef = collection(db, 'employees');
      const q = query(employeesRef, where('uid', '==', firebaseUser.uid));
      const querySnapshot = await getDocs(q);
      
      if (querySnapshot.empty) {
        // User authenticated but no employee record found
        await auth.signOut();
        return {
          success: false,
          message: 'Employee record not found. Please contact administrator.'
        };
      }

      // Get the employee data
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
        username: employeeData.employeeId // Add this for backend compatibility
      };

      setUser(employeeUserData);
      setToken(idToken);
      localStorage.setItem('user', JSON.stringify(employeeUserData));
      localStorage.setItem('token', idToken);

      console.log('Employee login successful:', employeeUserData);

      return {
        success: true,
        message: 'Login successful'
      };

    } catch (error) {
      console.error('Employee login error:', error);
      console.error('Error code:', error.code);
      console.error('Error message:', error.message);
      
      return {
        success: false,
        message: error.code === 'auth/wrong-password' || error.code === 'auth/user-not-found' || error.code === 'auth/invalid-credential'
          ? 'Invalid email or password'
          : error.code === 'auth/too-many-requests'
          ? 'Too many failed attempts. Please try again later.'
          : 'An error occurred during login. Please try again.'
      };
    }
  }, []);

  // Setup inactivity timer separately
  useEffect(() => {
    if (!token) return;

    let inactivityTimer;
    const resetTimer = () => {
      clearTimeout(inactivityTimer);
      inactivityTimer = setTimeout(() => {
        logout();
        alert('Session expired due to inactivity');
      }, 60 * 60 * 1000); // 1 hour
    };

    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keypress', resetTimer);
    resetTimer();

    return () => {
      clearTimeout(inactivityTimer);
      window.removeEventListener('mousemove', resetTimer);
      window.removeEventListener('keypress', resetTimer);
    };
  }, [token, logout]);

  const value = useMemo(() => ({
    user,
    token,
    login,
    logout,
    employeeLogin,
    isAuthenticated: !!token,
    loading
  }), [user, token, login, logout, employeeLogin, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};