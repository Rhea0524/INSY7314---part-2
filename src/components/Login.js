import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { validators, sanitizeInput } from '../utils/validation';
import { loginCustomer } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './Login.css';

/**
 * Login Component
 * 
 * Customer authentication interface for the International Payments Portal.
 * This component handles secure customer login using account number and password,
 * implementing comprehensive validation, sanitization, and security features.
 * 
 * Features:
 * - Account number validation using centralized validators
 * - Input sanitization to prevent injection attacks
 * - Password visibility toggle for improved UX
 * - Rate limiting detection and user notification
 * - Real-time error feedback and field-level validation
 * - Secure password handling with autocomplete attributes
 * - Loading states to prevent multiple submissions
 * - SSL security notice for user confidence
 * 
 * @returns {JSX.Element} The customer login form component
 */
const Login = () => {
  // Extract login function from authentication context for session management
  const { login } = useAuth();
  
  // Navigation hook for programmatic routing post-authentication
  const navigate = useNavigate();
  
  // State management for form data (account number and password)
  const [formData, setFormData] = useState({
    accountNumber: '',
    password: ''
  });

  // State for storing validation errors indexed by field name
  const [errors, setErrors] = useState({});
  
  // Loading state to manage async operations and prevent duplicate submissions
  const [loading, setLoading] = useState(false);
  
  // Toggle state for password visibility feature
  const [showPassword, setShowPassword] = useState(false);

  /**
   * Handles input changes for all form fields
   * Implements input sanitization using a centralized utility function to
   * ensure consistent security across the application. Provides immediate
   * feedback by clearing errors when user corrects invalid input.
   * 
   * @param {Event} e - The input change event
   */
  const handleChange = (e) => {
    const { name, value } = e.target;
    
    // Sanitize input using centralized utility function
    // This ensures consistent XSS prevention across the application
    const sanitizedValue = sanitizeInput(value);
    
    // Update form state with sanitized value using functional update pattern
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Clear field-specific error when user begins typing
    // Provides immediate feedback that improves user experience
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  /**
   * Validates form data before submission
   * Uses centralized validation utilities to ensure consistent business rules
   * across the application. Performs client-side validation to provide
   * immediate feedback and reduce unnecessary server requests.
   * 
   * @returns {boolean} True if all validations pass, false otherwise
   */
  const validateForm = () => {
    const newErrors = {};
    
    // Validate account number using centralized validator
    // This ensures consistent account number format across all components
    const accountError = validators.accountNumber(formData.accountNumber);
    if (accountError) {
      newErrors.accountNumber = accountError;
    }

    // Validate password presence
    // Note: Detailed password validation (length, complexity) should be
    // handled server-side to prevent client-side bypass
    if (!formData.password) {
      newErrors.password = 'Password is required';
    }

    // Update errors state with validation results
    setErrors(newErrors);
    
    // Return true only if no validation errors exist
    return Object.keys(newErrors).length === 0;
  };

  /**
   * Handles form submission and authentication workflow
   * Orchestrates the login process including validation, API communication,
   * session establishment, error handling, and post-login navigation.
   * Implements rate limiting detection to protect against brute force attacks.
   * 
   * @param {Event} e - The form submit event
   */
  const handleSubmit = async (e) => {
    // Prevent default form submission behavior (page reload)
    e.preventDefault();
    
    // Validate form data before proceeding with API call
    if (!validateForm()) {
      return; // Exit early if validation fails
    }

    // Set loading state to disable form and provide visual feedback
    setLoading(true);

    try {
      // Attempt authentication via API service
      // Response should contain user data and authentication token
      const response = await loginCustomer(formData);
      
      // Store authentication token and user data in context
      // This establishes the user session across the application
      login(response.user, response.token);
      
      // Notify user of successful authentication
      alert('Login successful!');
      
      // Navigate to customer dashboard after successful authentication
      // This provides access to payment functionality and account information
      navigate('/dashboard');
      
    } catch (error) {
      // Log error for debugging purposes
      // In production, this should use a proper logging service
      console.error('Login error:', error);
      
      // Extract error message from various possible error structures
      // Provides fallback to ensure user always receives feedback
      const errorMessage = error.error || error.message || 'Login failed. Please check your credentials.';
      
      // Check for rate limiting response from server
      // Alerts user to wait before retry to prevent account lockout
      if (errorMessage.includes('Too many')) {
        alert('Too many login attempts. Please try again in 15 minutes.');
      } else {
        // Display generic or specific error message to user
        alert(errorMessage);
      }
    } finally {
      // Always reset loading state regardless of success or failure
      // Ensures form remains usable for retry attempts
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        {/* Main application heading */}
        <h2>International Payments Portal</h2>
        
        {/* Subtitle providing context for the form */}
        <p className="subtitle">Login to your account</p>

        {/* Main authentication form */}
        <form onSubmit={handleSubmit} className="login-form">
          {/* Account Number input field group */}
          <div className="form-group">
            <label htmlFor="accountNumber">Account Number *</label>
            <input
              type="text" // Text type allows for alphanumeric account numbers
              id="accountNumber" // Explicit ID for label association (accessibility)
              name="accountNumber" // Name for form data identification
              value={formData.accountNumber} // Controlled component pattern
              onChange={handleChange} // Handle input changes with sanitization
              className={errors.accountNumber ? 'error' : ''} // Conditional error styling
              placeholder="Enter your account number" // User guidance
              maxLength="12" // Enforce maximum length to prevent abuse
              disabled={loading} // Prevent input during authentication
              autoComplete="username" // Browser autocomplete hint for account number
            />
            {/* Display field-specific error message if validation fails */}
            {errors.accountNumber && <span className="error-message">{errors.accountNumber}</span>}
          </div>

          {/* Password input field group with visibility toggle */}
          <div className="form-group">
            <label htmlFor="password">Password *</label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'} // Dynamic type based on visibility state
                id="password" // Label association
                name="password"
                value={formData.password} // Controlled component
                onChange={handleChange}
                className={errors.password ? 'error' : ''} // Error styling
                placeholder="Enter your password"
                disabled={loading} // Disable during authentication
                autoComplete="current-password" // Browser autocomplete hint for security
              />
              {/* Password visibility toggle button */}
              {/* Improves UX by allowing users to verify their input */}
              <button
                type="button" // Prevent form submission on click
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)} // Toggle visibility state
                tabIndex="-1" // Exclude from tab order for better keyboard navigation
              >
                {/* Dynamic emoji based on password visibility state */}
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
            {/* Display password validation error if present */}
            {errors.password && <span className="error-message">{errors.password}</span>}
          </div>

          {/* Submit button with dynamic states */}
          <button 
            type="submit" 
            className="submit-btn"
            disabled={loading} // Prevent multiple submissions during authentication
          >
            {/* Dynamic button text provides feedback about current operation */}
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        {/* Security notice to build user trust and confidence */}
        {/* Indicates that communication is encrypted using SSL/TLS */}
        <div className="security-notice">
          <p>🔒 Your connection is secure with SSL encryption</p>
        </div>

        {/* Navigation link to registration page */}
        {/* Provides path for new users to create accounts */}
        <div className="switch-form">
          <p>Don't have an account? <Link to="/register" className="link-btn">Register here</Link></p>
        </div>
      </div>
    </div>
  );
};

export default Login;