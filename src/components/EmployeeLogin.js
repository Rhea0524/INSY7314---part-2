import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './EmployeeLogin.css';

/**
 * EmployeeLogin Component
 * 
 * A secure authentication interface for bank employees to access the internal portal.
 * This component implements form validation, input sanitization, and error handling
 * to ensure secure access to the employee dashboard.
 * 
 * Features:
 * - Client-side input validation and sanitization
 * - Real-time error feedback for form fields
 * - Loading states during authentication
 * - Success/error messaging
 * - Automatic redirection upon successful login
 * - Navigation to customer portal
 * 
 * @returns {JSX.Element} The employee login form component
 */
const EmployeeLogin = () => {
  // State management for form inputs (email and password)
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  
  // State for storing validation errors keyed by field name
  const [errors, setErrors] = useState({});
  
  // Loading state to prevent multiple submissions and provide user feedback
  const [isLoading, setIsLoading] = useState(false);
  
  // General message state for displaying success or error notifications
  const [message, setMessage] = useState('');
  
  // Extract employeeLogin function from authentication context
  const { employeeLogin } = useAuth();
  
  // Navigation hook for programmatic routing after successful authentication
  const navigate = useNavigate();

  /**
   * Handles input changes across all form fields
   * Implements input sanitization to prevent XSS attacks by removing potentially
   * harmful characters before updating state. Also clears field-specific errors
   * when user begins typing to provide immediate feedback.
   * 
   * @param {Event} e - The input change event
   */
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    // Sanitize input by removing characters that could be used in XSS attacks
    // Removes: < > " ' & to prevent script injection and HTML manipulation
    const sanitizedValue = value.replace(/[<>\"'&]/g, '');
    
    // Update form data with sanitized value using functional update pattern
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));
    
    // Clear any existing error for this field to improve UX
    // This provides immediate feedback when user corrects an invalid input
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  /**
   * Validates form data before submission
   * Performs client-side validation to ensure data integrity and provide
   * immediate feedback to users before making server requests.
   * 
   * Validation rules:
   * - Email: Must match standard email format (user@domain.extension)
   * - Password: Minimum 6 characters (basic security requirement)
   * 
   * @returns {boolean} True if all validations pass, false otherwise
   */
  const validateForm = () => {
    const newErrors = {};
    
    // Email validation using regex pattern
    // Pattern breakdown: [^\s@]+ (one or more non-whitespace, non-@ chars)
    //                   @ (literal @ symbol)
    //                   [^\s@]+ (domain name)
    //                   \. (literal dot)
    //                   [^\s@]+ (TLD)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email || !emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }
    
    // Password validation - enforce minimum length requirement
    // Note: Server-side validation should implement more robust password policies
    if (!formData.password || formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }
    
    // Update errors state with any validation failures
    setErrors(newErrors);
    
    // Return true only if no errors were found
    return Object.keys(newErrors).length === 0;
  };

  /**
   * Handles form submission and authentication process
   * Orchestrates the login workflow including validation, API call,
   * error handling, and navigation upon success.
   * 
   * @param {Event} e - The form submit event
   */
  const handleSubmit = async (e) => {
    // Prevent default form submission behavior (page reload)
    e.preventDefault();
    
    // Clear any previous messages
    setMessage('');
    
    // Validate form data before attempting login
    if (!validateForm()) {
      return; // Exit early if validation fails
    }
    
    // Set loading state to disable form and show loading indicator
    setIsLoading(true);
    
    try {
      // Attempt authentication through context API
      // This abstracts the actual API call and session management
      const result = await employeeLogin(formData.email, formData.password);
      
      if (result.success) {
        // Display success message to user
        setMessage('Login successful! Redirecting to dashboard...');
        
        // Delayed navigation to allow user to see success message
        // 1.5 second delay provides good UX without feeling sluggish
        setTimeout(() => {
          navigate('/employee/dashboard');
        }, 1500);
      } else {
        // Display error message from authentication service
        // Fallback to generic message if none provided
        setMessage(result.message || 'Login failed. Please check your credentials.');
      }
    } catch (error) {
      // Handle network errors or unexpected exceptions
      // Generic message prevents leaking system information
      setMessage('Network error. Please try again.');
      
      // Log error for debugging purposes (should use proper logging in production)
      console.error('Employee login error:', error);
    } finally {
      // Always reset loading state regardless of success or failure
      // This ensures the form is re-enabled for retry attempts
      setIsLoading(false);
    }
  };

  return (
    <div className="employee-login-container">
      <div className="card">
        {/* Security indicator badge to reinforce trust and security */}
        <div className="secure-badge">
          Secure Employee Portal
        </div>
        
        {/* Main heading for the login interface */}
        <h2 className="card-title">Employee Login</h2>
        
        {/* Conditional rendering of alert messages */}
        {/* Dynamic styling based on message content (success vs error) */}
        {message && (
          <div className={`alert ${message.includes('successful') ? 'alert-success' : 'alert-error'}`}>
            {message}
          </div>
        )}
        
        {/* Main login form */}
        <form onSubmit={handleSubmit} className="employee-login-form">
          {/* Email input field group */}
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email" // HTML5 email type provides basic browser validation
              id="email" // Explicit ID for label association (accessibility)
              name="email" // Name attribute for form data identification
              value={formData.email} // Controlled component pattern
              onChange={handleInputChange} // Handle all input changes
              placeholder="emp001@bank.com" // Example format for user guidance
              required // HTML5 required attribute for basic validation
              className={errors.email ? 'error' : ''} // Conditional error styling
              disabled={isLoading} // Prevent input during submission
            />
            {/* Display field-specific error message if validation fails */}
            {errors.email && (
              <span className="error-text">{errors.email}</span>
            )}
          </div>
          
          {/* Password input field group */}
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password" // Masks input for security
              id="password" // Label association
              name="password"
              value={formData.password} // Controlled component
              onChange={handleInputChange}
              placeholder="Enter your secure password"
              maxLength={128} // Reasonable upper limit to prevent abuse
              required // Basic browser validation
              className={errors.password ? 'error' : ''} // Error styling
              disabled={isLoading} // Disable during authentication
            />
            {/* Display password validation error if present */}
            {errors.password && (
              <span className="error-text">{errors.password}</span>
            )}
          </div>
          
          {/* Submit button with dynamic states */}
          <button 
            type="submit" 
            className={`btn btn-primary ${isLoading ? 'loading' : ''}`}
            disabled={isLoading} // Prevent multiple submissions
          >
            {/* Dynamic button text based on loading state */}
            {isLoading ? 'Authenticating...' : 'Login to Dashboard'}
          </button>
        </form>
        
        {/* Navigation link to customer portal */}
        {/* Allows employees to switch to customer login if needed */}
        <div className="nav-links">
          <Link to="/login">Customer Portal</Link>
        </div>
      </div>
    </div>
  );
};

export default EmployeeLogin;