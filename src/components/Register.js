import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { validators, sanitizeInput } from '../utils/validation';
import { registerCustomer } from '../services/api';
import './Register.css';

/**
 * Register Component
 * 
 * Customer registration interface for the International Payments Portal.
 * This component provides a comprehensive registration form with real-time validation,
 * password strength assessment, and secure user account creation.
 * 
 * Features:
 * - Multi-field registration form (name, ID, account number, password)
 * - Real-time password strength meter with visual feedback
 * - Client-side input validation and sanitization
 * - Password confirmation matching
 * - Password visibility toggle for improved UX
 * - Field-level error feedback
 * - Loading states to prevent duplicate submissions
 * - Automatic navigation to login after successful registration
 * - South African ID number validation (13-digit format)
 * 
 * Security Features:
 * - Input sanitization to prevent XSS attacks
 * - Password complexity requirements (uppercase, lowercase, numbers, special characters)
 * - Secure password storage (confirmPassword excluded from API payload)
 * 
 * @returns {JSX.Element} The customer registration form component
 */
const Register = () => {
  // Navigation hook for programmatic routing after successful registration
  const navigate = useNavigate();
  
  // State management for all registration form fields
  const [formData, setFormData] = useState({
    fullName: '',          // User's complete legal name
    idNumber: '',          // South African ID number (13 digits)
    accountNumber: '',     // Bank account number (8-12 digits)
    password: '',          // Secure password with complexity requirements
    confirmPassword: ''    // Password verification field
  });

  // State for storing validation errors indexed by field name
  const [errors, setErrors] = useState({});
  
  // Loading state to manage async registration and prevent duplicate submissions
  const [loading, setLoading] = useState(false);
  
  // Toggle state for password visibility feature
  const [showPassword, setShowPassword] = useState(false);
  
  // State for password strength assessment with score, label, and improvement feedback
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,        // Numeric score from 0-5 based on complexity criteria
    label: '',       // Human-readable strength label (Weak/Medium/Strong)
    feedback: []     // Array of suggestions for improving password strength
  });

  /**
   * Handles input changes for all form fields
   * Implements input sanitization to prevent XSS attacks and provides immediate
   * feedback by clearing errors. Triggers password strength assessment when
   * password field is modified.
   * 
   * @param {Event} e - The input change event
   */
  const handleChange = (e) => {
    const { name, value } = e.target;
    
    // Sanitize input using centralized utility function
    // Removes potentially harmful characters to prevent injection attacks
    const sanitizedValue = sanitizeInput(value);

    // Update form state with sanitized value
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Clear field-specific error when user begins typing
    // Provides immediate visual feedback for error correction
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }

    // Trigger password strength assessment for real-time feedback
    // Only executes when password field is being modified
    if (name === 'password') {
      updatePasswordStrength(sanitizedValue);
    }
  };

  /**
   * Validates a single form field based on its name and value
   * Uses centralized validation utilities to ensure consistent business rules.
   * This function enables both individual field validation and full form validation.
   * 
   * @param {string} name - The field name to validate
   * @param {string} value - The field value to validate
   * @returns {string} Error message if validation fails, empty string if valid
   */
  const validateField = (name, value) => {
    let error = '';
    
    // Switch statement for field-specific validation rules
    switch (name) {
      case 'fullName':
        // Validates name format (letters, spaces, hyphens only)
        error = validators.fullName(value);
        break;
      case 'idNumber':
        // Validates South African ID number format (13 digits with checksum)
        error = validators.idNumber(value);
        break;
      case 'accountNumber':
        // Validates account number format and length (8-12 digits)
        error = validators.accountNumber(value);
        break;
      case 'password':
        // Validates password complexity requirements
        error = validators.password(value);
        break;
      case 'confirmPassword':
        // Validates that confirmation matches original password
        error = validators.confirmPassword(value, formData.password);
        break;
      default:
        break;
    }
    return error;
  };

  /**
   * Validates all form fields before submission
   * Iterates through all form data fields and collects validation errors.
   * Provides comprehensive validation to ensure data integrity before API call.
   * 
   * @returns {boolean} True if all validations pass, false otherwise
   */
  const validateForm = () => {
    const newErrors = {};
    
    // Iterate through all form fields and validate each one
    Object.keys(formData).forEach(field => {
      const error = validateField(field, formData[field]);
      if (error) newErrors[field] = error;
    });
    
    // Update errors state with all validation results
    setErrors(newErrors);
    
    // Return true only if no validation errors exist
    return Object.keys(newErrors).length === 0;
  };

  /**
   * Handles form submission and registration workflow
   * Orchestrates the registration process including validation, API call,
   * success notification, and navigation. Excludes confirmPassword from
   * API payload as it's only needed for client-side verification.
   * 
   * @param {Event} e - The form submit event
   */
  const handleSubmit = async (e) => {
    // Prevent default form submission behavior (page reload)
    e.preventDefault();
    
    // Validate all form fields before proceeding
    if (!validateForm()) return; // Exit early if validation fails

    // Set loading state to disable form and provide visual feedback
    setLoading(true);

    try {
      // Destructure to exclude confirmPassword from registration data
      // confirmPassword is only used for client-side validation
      const { confirmPassword, ...registrationData } = formData;
      
      // Submit registration data to API
      await registerCustomer(registrationData);
      
      // Display success message to user
      alert('Registration successful! Please login with your credentials.');
      
      // Navigate to login page after successful registration
      navigate('/login');
    } catch (error) {
      // Log error for debugging purposes
      console.error('Registration error:', error);
      
      // Extract error message from various possible error structures
      // Provides fallback to ensure user always receives feedback
      const errorMessage = error.error || error.message || 'Registration failed. Please try again.';
      alert(errorMessage);
    } finally {
      // Always reset loading state regardless of success or failure
      setLoading(false);
    }
  };

  /**
   * Password Strength Meter Logic
   * 
   * Calculates password strength based on multiple security criteria and provides
   * actionable feedback to help users create strong passwords. This real-time
   * assessment improves security by encouraging better password choices.
   * 
   * Scoring Criteria (each worth 1 point, max 5):
   * - Length: At least 8 characters
   * - Uppercase: Contains at least one uppercase letter (A-Z)
   * - Lowercase: Contains at least one lowercase letter (a-z)
   * - Numeric: Contains at least one digit (0-9)
   * - Special: Contains at least one special character (@$!%*?&#)
   * 
   * Strength Levels:
   * - Weak (0-2 points): Red indicator, significant improvements needed
   * - Medium (3 points): Yellow indicator, acceptable but could be stronger
   * - Strong (4-5 points): Green indicator, meets all security requirements
   * 
   * @param {string} password - The password to assess
   */
  const updatePasswordStrength = (password) => {
    let score = 0;
    const feedback = [];

    // Check minimum length requirement (8 characters)
    // Longer passwords are exponentially harder to crack
    if (password.length >= 8) score++;
    else feedback.push('Password should be at least 8 characters.');

    // Check for uppercase letters
    // Mixed case increases password complexity
    if (/[A-Z]/.test(password)) score++;
    else feedback.push('Include at least one uppercase letter.');

    // Check for lowercase letters
    // Required for case-sensitive authentication
    if (/[a-z]/.test(password)) score++;
    else feedback.push('Include at least one lowercase letter.');

    // Check for numeric characters
    // Numbers significantly increase password space
    if (/\d/.test(password)) score++;
    else feedback.push('Include at least one number.');

    // Check for special characters
    // Special characters further increase complexity and resist dictionary attacks
    if (/[@$!%*?&#]/.test(password)) score++;
    else feedback.push('Include at least one special character.');

    // Determine strength label based on score
    let label = '';
    if (score <= 2) label = 'Weak';        // Critical security concerns
    else if (score === 3) label = 'Medium'; // Acceptable but improvable
    else label = 'Strong';                  // Meets all security criteria

    // Update password strength state with calculated values
    setPasswordStrength({ score, label, feedback });
  };

  /**
   * Determines the color for the password strength bar
   * Provides visual feedback that reinforces the strength assessment.
   * Uses industry-standard color coding for security indicators.
   * 
   * @returns {string} Hex color code for the strength bar
   */
  const getStrengthBarColor = () => {
    if (passwordStrength.score <= 2) return '#e74c3c';  // Red for weak passwords
    if (passwordStrength.score === 3) return '#f1c40f';  // Yellow for medium passwords
    return '#2ecc71';                                     // Green for strong passwords
  };

  return (
    <div className="register-container">
      <div className="register-card">
        {/* Main heading */}
        <h2>Register for International Payments</h2>
        
        {/* Subtitle providing context */}
        <p className="subtitle">Create your secure account</p>

        {/* Main registration form */}
        <form onSubmit={handleSubmit} className="register-form">
          {/* Full Name input field */}
          <div className="form-group">
            <label htmlFor="fullName">Full Name *</label>
            <input
              type="text"
              id="fullName" // Explicit ID for label association (accessibility)
              name="fullName"
              value={formData.fullName} // Controlled component pattern
              onChange={handleChange}
              className={errors.fullName ? 'error' : ''} // Conditional error styling
              placeholder="Enter your full name"
              disabled={loading} // Prevent input during submission
            />
            {/* Display field-specific error message if validation fails */}
            {errors.fullName && <span className="error-message">{errors.fullName}</span>}
          </div>

          {/* ID Number input field */}
          {/* South African ID numbers are 13 digits containing birth date and citizenship info */}
          <div className="form-group">
            <label htmlFor="idNumber">ID Number *</label>
            <input
              type="text"
              id="idNumber"
              name="idNumber"
              value={formData.idNumber} // Controlled component
              onChange={handleChange}
              className={errors.idNumber ? 'error' : ''} // Error styling
              placeholder="13-digit ID number"
              maxLength="13" // Enforce South African ID number length
              disabled={loading} // Disable during submission
            />
            {/* Display ID validation error if present */}
            {errors.idNumber && <span className="error-message">{errors.idNumber}</span>}
          </div>

          {/* Account Number input field */}
          <div className="form-group">
            <label htmlFor="accountNumber">Account Number *</label>
            <input
              type="text"
              id="accountNumber"
              name="accountNumber"
              value={formData.accountNumber} // Controlled component
              onChange={handleChange}
              className={errors.accountNumber ? 'error' : ''} // Error styling
              placeholder="8-12 digit account number"
              maxLength="12" // Enforce maximum account number length
              disabled={loading} // Disable during submission
            />
            {/* Display account validation error if present */}
            {errors.accountNumber && <span className="error-message">{errors.accountNumber}</span>}
          </div>

          {/* Password input field with strength meter */}
          <div className="form-group">
            <label htmlFor="password">Password *</label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'} // Dynamic type based on visibility state
                id="password"
                name="password"
                value={formData.password} // Controlled component
                onChange={handleChange} // Triggers strength assessment
                className={errors.password ? 'error' : ''} // Error styling
                placeholder="Create a strong password"
                disabled={loading} // Disable during submission
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
            {/* Informational hint about password requirements */}
            <small className="password-hint">
              Must contain: 8+ characters, uppercase, lowercase, number, and special character
            </small>

            {/* Password Strength Meter */}
            {/* Provides real-time visual feedback on password security */}
            <div className="password-strength-container">
              {/* Strength bar background (gray track) */}
              <div className="strength-bar-background">
                {/* Strength bar fill (colored based on score) */}
                {/* Width percentage calculated from score (0-5 scale) */}
                <div
                  className="strength-bar-fill"
                  style={{
                    width: `${(passwordStrength.score / 5) * 100}%`,
                    backgroundColor: getStrengthBarColor()
                  }}
                ></div>
              </div>
              {/* Strength information section */}
              <div className="strength-info">
                {/* Strength label (Weak/Medium/Strong) with color coding */}
                <span className="strength-label" style={{ color: getStrengthBarColor() }}>
                  {passwordStrength.label}
                </span>
                {/* Feedback list with specific improvement suggestions */}
                <ul className="strength-feedback">
                  {passwordStrength.feedback.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Confirm Password input field */}
          {/* Prevents typos in password entry by requiring verification */}
          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password *</label>
            <input
              type={showPassword ? 'text' : 'password'} // Matches password field visibility
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword} // Controlled component
              onChange={handleChange}
              className={errors.confirmPassword ? 'error' : ''} // Error styling
              placeholder="Re-enter your password"
              disabled={loading} // Disable during submission
            />
            {/* Display confirmation validation error if passwords don't match */}
            {errors.confirmPassword && <span className="error-message">{errors.confirmPassword}</span>}
          </div>

          {/* Submit button with dynamic states */}
          <button type="submit" className="submit-btn" disabled={loading}>
            {/* Dynamic button text provides feedback about current operation */}
            {loading ? 'Registering...' : 'Register'}
          </button>
        </form>

        {/* Navigation link to login page */}
        {/* Provides path for existing users to access login */}
        <div className="switch-form">
          <p>
            Already have an account? <Link to="/login" className="link-btn">Login here</Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;