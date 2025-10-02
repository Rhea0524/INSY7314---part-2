import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { validators, sanitizeInput } from '../utils/validation';
import { registerCustomer } from '../services/api';
import './Register.css';

const Register = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    fullName: '',
    idNumber: '',
    accountNumber: '',
    password: '',
    confirmPassword: ''
  });

  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    label: '',
    feedback: []
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    const sanitizedValue = sanitizeInput(value);

    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }

    if (name === 'password') {
      updatePasswordStrength(sanitizedValue);
    }
  };

  const validateField = (name, value) => {
    let error = '';
    switch (name) {
      case 'fullName':
        error = validators.fullName(value);
        break;
      case 'idNumber':
        error = validators.idNumber(value);
        break;
      case 'accountNumber':
        error = validators.accountNumber(value);
        break;
      case 'password':
        error = validators.password(value);
        break;
      case 'confirmPassword':
        error = validators.confirmPassword(value, formData.password);
        break;
      default:
        break;
    }
    return error;
  };

  const validateForm = () => {
    const newErrors = {};
    Object.keys(formData).forEach(field => {
      const error = validateField(field, formData[field]);
      if (error) newErrors[field] = error;
    });
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);

    try {
      const { confirmPassword, ...registrationData } = formData;
      await registerCustomer(registrationData);
      alert('Registration successful! Please login with your credentials.');
      navigate('/login');
    } catch (error) {
      console.error('Registration error:', error);
      const errorMessage = error.error || error.message || 'Registration failed. Please try again.';
      alert(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  /** 🔥 Password Strength Meter Logic */
  const updatePasswordStrength = (password) => {
    let score = 0;
    const feedback = [];

    if (password.length >= 8) score++;
    else feedback.push('Password should be at least 8 characters.');

    if (/[A-Z]/.test(password)) score++;
    else feedback.push('Include at least one uppercase letter.');

    if (/[a-z]/.test(password)) score++;
    else feedback.push('Include at least one lowercase letter.');

    if (/\d/.test(password)) score++;
    else feedback.push('Include at least one number.');

    if (/[@$!%*?&#]/.test(password)) score++;
    else feedback.push('Include at least one special character.');

    let label = '';
    if (score <= 2) label = 'Weak';
    else if (score === 3) label = 'Medium';
    else label = 'Strong';

    setPasswordStrength({ score, label, feedback });
  };

  const getStrengthBarColor = () => {
    if (passwordStrength.score <= 2) return '#e74c3c';
    if (passwordStrength.score === 3) return '#f1c40f';
    return '#2ecc71';
  };

  return (
    <div className="register-container">
      <div className="register-card">
        <h2>Register for International Payments</h2>
        <p className="subtitle">Create your secure account</p>

        <form onSubmit={handleSubmit} className="register-form">
          {/* Full Name */}
          <div className="form-group">
            <label htmlFor="fullName">Full Name *</label>
            <input
              type="text"
              id="fullName"
              name="fullName"
              value={formData.fullName}
              onChange={handleChange}
              className={errors.fullName ? 'error' : ''}
              placeholder="Enter your full name"
              disabled={loading}
            />
            {errors.fullName && <span className="error-message">{errors.fullName}</span>}
          </div>

          {/* ID Number */}
          <div className="form-group">
            <label htmlFor="idNumber">ID Number *</label>
            <input
              type="text"
              id="idNumber"
              name="idNumber"
              value={formData.idNumber}
              onChange={handleChange}
              className={errors.idNumber ? 'error' : ''}
              placeholder="13-digit ID number"
              maxLength="13"
              disabled={loading}
            />
            {errors.idNumber && <span className="error-message">{errors.idNumber}</span>}
          </div>

          {/* Account Number */}
          <div className="form-group">
            <label htmlFor="accountNumber">Account Number *</label>
            <input
              type="text"
              id="accountNumber"
              name="accountNumber"
              value={formData.accountNumber}
              onChange={handleChange}
              className={errors.accountNumber ? 'error' : ''}
              placeholder="8-12 digit account number"
              maxLength="12"
              disabled={loading}
            />
            {errors.accountNumber && <span className="error-message">{errors.accountNumber}</span>}
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="password">Password *</label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className={errors.password ? 'error' : ''}
                placeholder="Create a strong password"
                disabled={loading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex="-1"
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
            {errors.password && <span className="error-message">{errors.password}</span>}
            <small className="password-hint">
              Must contain: 8+ characters, uppercase, lowercase, number, and special character
            </small>

            {/* 🔥 Password Strength Meter */}
            <div className="password-strength-container">
              <div className="strength-bar-background">
                <div
                  className="strength-bar-fill"
                  style={{
                    width: `${(passwordStrength.score / 5) * 100}%`,
                    backgroundColor: getStrengthBarColor()
                  }}
                ></div>
              </div>
              <div className="strength-info">
                <span className="strength-label" style={{ color: getStrengthBarColor() }}>
                  {passwordStrength.label}
                </span>
                <ul className="strength-feedback">
                  {passwordStrength.feedback.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password *</label>
            <input
              type={showPassword ? 'text' : 'password'}
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              className={errors.confirmPassword ? 'error' : ''}
              placeholder="Re-enter your password"
              disabled={loading}
            />
            {errors.confirmPassword && <span className="error-message">{errors.confirmPassword}</span>}
          </div>

          <button type="submit" className="submit-btn" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
        </form>

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
