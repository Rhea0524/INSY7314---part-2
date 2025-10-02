import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { validators, sanitizeInput } from '../utils/validation';
import { loginCustomer } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './Login.css';

const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    accountNumber: '',
    password: ''
  });

  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    const sanitizedValue = sanitizeInput(value);
    
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Clear error for this field when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    const accountError = validators.accountNumber(formData.accountNumber);
    if (accountError) {
      newErrors.accountNumber = accountError;
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      const response = await loginCustomer(formData);
      
      // Store token and user data
      login(response.user, response.token);
      
      alert('Login successful!');
      
      // Navigate to payment page after successful login
      navigate('/dashboard');
      
    } catch (error) {
      console.error('Login error:', error);
      const errorMessage = error.error || error.message || 'Login failed. Please check your credentials.';
      
      if (errorMessage.includes('Too many')) {
        alert('Too many login attempts. Please try again in 15 minutes.');
      } else {
        alert(errorMessage);
      }
    } finally {
      setLoading(false);
    
  };
}

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>International Payments Portal</h2>
        <p className="subtitle">Login to your account</p>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="accountNumber">Account Number *</label>
            <input
              type="text"
              id="accountNumber"
              name="accountNumber"
              value={formData.accountNumber}
              onChange={handleChange}
              className={errors.accountNumber ? 'error' : ''}
              placeholder="Enter your account number"
              maxLength="13"
              disabled={loading}
              autoComplete="username"
            />
            {errors.accountNumber && <span className="error-message">{errors.accountNumber}</span>}
          </div>

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
                placeholder="Enter your password"
                disabled={loading}
                autoComplete="current-password"
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
          </div>

          <button 
            type="submit" 
            className="submit-btn"
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <div className="security-notice">
          <p>🔒 Your connection is secure with SSL encryption</p>
        </div>

        <div className="switch-form">
          <p>Don't have an account? <Link to="/register" className="link-btn">Register here</Link></p>
        </div>
      </div>
    </div>
  );
};

export default Login;