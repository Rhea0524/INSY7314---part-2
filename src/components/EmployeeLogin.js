import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './EmployeeLogin.css';

const EmployeeLogin = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');
  
  const { employeeLogin } = useAuth();
  const navigate = useNavigate();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    // Input sanitization - remove potentially harmful characters
    const sanitizedValue = value.replace(/[<>\"'&]/g, '');
    
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));
    
    // Clear field-specific error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email || !emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }
    
    if (!formData.password || formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    
    if (!validateForm()) {
      return;
    }
    
    setIsLoading(true);
    
    try {
      const result = await employeeLogin(formData.email, formData.password);
      
      if (result.success) {
        setMessage('Login successful! Redirecting to dashboard...');
        setTimeout(() => {
          navigate('/employee/dashboard');
        }, 1500);
      } else {
        setMessage(result.message || 'Login failed. Please check your credentials.');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
      console.error('Employee login error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="employee-login-container">
      <div className="card">
        <div className="secure-badge">
          Secure Employee Portal
        </div>
        
        <h2 className="card-title">Employee Login</h2>
        
        {message && (
          <div className={`alert ${message.includes('successful') ? 'alert-success' : 'alert-error'}`}>
            {message}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="employee-login-form">
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="emp001@bank.com"
              required
              className={errors.email ? 'error' : ''}
              disabled={isLoading}
            />
            {errors.email && (
              <span className="error-text">{errors.email}</span>
            )}
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              placeholder="Enter your secure password"
              maxLength={128}
              required
              className={errors.password ? 'error' : ''}
              disabled={isLoading}
            />
            {errors.password && (
              <span className="error-text">{errors.password}</span>
            )}
          </div>
          
          <button 
            type="submit" 
            className={`btn btn-primary ${isLoading ? 'loading' : ''}`}
            disabled={isLoading}
          >
            {isLoading ? 'Authenticating...' : 'Login to Dashboard'}
          </button>
        </form>
        
        <div className="nav-links">
          <Link to="/login">Customer Portal</Link>
        </div>
      </div>
    </div>
  );
};

export default EmployeeLogin;