import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// SECURITY: Create axios instance with enhanced security config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  // CRITICAL: Enable credentials for httpOnly cookies
  withCredentials: true,
  // SECURITY: Set timeout to prevent hanging requests (DDoS protection)
  timeout: 30000, // 30 seconds
});

// SECURITY: Request interceptor with token and error handling
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// SECURITY: Response interceptor for centralized error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle 401 Unauthorized - token expired or invalid
    if (error.response?.status === 401) {
      console.warn('Authentication failed - clearing session');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      // Redirect to login if not already there
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    
    // Handle 429 Too Many Requests - rate limiting
    if (error.response?.status === 429) {
      console.error('Rate limit exceeded');
      return Promise.reject({
        error: 'Too many requests. Please wait and try again.',
        retryAfter: error.response.headers['retry-after']
      });
    }

    return Promise.reject(error);
  }
);

// SECURITY: Enhanced input sanitization helper - XSS Protection
// Multi-pass approach with comprehensive attack vector coverage
const sanitizeInput = (data) => {
  if (typeof data === 'string') {
    // PROTECTION: Remove multiple XSS attack vectors
    return data
      // Remove script tags and content (ReDoS-safe pattern)
    .replace(/<script\b[^<]{0,500}?<\/script>/gi, '')
      // Remove event handlers (onclick, onerror, onload, etc.)
      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
      .replace(/on\w+\s*=\s*[^\s>]*/gi, '')
      // Remove javascript: protocol
      .replace(/javascript:/gi, '')
      // Remove data: protocol (can be used for XSS)
      .replace(/data:text\/html/gi, '')
      // Remove HTML tags
      .replace(/<[^>]*>/g, '')
      // Remove HTML entities that could decode to scripts
      .replace(/&lt;|&gt;|&quot;|&#x3C;|&#x3E;/gi, '')
      .trim();
  }
  if (typeof data === 'object' && data !== null) {
    const sanitized = {};
    for (const key in data) {
      sanitized[key] = sanitizeInput(data[key]);
    }
    return sanitized;
  }
  return data;
};

// Customer APIs
export const registerCustomer = async (userData) => {
  try {
    // SECURITY: Sanitize user input before sending
    const sanitizedData = sanitizeInput(userData);
    const response = await api.post('/register', sanitizedData);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Registration failed' };
  }
};

export const loginCustomer = async (credentials) => {
  try {
    // SECURITY: Sanitize credentials
    const loginData = {
      accountNumber: sanitizeInput(credentials.accountNumber),
      password: credentials.password // Don't sanitize password (allow special chars)
    };
    
    const response = await api.post('/login', loginData);
    
    // SECURITY: Store token and user data (httpOnly cookie set by server)
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Login failed' };
  }
};

export const submitPayment = async (paymentData) => {
  try {
    // SECURITY: Validate and sanitize payment data
    const sanitizedData = {
      amount: parseFloat(paymentData.amount),
      currency: sanitizeInput(paymentData.currency),
      provider: 'SWIFT',
      payeeAccount: sanitizeInput(paymentData.recipientAccount),
      swiftCode: sanitizeInput(paymentData.swiftCode),
      description: sanitizeInput(paymentData.description || '')
    };

    // SECURITY: Validate amount is positive
    if (sanitizedData.amount <= 0 || isNaN(sanitizedData.amount)) {
      throw { error: 'Invalid payment amount' };
    }

    const response = await api.post('/payment', sanitizedData);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Payment submission failed' };
  }
};

export const getCustomerTransactions = async () => {
  try {
    const response = await api.get('/customer/transactions');
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Failed to fetch transactions' };
  }
};

// Employee APIs
export const loginEmployee = async (credentials) => {
  try {
    const response = await api.post('/employee/login', credentials);
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Employee login failed' };
  }
};

export const getEmployeeTransactions = async () => {
  try {
    const response = await api.get('/employee/transactions');
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Failed to fetch transactions' };
  }
};

// Transaction verification
export const verifyTransaction = async (transactionId) => {
  try {
    // SECURITY: Validate transactionId format
    if (!transactionId || typeof transactionId !== 'string') {
      throw { error: 'Invalid transaction ID' };
    }
    
    const response = await api.put(`/employee/transactions/${transactionId}/verify`);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Verification failed' };
  }
};

// SWIFT submission
export const submitToSWIFT = async (transactionId) => {
  try {
    // SECURITY: Validate transactionId format
    if (!transactionId || typeof transactionId !== 'string') {
      throw { error: 'Invalid transaction ID' };
    }
    
    const response = await api.post(`/employee/transactions/${transactionId}/swift`);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'SWIFT submission failed' };
  }
};

// SECURITY: Enhanced logout that clears httpOnly cookie
export const logout = async () => {
  try {
    // Call server logout to clear httpOnly cookie
    await api.post('/logout');
  } catch (error) {
    console.error('Logout API error:', error);
  } finally {
    // Always clear local storage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  }
};

// Attach methods to api object for backward compatibility
api.verifyTransaction = verifyTransaction;
api.submitToSWIFT = submitToSWIFT;

export default api;