import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'https://localhost:5443/api';

// SECURITY: Create axios instance with enhanced security config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
  timeout: 30000,
});

// SECURITY: Request interceptor with token and error handling
api.interceptors.request.use(
  (config) => {
    // CRITICAL FIX: Always get fresh token from localStorage
    // This ensures we use the latest token (employee or customer)
    const token = localStorage.getItem('token');
    
    if (token) {
      console.log('📤 Sending request with token:', token.substring(0, 20) + '...');
      config.headers.Authorization = `Bearer ${token}`;
    } else {
      console.warn('⚠️ No token found in localStorage');
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
      console.warn('⚠️ Authentication failed - clearing session');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      if (window.location.pathname !== '/login' && window.location.pathname !== '/employee/login') {
        window.location.href = '/login';
      }
    }
    
    // Handle 403 Forbidden - insufficient permissions
    if (error.response?.status === 403) {
      console.error('🚫 Access forbidden:', error.response.data);
    }
    
    // Handle 429 Too Many Requests - rate limiting
    if (error.response?.status === 429) {
      console.error('⏱️ Rate limit exceeded');
      return Promise.reject({
        error: 'Too many requests. Please wait and try again.',
        retryAfter: error.response.headers['retry-after']
      });
    }

    return Promise.reject(error);
  }
);

// SECURITY: Enhanced input sanitization helper - XSS Protection
const sanitizeInput = (data) => {
  if (typeof data === 'string') {
    return data
      .replace(/<script\b[^<]{0,500}?<\/script>/gi, '')
      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
      .replace(/on\w+\s*=\s*[^\s>]*/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/data:text\/html/gi, '')
      .replace(/<[^>]*>/g, '')
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
    const sanitizedData = sanitizeInput(userData);
    const response = await api.post('/register', sanitizedData);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Registration failed' };
  }
};

export const loginCustomer = async (credentials) => {
  try {
    const loginData = {
      accountNumber: sanitizeInput(credentials.accountNumber),
      password: credentials.password
    };
    
    const response = await api.post('/login', loginData);
    
    if (response.data.token) {
      console.log('✅ Customer login successful, storing token');
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
    const sanitizedData = {
      amount: parseFloat(paymentData.amount),
      currency: sanitizeInput(paymentData.currency),
      provider: 'SWIFT',
      recipientAccount: sanitizeInput(paymentData.recipientAccount),
      swiftCode: sanitizeInput(paymentData.swiftCode),
      description: sanitizeInput(paymentData.description || '')
    };

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
export const getEmployeeTransactions = async () => {
  try {
    console.log('🔍 Fetching employee transactions...');
    const response = await api.get('/employee/transactions');
    console.log('✅ Transactions fetched successfully');
    return response.data;
  } catch (error) {
    console.error('❌ Failed to fetch transactions:', error.response?.data);
    throw error.response?.data || { error: 'Failed to fetch transactions' };
  }
};

// Transaction verification
export const verifyTransaction = async (transactionId) => {
  try {
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
    await api.post('/logout');
  } catch (error) {
    console.error('Logout API error:', error);
  } finally {
    // Always clear local storage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    console.log('✅ Logged out and cleared local storage');
  }
};

export default api;