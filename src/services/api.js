import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests if it exists
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Customer APIs
export const registerCustomer = async (userData) => {
  try {
    const response = await api.post('/register', userData);
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Registration failed' };
  }
};

export const loginCustomer = async (credentials) => {
  try {
    const loginData = {
      username: credentials.accountNumber,
      accountNumber: credentials.accountNumber,
      password: credentials.password
    };
    
    const response = await api.post('/login', loginData);
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
    const mappedData = {
      amount: parseFloat(paymentData.amount),
      currency: paymentData.currency,
      provider: 'SWIFT',
      payeeAccount: paymentData.recipientAccount,
      swiftCode: paymentData.swiftCode,
      description: paymentData.description
    };
    
    const response = await api.post('/payment', mappedData);
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

// FIXED: Match the function names used in TransactionDashboard
export const verifyTransaction = async (transactionId, employeeId) => {
  try {
    const response = await api.put(`/employee/transactions/${transactionId}/verify`);
    return response;
  } catch (error) {
    throw error.response?.data || { error: 'Verification failed' };
  }
};

// FIXED: Changed endpoint to match backend
export const submitToSWIFT = async (transactionId, employeeId) => {
  try {
    const response = await api.post(`/employee/transactions/${transactionId}/swift`);
    return response;
  } catch (error) {
    throw error.response?.data || { error: 'SWIFT submission failed' };
  }
};

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

// Add named exports that TransactionDashboard expects
api.verifyTransaction = verifyTransaction;
api.submitToSWIFT = submitToSWIFT;

// Add methods that TransactionDashboard expects
api.verifyTransaction = async (transactionId, employeeId) => {
  return api.put(`/employee/transactions/${transactionId}/verify`);
};

api.submitToSWIFT = async (transactionId, employeeId) => {
  return api.post(`/employee/transactions/${transactionId}/swift`);
};



export default api;