import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import './TransactionDashboard.css';

const TransactionDashboard = () => {
  const [transactions, setTransactions] = useState([]);
  const [filteredTransactions, setFilteredTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [verificationStatus, setVerificationStatus] = useState({});
  const [message, setMessage] = useState('');
  
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const hasCheckedAuth = useRef(false);

  useEffect(() => {
    // Prevent multiple authentication checks
    if (hasCheckedAuth.current) return;
    
    if (!user) {
      console.log('No user found, redirecting to login');
      hasCheckedAuth.current = true;
      navigate('/employee/login', { replace: true });
      return;
    }
    
    console.log('Checking user role. Current role:', user.role);
    console.log('User role type:', typeof user.role);
    
    // Normalize the role for comparison
    const normalizedRole = user.role?.toString().toLowerCase().trim();
    console.log('Normalized role:', normalizedRole);
    
    // Accept both 'employee' and 'staff' roles
    if (normalizedRole !== 'employee' && normalizedRole !== 'staff') {
      console.log('User is not an employee/staff. Role is:', user.role);
      console.log('Redirecting to employee login...');
      hasCheckedAuth.current = true;
      navigate('/employee/login', { replace: true });
      return;
    }
    
    hasCheckedAuth.current = true;
    console.log('User authenticated as employee, fetching transactions');
    fetchTransactions();
  }, [user, navigate]);

  useEffect(() => {
    filterTransactionsByStatus();
  }, [transactions, filterStatus]);

  const fetchTransactions = async () => {
    try {
      setLoading(true);
      console.log('Fetching transactions for user:', user);
      
      const response = await api.get('/employee/transactions');
      console.log('API response:', response);
      const data = response.data;
      setTransactions(Array.isArray(data) ? data : []);
      setError('');
    } catch (err) {
      console.error('Error fetching transactions:', err);
      console.error('Error response:', err.response);
      
      // More specific error messages
      if (err.response?.status === 403) {
        setError('Access denied. Please check your credentials and try logging in again.');
      } else if (err.response?.status === 401) {
        setError('Session expired. Please log in again.');
        setTimeout(() => {
          logout();
          navigate('/employee/login');
        }, 2000);
      } else {
        setError(`Failed to fetch transactions: ${err.response?.data?.message || err.message}`);
      }
      setTransactions([]);
    } finally {
      setLoading(false);
    }
  };

  const filterTransactionsByStatus = () => {
    if (filterStatus === 'all') {
      setFilteredTransactions(transactions);
    } else {
      setFilteredTransactions(
        transactions.filter(transaction => transaction.status === filterStatus)
      );
    }
  };

  const handleVerifyTransaction = async (transactionId) => {
    try {
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'verifying' }));
      
      const response = await api.put(`/employee/transactions/${transactionId}/verify`);
      
      if (response.data.success) {
        setMessage(`Transaction ${transactionId} verified successfully!`);
        setVerificationStatus(prev => ({ ...prev, [transactionId]: 'verified' }));
        
        setTransactions(prev => 
          prev.map(transaction => 
            transaction.id === transactionId 
              ? { ...transaction, status: 'verified', verifiedBy: user.username }
              : transaction
          )
        );
        
        setTimeout(() => setMessage(''), 3000);
      } else {
        throw new Error(response.data.message || 'Verification failed');
      }
    } catch (err) {
      console.error('Verification error:', err);
      setError(`Failed to verify transaction: ${err.response?.data?.message || err.message}`);
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'error' }));
      setTimeout(() => setError(''), 5000);
    }
  };

  const handleSubmitToSWIFT = async (transactionId) => {
    try {
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'submitting' }));
      
      const response = await api.post(`/employee/transactions/${transactionId}/swift`);
      
      if (response.data.success) {
        setMessage(`Transaction ${transactionId} submitted to SWIFT successfully!`);
        setVerificationStatus(prev => ({ ...prev, [transactionId]: 'completed' }));
        
        setTransactions(prev => 
          prev.map(transaction => 
            transaction.id === transactionId 
              ? { ...transaction, status: 'completed', swiftReference: response.data.swiftReference }
              : transaction
          )
        );
        
        setTimeout(() => setMessage(''), 3000);
      } else {
        throw new Error(response.data.message || 'SWIFT submission failed');
      }
    } catch (err) {
      console.error('SWIFT submission error:', err);
      setError(`Failed to submit to SWIFT: ${err.response?.data?.message || err.message}`);
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'error' }));
      setTimeout(() => setError(''), 5000);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/employee/login');
  };

  const formatCurrency = (amount, currency) => {
    return new Intl.NumberFormat('en-ZA', {
      style: 'currency',
      currency: currency || 'ZAR'
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-ZA');
  };

  const getStatusBadge = (status) => {
    const statusClasses = {
      pending: 'status-badge status-pending',
      verified: 'status-badge status-verified',
      completed: 'status-badge status-completed',
      failed: 'status-badge status-failed'
    };
    
    return (
      <span className={statusClasses[status] || 'status-badge'}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading transactions...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="header-content">
          <h1>Transaction Dashboard</h1>
          <div className="employee-info">
            <span>Welcome, {user?.name || user?.username || 'Employee'}</span>
            <button onClick={handleLogout} className="btn btn-logout">
              Logout
            </button>
          </div>
        </div>
      </div>

      {message && (
        <div className="alert alert-success">
          {message}
        </div>
      )}

      {error && (
        <div className="alert alert-error">
          {error}
        </div>
      )}

      <div className="dashboard-content">
        <div className="filters-section">
          <h3>Filter Transactions</h3>
          <div className="filter-buttons">
            <button 
              className={filterStatus === 'all' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('all')}
            >
              All ({transactions.length})
            </button>
            <button 
              className={filterStatus === 'pending' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('pending')}
            >
              Pending ({transactions.filter(t => t.status === 'pending').length})
            </button>
            <button 
              className={filterStatus === 'verified' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('verified')}
            >
              Verified ({transactions.filter(t => t.status === 'verified').length})
            </button>
            <button 
              className={filterStatus === 'completed' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('completed')}
            >
              Completed ({transactions.filter(t => t.status === 'completed').length})
            </button>
          </div>
        </div>

        <div className="transactions-section">
          <h3>Transactions</h3>
          
          {filteredTransactions.length === 0 ? (
            <div className="no-transactions">
              <p>No transactions found for the selected filter.</p>
            </div>
          ) : (
            <div className="transactions-grid">
              {filteredTransactions.map((transaction) => (
                <div key={transaction.id} className="transaction-card">
                  <div className="transaction-header">
                    <span className="transaction-id">#{transaction.id}</span>
                    {getStatusBadge(transaction.status)}
                  </div>
                  
                  <div className="transaction-details">
                    <div className="detail-row">
                      <strong>From:</strong> {transaction.customerName}
                    </div>
                    <div className="detail-row">
                      <strong>To:</strong> {transaction.recipientName}
                    </div>
                    <div className="detail-row">
                      <strong>Amount:</strong> {formatCurrency(transaction.amount, transaction.currency)}
                    </div>
                    <div className="detail-row">
                      <strong>SWIFT Code:</strong> {transaction.swiftCode}
                    </div>
                    <div className="detail-row">
                      <strong>Account:</strong> {transaction.recipientAccount}
                    </div>
                    <div className="detail-row">
                      <strong>Date:</strong> {formatDate(transaction.createdAt)}
                    </div>
                    {transaction.swiftReference && (
                      <div className="detail-row">
                        <strong>SWIFT Ref:</strong> {transaction.swiftReference}
                      </div>
                    )}
                  </div>
                  
                  <div className="transaction-actions">
                    {transaction.status === 'pending' && (
                      <button
                        className="btn btn-success"
                        onClick={() => handleVerifyTransaction(transaction.id)}
                        disabled={verificationStatus[transaction.id] === 'verifying'}
                      >
                        {verificationStatus[transaction.id] === 'verifying' ? 'Verifying...' : 'Verify'}
                      </button>
                    )}
                    
                    {transaction.status === 'verified' && (
                      <button
                        className="btn btn-primary"
                        onClick={() => handleSubmitToSWIFT(transaction.id)}
                        disabled={verificationStatus[transaction.id] === 'submitting'}
                      >
                        {verificationStatus[transaction.id] === 'submitting' ? 'Submitting...' : 'Submit to SWIFT'}
                      </button>
                    )}
                    
                    {transaction.status === 'completed' && (
                      <span className="completed-text">✓ Completed</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TransactionDashboard;