import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import PaymentForm from './PaymentForm';
import { getCustomerTransactions } from '../services/api';
import './CustomerDashboard.css';

const CustomerDashboard = () => {
  const { user } = useAuth();
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('payment');

  const fetchTransactions = async () => {
  try {
    setLoading(true);
    console.log('Fetching transactions...');
    console.log('Token:', localStorage.getItem('token'));
    console.log('User:', user);
    
    const data = await getCustomerTransactions();
    console.log('Transactions received:', data);
    
    setTransactions(data);
    setError('');
  } catch (err) {
    console.error('Error fetching transactions:', err);
    console.error('Error response:', err.response);
    setError('Failed to load transactions');
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
    if (activeTab === 'history') {
      fetchTransactions();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const handlePaymentSuccess = () => {
    fetchTransactions();
    setActiveTab('history');
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending':
        return '#ffa500';
      case 'verified':
        return '#2196f3';
      case 'completed':
        return '#4caf50';
      case 'failed':
        return '#f44336';
      default:
        return '#6c757d';
    }
  };

  return (
    <div className="customer-dashboard">
      <div className="dashboard-header-info">
        <h2>Welcome, {user?.fullName}</h2>
        <p className="account-info">Account Number: {user?.accountNumber}</p>
      </div>

      <nav className="dashboard-tabs">
        <button 
          className={`tab-btn ${activeTab === 'payment' ? 'active' : ''}`}
          onClick={() => setActiveTab('payment')}
        >
          💸 Make Payment
        </button>
        <button 
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          📋 Transaction History
        </button>
      </nav>

      <div className="dashboard-main-content">
        {activeTab === 'payment' && (
          <PaymentForm onPaymentSuccess={handlePaymentSuccess} />
        )}

        {activeTab === 'history' && (
          <div className="transactions-section">
            <h3>My Transactions</h3>
            
            {error && <div className="error-message">{error}</div>}
            
            {loading ? (
              <div className="loading-message">
                <div className="spinner"></div>
                <p>Loading transactions...</p>
              </div>
            ) : transactions.length === 0 ? (
              <div className="no-transactions">
                <p>No transactions yet</p>
                <button 
                  onClick={() => setActiveTab('payment')} 
                  className="make-payment-btn"
                >
                  Make your first payment
                </button>
              </div>
            ) : (
              <div className="transactions-list">
                {transactions.map((transaction) => (
                  <div key={transaction.id} className="transaction-card">
                    <div className="transaction-header">
                      <span className="transaction-id">Transaction #{transaction.id}</span>
                      <span 
                        className="transaction-status"
                        style={{ backgroundColor: getStatusColor(transaction.status) }}
                      >
                        {transaction.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="transaction-details">
                      <div className="detail-row">
                        <span className="detail-label">Amount:</span>
                        <span className="detail-value amount-value">
                          {transaction.currency} {parseFloat(transaction.amount).toFixed(2)}
                        </span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Recipient Account:</span>
                        <span className="detail-value">{transaction.recipientAccount}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">SWIFT Code:</span>
                        <span className="detail-value">{transaction.swiftCode}</span>
                      </div>
                      {transaction.description && (
                        <div className="detail-row">
                          <span className="detail-label">Description:</span>
                          <span className="detail-value">{transaction.description}</span>
                        </div>
                      )}
                      <div className="detail-row">
                        <span className="detail-label">Date:</span>
                        <span className="detail-value">
                          {new Date(transaction.createdAt).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CustomerDashboard;