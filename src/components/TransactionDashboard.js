import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import './TransactionDashboard.css';

/**
 * TransactionDashboard Component
 * 
 * Employee dashboard for managing and processing international payment transactions.
 * This component provides a comprehensive interface for bank employees to view, verify,
 * and submit transactions to the SWIFT network for international fund transfers.
 * 
 * Features:
 * - Role-based access control (employee/staff only)
 * - Real-time transaction filtering by status
 * - Transaction verification workflow
 * - SWIFT network submission capability
 * - Transaction status tracking with visual indicators
 * - Currency formatting with internationalization
 * - Date/time formatting for transaction timestamps
 * - Error handling with user-friendly messages
 * - Session management with automatic logout
 * - Loading states for async operations
 * - Transaction count badges for each status
 * 
 * Transaction Workflow:
 * 1. Pending: Awaiting employee verification
 * 2. Verified: Approved by employee, ready for SWIFT submission
 * 3. Completed: Successfully submitted to SWIFT network
 * 4. Failed: Transaction processing failed
 * 
 * Security Features:
 * - Authentication verification on component mount
 * - Role-based authorization (employee/staff roles only)
 * - Session expiration handling with automatic logout
 * - Prevention of duplicate authentication checks
 * - Comprehensive error handling for unauthorized access
 * 
 * @returns {JSX.Element} The transaction dashboard component
 */
const TransactionDashboard = () => {
  // State management for transactions data
  const [transactions, setTransactions] = useState([]);
  
  // State for filtered subset of transactions based on status
  const [filteredTransactions, setFilteredTransactions] = useState([]);
  
  // Loading state for initial data fetch
  const [loading, setLoading] = useState(true);
  
  // Error message state for displaying failures
  const [error, setError] = useState('');
  
  // Current filter selection (all, pending, verified, completed)
  const [filterStatus, setFilterStatus] = useState('all');
  
  // Tracking verification/submission status for each transaction
  // Maps transaction ID to status (verifying, submitting, verified, completed, error)
  const [verificationStatus, setVerificationStatus] = useState({});
  
  // Success message state for displaying operation confirmations
  const [message, setMessage] = useState('');
  
  // Extract user data and logout function from authentication context
  const { user, logout } = useAuth();
  
  // Navigation hook for programmatic routing
  const navigate = useNavigate();
  
  // Ref to prevent duplicate authentication checks on re-renders
  // useRef persists across renders without triggering re-renders
  const hasCheckedAuth = useRef(false);

  /**
   * Authentication and Authorization Effect
   * 
   * Runs on component mount and when user/navigate dependencies change.
   * Implements comprehensive security checks to ensure only authorized
   * employees can access the dashboard. Uses ref to prevent duplicate
   * authentication checks that could cause navigation loops.
   * 
   * Security Checks:
   * 1. User existence verification
   * 2. Role validation (employee or staff)
   * 3. Normalized role comparison (case-insensitive)
   * 
   * Dependencies: [user, navigate]
   */
  useEffect(() => {
    // Prevent multiple authentication checks using ref guard
    // This avoids navigation loops and unnecessary API calls
    if (hasCheckedAuth.current) return;
    
    // Check if user is authenticated
    if (!user) {
      console.log('No user found, redirecting to login');
      hasCheckedAuth.current = true;
      // Replace history to prevent back button navigation to protected route
      navigate('/employee/login', { replace: true });
      return;
    }
    
    // Log role information for debugging authentication issues
    console.log('Checking user role. Current role:', user.role);
    console.log('User role type:', typeof user.role);
    
    // Normalize role for case-insensitive comparison
    // Handles variations like "Employee", "EMPLOYEE", " employee "
    const normalizedRole = user.role?.toString().toLowerCase().trim();
    console.log('Normalized role:', normalizedRole);
    
    // Accept both 'employee' and 'staff' roles for flexibility
    // This allows different role naming conventions across systems
    if (normalizedRole !== 'employee' && normalizedRole !== 'staff') {
      console.log('User is not an employee/staff. Role is:', user.role);
      console.log('Redirecting to employee login...');
      hasCheckedAuth.current = true;
      // Redirect unauthorized users back to login
      navigate('/employee/login', { replace: true });
      return;
    }
    
    // Mark authentication check as complete
    hasCheckedAuth.current = true;
    console.log('User authenticated as employee, fetching transactions');
    
    // Fetch transactions after successful authentication
    fetchTransactions();
  }, [user, navigate]);

  /**
   * Transaction Filtering Effect
   * 
   * Automatically updates filtered transactions whenever the full transaction
   * list or filter status changes. This ensures the UI stays synchronized
   * with both data updates and user filter selections.
   * 
   * Dependencies: [transactions, filterStatus]
   */
  useEffect(() => {
    filterTransactionsByStatus();
  }, [transactions, filterStatus]);

  /**
   * Fetches all transactions from the API
   * 
   * Retrieves transaction data for the authenticated employee from the backend.
   * Implements comprehensive error handling for various failure scenarios including
   * authentication failures, authorization errors, and network issues.
   * 
   * Error Handling:
   * - 403 Forbidden: Access denied, credentials issue
   * - 401 Unauthorized: Session expired, triggers automatic logout
   * - Other errors: Display specific error message from server
   * 
   * @async
   */
  const fetchTransactions = async () => {
    try {
      setLoading(true);
      console.log('Fetching transactions for user:', user);
      
      // Make API request to employee transactions endpoint
      const response = await api.get('/employee/transactions');
      console.log('API response:', response);
      
      const data = response.data;
      
      // Ensure data is always an array to prevent runtime errors
      // Handles edge case where API returns non-array response
      setTransactions(Array.isArray(data) ? data : []);
      
      // Clear any previous errors on successful fetch
      setError('');
    } catch (err) {
      // Log detailed error information for debugging
      console.error('Error fetching transactions:', err);
      console.error('Error response:', err.response);
      
      // Provide specific error messages based on HTTP status code
      if (err.response?.status === 403) {
        // Forbidden: User lacks necessary permissions
        setError('Access denied. Please check your credentials and try logging in again.');
      } else if (err.response?.status === 401) {
        // Unauthorized: Session has expired
        setError('Session expired. Please log in again.');
        
        // Automatic logout after brief delay to show message
        setTimeout(() => {
          logout();
          navigate('/employee/login');
        }, 2000);
      } else {
        // Generic error with server message or fallback
        setError(`Failed to fetch transactions: ${err.response?.data?.message || err.message}`);
      }
      
      // Reset transactions to empty array on error
      setTransactions([]);
    } finally {
      // Always reset loading state regardless of success or failure
      setLoading(false);
    }
  };

  /**
   * Filters transactions based on selected status
   * 
   * Updates the filteredTransactions state based on the current filter selection.
   * The 'all' filter shows all transactions, while other filters show only
   * transactions matching the specific status.
   */
  const filterTransactionsByStatus = () => {
    if (filterStatus === 'all') {
      // Show all transactions without filtering
      setFilteredTransactions(transactions);
    } else {
      // Filter transactions matching the selected status
      setFilteredTransactions(
        transactions.filter(transaction => transaction.status === filterStatus)
      );
    }
  };

  /**
   * Handles transaction verification process
   * 
   * Allows employees to verify pending transactions before SWIFT submission.
   * This is a critical step in the payment processing workflow that ensures
   * all transaction details are correct before international transfer.
   * 
   * Workflow:
   * 1. Set verification status to 'verifying'
   * 2. Make API call to verify endpoint
   * 3. Update transaction status to 'verified' on success
   * 4. Record which employee verified the transaction
   * 5. Display success message with auto-dismiss
   * 
   * @async
   * @param {string|number} transactionId - The ID of the transaction to verify
   */
  const handleVerifyTransaction = async (transactionId) => {
    try {
      // Update UI to show verification in progress
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'verifying' }));
      
      // Make API call to verify the transaction
      const response = await api.put(`/employee/transactions/${transactionId}/verify`);
      
      if (response.data.success) {
        // Display success message to user
        setMessage(`Transaction ${transactionId} verified successfully!`);
        
        // Update verification status in UI
        setVerificationStatus(prev => ({ ...prev, [transactionId]: 'verified' }));
        
        // Update transaction in state with new status and verifier info
        // Uses functional update to ensure we work with latest state
        setTransactions(prev => 
          prev.map(transaction => 
            transaction.id === transactionId 
              ? { ...transaction, status: 'verified', verifiedBy: user.username }
              : transaction
          )
        );
        
        // Auto-dismiss success message after 3 seconds
        setTimeout(() => setMessage(''), 3000);
      } else {
        // Handle unexpected success:false response from server
        throw new Error(response.data.message || 'Verification failed');
      }
    } catch (err) {
      // Log error for debugging
      console.error('Verification error:', err);
      
      // Display user-friendly error message
      setError(`Failed to verify transaction: ${err.response?.data?.message || err.message}`);
      
      // Update verification status to show error in UI
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'error' }));
      
      // Auto-dismiss error message after 5 seconds
      setTimeout(() => setError(''), 5000);
    }
  };

  /**
   * Handles SWIFT network submission
   * 
   * Submits verified transactions to the SWIFT network for international processing.
   * SWIFT (Society for Worldwide Interbank Financial Telecommunication) is the
   * international standard for cross-border payments. This function represents
   * the final step in the transaction workflow.
   * 
   * Workflow:
   * 1. Set submission status to 'submitting'
   * 2. Make API call to SWIFT submission endpoint
   * 3. Update transaction status to 'completed' on success
   * 4. Store SWIFT reference number for tracking
   * 5. Display success message with auto-dismiss
   * 
   * @async
   * @param {string|number} transactionId - The ID of the transaction to submit
   */
  const handleSubmitToSWIFT = async (transactionId) => {
    try {
      // Update UI to show submission in progress
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'submitting' }));
      
      // Make API call to SWIFT submission endpoint
      const response = await api.post(`/employee/transactions/${transactionId}/swift`);
      
      if (response.data.success) {
        // Display success message to user
        setMessage(`Transaction ${transactionId} submitted to SWIFT successfully!`);
        
        // Update submission status in UI
        setVerificationStatus(prev => ({ ...prev, [transactionId]: 'completed' }));
        
        // Update transaction with completed status and SWIFT reference
        // SWIFT reference allows tracking of international payment
        setTransactions(prev => 
          prev.map(transaction => 
            transaction.id === transactionId 
              ? { ...transaction, status: 'completed', swiftReference: response.data.swiftReference }
              : transaction
          )
        );
        
        // Auto-dismiss success message after 3 seconds
        setTimeout(() => setMessage(''), 3000);
      } else {
        // Handle unexpected success:false response from server
        throw new Error(response.data.message || 'SWIFT submission failed');
      }
    } catch (err) {
      // Log error for debugging
      console.error('SWIFT submission error:', err);
      
      // Display user-friendly error message
      setError(`Failed to submit to SWIFT: ${err.response?.data?.message || err.message}`);
      
      // Update submission status to show error in UI
      setVerificationStatus(prev => ({ ...prev, [transactionId]: 'error' }));
      
      // Auto-dismiss error message after 5 seconds
      setTimeout(() => setError(''), 5000);
    }
  };

  /**
   * Handles employee logout
   * 
   * Clears user session and redirects to employee login page.
   * This ensures secure session termination when employee finishes work.
   */
  const handleLogout = () => {
    // Clear authentication state
    logout();
    
    // Redirect to employee login page
    navigate('/employee/login');
  };

  /**
   * Formats currency amounts with proper localization
   * 
   * Uses Internationalization API to format currency values according to
   * South African locale conventions. Handles multiple currency types
   * for international transactions.
   * 
   * @param {number} amount - The numeric amount to format
   * @param {string} currency - The ISO currency code (e.g., 'ZAR', 'USD', 'EUR')
   * @returns {string} Formatted currency string (e.g., "R 1,234.56")
   */
  const formatCurrency = (amount, currency) => {
    return new Intl.NumberFormat('en-ZA', {
      style: 'currency',
      currency: currency || 'ZAR' // Default to South African Rand
    }).format(amount);
  };

  /**
   * Formats date and time strings for display
   * 
   * Converts ISO date strings to human-readable format using South African
   * locale conventions. Includes both date and time information.
   * 
   * @param {string} dateString - ISO date string from database
   * @returns {string} Formatted date/time string (e.g., "2024/10/03, 14:30:00")
   */
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-ZA');
  };

  /**
   * Generates status badge component with appropriate styling
   * 
   * Creates visually distinct badges for different transaction statuses.
   * Color coding helps employees quickly identify transaction states.
   * 
   * Status Colors:
   * - Pending: Yellow/warning color
   * - Verified: Blue/info color
   * - Completed: Green/success color
   * - Failed: Red/error color
   * 
   * @param {string} status - The transaction status
   * @returns {JSX.Element} Styled badge component
   */
  const getStatusBadge = (status) => {
    // Map status to corresponding CSS class
    const statusClasses = {
      pending: 'status-badge status-pending',
      verified: 'status-badge status-verified',
      completed: 'status-badge status-completed',
      failed: 'status-badge status-failed'
    };
    
    return (
      <span className={statusClasses[status] || 'status-badge'}>
        {/* Capitalize first letter of status text */}
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  // Loading state UI - displayed while fetching initial data
  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading-spinner">
          {/* Animated spinner for visual feedback */}
          <div className="spinner"></div>
          <p>Loading transactions...</p>
        </div>
      </div>
    );
  }

  // Main dashboard UI - rendered after successful data load
  return (
    <div className="dashboard-container">
      {/* Dashboard header with title and employee info */}
      <div className="dashboard-header">
        <div className="header-content">
          <h1>Transaction Dashboard</h1>
          
          {/* Employee information and logout button */}
          <div className="employee-info">
            {/* Display employee name with fallback to username */}
            <span>Welcome, {user?.name || user?.username || 'Employee'}</span>
            <button onClick={handleLogout} className="btn btn-logout">
              Logout
            </button>
          </div>
        </div>
      </div>

      {/* Success message alert - conditionally rendered */}
      {message && (
        <div className="alert alert-success">
          {message}
        </div>
      )}

      {/* Error message alert - conditionally rendered */}
      {error && (
        <div className="alert alert-error">
          {error}
        </div>
      )}

      {/* Main dashboard content area */}
      <div className="dashboard-content">
        {/* Filter section for transaction status filtering */}
        <div className="filters-section">
          <h3>Filter Transactions</h3>
          <div className="filter-buttons">
            {/* All transactions filter button with count badge */}
            <button 
              className={filterStatus === 'all' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('all')}
            >
              All ({transactions.length})
            </button>
            
            {/* Pending transactions filter button with count badge */}
            <button 
              className={filterStatus === 'pending' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('pending')}
            >
              Pending ({transactions.filter(t => t.status === 'pending').length})
            </button>
            
            {/* Verified transactions filter button with count badge */}
            <button 
              className={filterStatus === 'verified' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('verified')}
            >
              Verified ({transactions.filter(t => t.status === 'verified').length})
            </button>
            
            {/* Completed transactions filter button with count badge */}
            <button 
              className={filterStatus === 'completed' ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setFilterStatus('completed')}
            >
              Completed ({transactions.filter(t => t.status === 'completed').length})
            </button>
          </div>
        </div>

        {/* Transactions display section */}
        <div className="transactions-section">
          <h3>Transactions</h3>
          
          {/* Empty state - shown when no transactions match filter */}
          {filteredTransactions.length === 0 ? (
            <div className="no-transactions">
              <p>No transactions found for the selected filter.</p>
            </div>
          ) : (
            /* Transaction cards grid - displays all filtered transactions */
            <div className="transactions-grid">
              {filteredTransactions.map((transaction) => (
                /* Individual transaction card */
                <div key={transaction.id} className="transaction-card">
                  {/* Card header with transaction ID and status badge */}
                  <div className="transaction-header">
                    <span className="transaction-id">#{transaction.id}</span>
                    {getStatusBadge(transaction.status)}
                  </div>
                  
                  {/* Transaction details section */}
                  <div className="transaction-details">
                    {/* Customer name (sender) */}
                    <div className="detail-row">
                      <strong>From:</strong> {transaction.customerName}
                    </div>
                    
                    {/* Recipient name */}
                    <div className="detail-row">
                      <strong>To:</strong> {transaction.recipientName}
                    </div>
                    
                    {/* Transaction amount with currency formatting */}
                    <div className="detail-row">
                      <strong>Amount:</strong> {formatCurrency(transaction.amount, transaction.currency)}
                    </div>
                    
                    {/* SWIFT code for recipient's bank */}
                    <div className="detail-row">
                      <strong>SWIFT Code:</strong> {transaction.swiftCode}
                    </div>
                    
                    {/* Recipient account number */}
                    <div className="detail-row">
                      <strong>Account:</strong> {transaction.recipientAccount}
                    </div>
                    
                    {/* Transaction creation timestamp */}
                    <div className="detail-row">
                      <strong>Date:</strong> {formatDate(transaction.createdAt)}
                    </div>
                    
                    {/* SWIFT reference - conditionally rendered after submission */}
                    {transaction.swiftReference && (
                      <div className="detail-row">
                        <strong>SWIFT Ref:</strong> {transaction.swiftReference}
                      </div>
                    )}
                  </div>
                  
                  {/* Action buttons section - conditional based on transaction status */}
                  <div className="transaction-actions">
                    {/* Verify button - shown only for pending transactions */}
                    {transaction.status === 'pending' && (
                      <button
                        className="btn btn-success"
                        onClick={() => handleVerifyTransaction(transaction.id)}
                        disabled={verificationStatus[transaction.id] === 'verifying'}
                      >
                        {/* Dynamic button text based on verification status */}
                        {verificationStatus[transaction.id] === 'verifying' ? 'Verifying...' : 'Verify'}
                      </button>
                    )}
                    
                    {/* Submit to SWIFT button - shown only for verified transactions */}
                    {transaction.status === 'verified' && (
                      <button
                        className="btn btn-primary"
                        onClick={() => handleSubmitToSWIFT(transaction.id)}
                        disabled={verificationStatus[transaction.id] === 'submitting'}
                      >
                        {/* Dynamic button text based on submission status */}
                        {verificationStatus[transaction.id] === 'submitting' ? 'Submitting...' : 'Submit to SWIFT'}
                      </button>
                    )}
                    
                    {/* Completion indicator - shown for completed transactions */}
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