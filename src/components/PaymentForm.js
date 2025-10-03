import React, { useState } from 'react';
import { validators, sanitizeInput } from '../utils/validation';
import { submitPayment } from '../services/api';
import './PaymentForm.css';

/**
 * PaymentForm Component
 * 
 * A comprehensive form component for processing international payment transactions.
 * This component handles the collection, validation, and submission of payment details
 * including amount, currency, recipient information, and SWIFT codes for international
 * bank transfers.
 * 
 * Features:
 * - Multi-currency support (ZAR, USD, EUR, GBP, JPY, AUD, CAD)
 * - Real-time input validation and sanitization
 * - Automatic SWIFT code formatting (uppercase conversion)
 * - Payment confirmation dialog for user verification
 * - Character counting for description field
 * - Field-level error feedback
 * - Form reset after successful submission
 * - Parent component notification via callback
 * - Loading states to prevent duplicate submissions
 * 
 * @param {Object} props - Component properties
 * @param {Function} props.onPaymentSuccess - Optional callback executed after successful payment
 * @returns {JSX.Element} The payment form component
 */
const PaymentForm = ({ onPaymentSuccess }) => {
  // State management for all payment form fields
  const [formData, setFormData] = useState({
    amount: '',              // Transaction amount (numeric)
    currency: 'ZAR',         // Default to South African Rand
    recipientAccount: '',    // Recipient's account number
    swiftCode: '',          // Bank identifier for international transfers
    description: ''         // Optional payment reference or notes
  });

  // State for storing validation errors indexed by field name
  const [errors, setErrors] = useState({});
  
  // Loading state to manage async payment submission and prevent duplicate transactions
  const [loading, setLoading] = useState(false);

  // Array of supported currencies for international payments
  // Limited set ensures proper exchange rate handling on backend
  const currencies = ['ZAR', 'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD'];

  /**
   * Handles input changes for all form fields
   * Implements field-specific transformations (e.g., SWIFT code uppercasing)
   * and sanitizes all inputs to prevent injection attacks. Provides immediate
   * feedback by clearing errors as user corrects invalid input.
   * 
   * @param {Event} e - The input change event
   */
  const handleChange = (e) => {
    const { name, value } = e.target;
    
    // Sanitize input using centralized utility function
    // Removes potentially harmful characters to prevent XSS attacks
    let sanitizedValue = sanitizeInput(value);
    
    // Apply field-specific transformations
    // SWIFT codes are always uppercase per international banking standards (ISO 9362)
    if (name === 'swiftCode') {
      sanitizedValue = sanitizedValue.toUpperCase();
    }
    
    // Update form state with sanitized and transformed value
    setFormData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Clear field-specific error when user begins typing
    // Provides immediate visual feedback that improves user experience
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  /**
   * Validates all form fields before submission
   * Uses centralized validation utilities to ensure consistent business rules
   * across the application. Each field is validated according to specific
   * requirements for international payment processing.
   * 
   * Validation includes:
   * - Amount: Must be numeric, positive, and within acceptable limits
   * - Currency: Must be from supported currency list
   * - Account Number: Must match expected format and length
   * - SWIFT Code: Must conform to ISO 9362 standard (8 or 11 characters)
   * - Description: Optional but must not exceed character limit if provided
   * 
   * @returns {boolean} True if all validations pass, false otherwise
   */
  const validateForm = () => {
    const newErrors = {};
    
    // Validate payment amount
    // Ensures amount is numeric, positive, and within transaction limits
    const amountError = validators.amount(formData.amount);
    if (amountError) {
      newErrors.amount = amountError;
    }

    // Validate currency selection
    // Ensures only supported currencies are accepted
    const currencyError = validators.currency(formData.currency);
    if (currencyError) {
      newErrors.currency = currencyError;
    }

    // Validate recipient account number
    // Ensures account number conforms to expected format
    const accountError = validators.accountNumber(formData.recipientAccount);
    if (accountError) {
      newErrors.recipientAccount = accountError;
    }

    // Validate SWIFT code format
    // SWIFT codes follow ISO 9362: 8 chars (bank/country/location) or 11 chars (with branch)
    const swiftError = validators.swiftCode(formData.swiftCode);
    if (swiftError) {
      newErrors.swiftCode = swiftError;
    }

    // Validate payment description (optional field)
    // If provided, ensures it meets length and content requirements
    const descriptionError = validators.description(formData.description);
    if (descriptionError) {
      newErrors.description = descriptionError;
    }

    // Update errors state with validation results
    setErrors(newErrors);
    
    // Return true only if no validation errors exist
    return Object.keys(newErrors).length === 0;
  };

  /**
   * Handles form submission and payment processing workflow
   * Orchestrates the payment process including validation, user confirmation,
   * API submission, success handling, and error management. Implements
   * confirmation dialog to prevent accidental transactions.
   * 
   * @param {Event} e - The form submit event
   */
  const handleSubmit = async (e) => {
    // Prevent default form submission behavior (page reload)
    e.preventDefault();
    
    // Validate all form fields before proceeding
    if (!validateForm()) {
      return; // Exit early if validation fails
    }

    // Display confirmation dialog to prevent accidental payments
    // Shows key transaction details for user verification
    const confirmPayment = window.confirm(
      `Confirm payment of ${formData.currency} ${formData.amount} to account ${formData.recipientAccount}?`
    );

    // Exit if user cancels the payment
    if (!confirmPayment) {
      return;
    }

    // Set loading state to disable form and provide visual feedback
    setLoading(true);

    try {
      // Submit payment to backend API
      // Response should contain transaction ID for record-keeping
      const response = await submitPayment(formData);
      
      // Display success message with transaction ID
      // Transaction ID allows user to track and verify payment
      alert(`Payment submitted successfully! Transaction ID: ${response.transactionId}`);
      
      // Reset form to initial state after successful submission
      // Prepares form for next transaction and prevents accidental resubmission
      setFormData({
        amount: '',
        currency: 'ZAR',          // Reset to default currency
        recipientAccount: '',
        swiftCode: '',
        description: ''
      });
      
      // Notify parent component of successful payment
      // Allows parent to refresh data, update UI, or perform additional actions
      if (onPaymentSuccess) {
        onPaymentSuccess();
      }
      
    } catch (error) {
      // Display error message to user
      // Uses error message from API if available, otherwise shows generic message
      alert(error.message || 'Payment submission failed. Please try again.');
    } finally {
      // Always reset loading state regardless of success or failure
      // Ensures form remains usable for retry attempts
      setLoading(false);
    }
  };

  return (
    <div className="payment-form-container">
      {/* Form heading */}
      <h3>Make International Payment</h3>
      
      {/* Descriptive text providing context for the form */}
      <p className="form-description">Enter payment details to transfer funds internationally</p>

      {/* Main payment form */}
      <form onSubmit={handleSubmit} className="payment-form">
        {/* Amount and Currency row - grouped for visual organization */}
        <div className="form-row">
          {/* Amount input field */}
          <div className="form-group">
            <label htmlFor="amount">Amount *</label>
            <input
              type="text" // Text type allows for decimal input with custom validation
              id="amount" // Explicit ID for label association (accessibility)
              name="amount"
              value={formData.amount} // Controlled component pattern
              onChange={handleChange}
              className={errors.amount ? 'error' : ''} // Conditional error styling
              placeholder="0.00" // Numeric format guidance
              disabled={loading} // Prevent input during submission
            />
            {/* Display field-specific error message if validation fails */}
            {errors.amount && <span className="error-message">{errors.amount}</span>}
          </div>

          {/* Currency selection dropdown */}
          <div className="form-group">
            <label htmlFor="currency">Currency *</label>
            <select
              id="currency"
              name="currency"
              value={formData.currency} // Controlled component
              onChange={handleChange}
              className={errors.currency ? 'error' : ''} // Error styling
              disabled={loading} // Disable during submission
            >
              {/* Dynamically generate options from currencies array */}
              {/* Ensures consistent currency options across application */}
              {currencies.map(curr => (
                <option key={curr} value={curr}>{curr}</option>
              ))}
            </select>
            {/* Display currency validation error if present */}
            {errors.currency && <span className="error-message">{errors.currency}</span>}
          </div>
        </div>

        {/* Recipient Account Number input field */}
        <div className="form-group">
          <label htmlFor="recipientAccount">Recipient Account Number *</label>
          <input
            type="text"
            id="recipientAccount"
            name="recipientAccount"
            value={formData.recipientAccount} // Controlled component
            onChange={handleChange}
            className={errors.recipientAccount ? 'error' : ''} // Error styling
            placeholder="Enter recipient's account number"
            maxLength="12" // Enforce maximum length to prevent abuse
            disabled={loading} // Disable during submission
          />
          {/* Display account validation error if present */}
          {errors.recipientAccount && <span className="error-message">{errors.recipientAccount}</span>}
        </div>

        {/* SWIFT Code input field */}
        <div className="form-group">
          <label htmlFor="swiftCode">SWIFT Code *</label>
          <input
            type="text"
            id="swiftCode"
            name="swiftCode"
            value={formData.swiftCode} // Controlled component
            onChange={handleChange} // Automatically converts to uppercase
            className={errors.swiftCode ? 'error' : ''} // Error styling
            placeholder="e.g., ABCDEF12 or ABCDEF12345"
            maxLength="11" // ISO 9362 standard maximum length
            disabled={loading} // Disable during submission
          />
          {/* Display SWIFT validation error if present */}
          {errors.swiftCode && <span className="error-message">{errors.swiftCode}</span>}
          {/* Informational hint about SWIFT code format */}
          {/* Helps users understand expected input format */}
          <small className="input-hint">SWIFT codes are typically 8 or 11 characters</small>
        </div>

        {/* Payment Description textarea - optional field for reference information */}
        <div className="form-group">
          <label htmlFor="description">Payment Description (Optional)</label>
          <textarea
            id="description"
            name="description"
            value={formData.description} // Controlled component
            onChange={handleChange}
            className={errors.description ? 'error' : ''} // Error styling
            placeholder="Enter payment reference or description"
            rows="3" // Initial height for better UX
            maxLength="200" // Character limit to prevent abuse and ensure database compatibility
            disabled={loading} // Disable during submission
          />
          {/* Display description validation error if present */}
          {errors.description && <span className="error-message">{errors.description}</span>}
          {/* Live character counter */}
          {/* Provides real-time feedback on remaining characters */}
          <small className="input-hint">{formData.description.length}/200 characters</small>
        </div>

        {/* Submit button with dynamic states */}
        <button 
          type="submit" 
          className="pay-now-btn"
          disabled={loading} // Prevent multiple submissions during processing
        >
          {/* Dynamic button text provides feedback about current operation */}
          {loading ? 'Processing...' : 'Pay Now'}
        </button>
      </form>
    </div>
  );
};

export default PaymentForm;