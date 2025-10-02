import React, { useState } from 'react';
import { validators, sanitizeInput } from '../utils/validation';
import { submitPayment } from '../services/api';
import './PaymentForm.css';

const PaymentForm = ({ onPaymentSuccess }) => {
  const [formData, setFormData] = useState({
    amount: '',
    currency: 'ZAR',
    recipientAccount: '',
    swiftCode: '',
    description: ''
  });

  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const currencies = ['ZAR', 'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD'];

  const handleChange = (e) => {
    const { name, value } = e.target;
    let sanitizedValue = sanitizeInput(value);
    
    // Auto-uppercase SWIFT code
    if (name === 'swiftCode') {
      sanitizedValue = sanitizedValue.toUpperCase();
    }
    
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
    
    const amountError = validators.amount(formData.amount);
    if (amountError) {
      newErrors.amount = amountError;
    }

    const currencyError = validators.currency(formData.currency);
    if (currencyError) {
      newErrors.currency = currencyError;
    }

    const accountError = validators.accountNumber(formData.recipientAccount);
    if (accountError) {
      newErrors.recipientAccount = accountError;
    }

    const swiftError = validators.swiftCode(formData.swiftCode);
    if (swiftError) {
      newErrors.swiftCode = swiftError;
    }

    const descriptionError = validators.description(formData.description);
    if (descriptionError) {
      newErrors.description = descriptionError;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    const confirmPayment = window.confirm(
      `Confirm payment of ${formData.currency} ${formData.amount} to account ${formData.recipientAccount}?`
    );

    if (!confirmPayment) {
      return;
    }

    setLoading(true);

    try {
      const response = await submitPayment(formData);
      
      alert(`Payment submitted successfully! Transaction ID: ${response.transactionId}`);
      
      // Reset form
      setFormData({
        amount: '',
        currency: 'ZAR',
        recipientAccount: '',
        swiftCode: '',
        description: ''
      });
      
      // Notify parent component
      if (onPaymentSuccess) {
        onPaymentSuccess();
      }
      
    } catch (error) {
      alert(error.message || 'Payment submission failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="payment-form-container">
      <h3>Make International Payment</h3>
      <p className="form-description">Enter payment details to transfer funds internationally</p>

      <form onSubmit={handleSubmit} className="payment-form">
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="amount">Amount *</label>
            <input
              type="text"
              id="amount"
              name="amount"
              value={formData.amount}
              onChange={handleChange}
              className={errors.amount ? 'error' : ''}
              placeholder="0.00"
              disabled={loading}
            />
            {errors.amount && <span className="error-message">{errors.amount}</span>}
          </div>

          <div className="form-group">
            <label htmlFor="currency">Currency *</label>
            <select
              id="currency"
              name="currency"
              value={formData.currency}
              onChange={handleChange}
              className={errors.currency ? 'error' : ''}
              disabled={loading}
            >
              {currencies.map(curr => (
                <option key={curr} value={curr}>{curr}</option>
              ))}
            </select>
            {errors.currency && <span className="error-message">{errors.currency}</span>}
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="recipientAccount">Recipient Account Number *</label>
          <input
            type="text"
            id="recipientAccount"
            name="recipientAccount"
            value={formData.recipientAccount}
            onChange={handleChange}
            className={errors.recipientAccount ? 'error' : ''}
            placeholder="Enter recipient's account number"
            maxLength="12"
            disabled={loading}
          />
          {errors.recipientAccount && <span className="error-message">{errors.recipientAccount}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="swiftCode">SWIFT Code *</label>
          <input
            type="text"
            id="swiftCode"
            name="swiftCode"
            value={formData.swiftCode}
            onChange={handleChange}
            className={errors.swiftCode ? 'error' : ''}
            placeholder="e.g., ABCDEF12 or ABCDEF12345"
            maxLength="11"
            disabled={loading}
          />
          {errors.swiftCode && <span className="error-message">{errors.swiftCode}</span>}
          <small className="input-hint">SWIFT codes are typically 8 or 11 characters</small>
        </div>

        <div className="form-group">
          <label htmlFor="description">Payment Description (Optional)</label>
          <textarea
            id="description"
            name="description"
            value={formData.description}
            onChange={handleChange}
            className={errors.description ? 'error' : ''}
            placeholder="Enter payment reference or description"
            rows="3"
            maxLength="200"
            disabled={loading}
          />
          {errors.description && <span className="error-message">{errors.description}</span>}
          <small className="input-hint">{formData.description.length}/200 characters</small>
        </div>

        <button 
          type="submit" 
          className="pay-now-btn"
          disabled={loading}
        >
          {loading ? 'Processing...' : 'Pay Now'}
        </button>
      </form>
    </div>
  );
};

export default PaymentForm;