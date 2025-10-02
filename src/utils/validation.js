// RegEx patterns for input validation
export const patterns = {
  accountNumber: /^[0-9]{8,12}$/,
  swiftCode: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,
  name: /^[a-zA-Z\s\-']{2,50}$/,
  amount: /^\d+(\.\d{1,2})?$/,
  idNumber: /^[0-9]{13}$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
};

// Standalone validation functions for employee login
export const validateEmployeeId = (value) => {
 const employeeIdPattern = /^EMP\d{3,6}$/;
  return employeeIdPattern.test(value);
};

export const validatePassword = (value) => {
  return patterns.password.test(value) && value.length >= 8;
};

// Validation functions
export const validators = {
  accountNumber: (value) => {
    if (!value) return 'Account number is required';
    if (!patterns.accountNumber.test(value)) {
      return 'Account number must be 8-12 digits';
    }
    return '';
  },

  swiftCode: (value) => {
    if (!value) return 'SWIFT code is required';
    const upperValue = value.toUpperCase();
    if (!patterns.swiftCode.test(upperValue)) {
      return 'Invalid SWIFT code format (e.g., ABCDEF12 or ABCDEF12345)';
    }
    return '';
  },

  fullName: (value) => {
    if (!value) return 'Full name is required';
    if (!patterns.name.test(value)) {
      return 'Name must contain only letters, spaces, hyphens, and apostrophes (2-50 characters)';
    }
    return '';
  },

  amount: (value) => {
    if (!value) return 'Amount is required';
    if (!patterns.amount.test(value)) {
      return 'Invalid amount format';
    }
    const numValue = parseFloat(value);
    if (numValue <= 0) {
      return 'Amount must be greater than 0';
    }
    if (numValue > 1000000) {
      return 'Amount exceeds maximum limit (1,000,000)';
    }
    return '';
  },

  idNumber: (value) => {
    if (!value) return 'ID number is required';
    if (!patterns.idNumber.test(value)) {
      return 'ID number must be exactly 13 digits';
    }
    return '';
  },

  password: (value) => {
    if (!value) return 'Password is required';
    if (value.length < 8) {
      return 'Password must be at least 8 characters';
    }
    if (!patterns.password.test(value)) {
      return 'Password must contain uppercase, lowercase, number, and special character (@$!%*?&)';
    }
    return '';
  },

  confirmPassword: (value, password) => {
    if (!value) return 'Please confirm your password';
    if (value !== password) {
      return 'Passwords do not match';
    }
    return '';
  },

  currency: (value) => {
    if (!value) return 'Currency is required';
    return '';
  },

  description: (value) => {
    if (value && value.length > 200) {
      return 'Description must not exceed 200 characters';
    }
    return '';
  }
};

// Sanitize input to prevent XSS
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.replace(/[<>"']/g, '');
};

// Validate entire form
export const validateForm = (formData, validationRules) => {
  const errors = {};
  
  Object.keys(validationRules).forEach(field => {
    const validator = validationRules[field];
    const error = validator(formData[field], formData);
    if (error) {
      errors[field] = error;
    }
  });

  return {
    isValid: Object.keys(errors).length === 0,
    errors
  };
};