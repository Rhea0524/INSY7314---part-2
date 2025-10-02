const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Import Firebase Admin
const { admin, db } = require('./config/firebase');

const app = express();

// JWT Secret (add this to your .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// 🔥 NEW: Password Pepper (additional security layer)
const PEPPER = process.env.PASSWORD_PEPPER || 'default-pepper-change-in-production-5k9j3h7f2d1a';

// 🔥 NEW: Adaptive bcrypt cost factor based on server capability
const getAdaptiveCostFactor = () => {
  const targetTime = 250; // Target 250ms for password hashing
  let rounds = 10;
  
  // Test hashing speed (only do this once at startup)
  const testPassword = 'test-password-for-benchmarking';
  const start = Date.now();
  bcrypt.hashSync(testPassword, 10);
  const duration = Date.now() - start;
  
  // Adjust rounds based on server speed
  if (duration < 100) rounds = 12; // Fast server
  else if (duration < 200) rounds = 11; // Medium server
  else rounds = 10; // Slower server
  
  console.log(`⚙️ Adaptive bcrypt rounds set to: ${rounds} (${duration}ms test)`);
  return rounds;
};

const BCRYPT_ROUNDS = getAdaptiveCostFactor();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: 'http://localhost:5001',
  credentials: true
}));

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// UPDATED: Hybrid Authentication Middleware
// - Customers use JWT (Firestore-based)
// - Employees use Firebase Auth
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Try to decode as JWT first (for customers)
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      if (decoded.userType === 'customer') {
        // Verify customer still exists in Firestore
        const customerSnapshot = await db.collection('customers')
          .where('accountNumber', '==', decoded.accountNumber)
          .limit(1)
          .get();
        
        if (customerSnapshot.empty) {
          return res.status(403).json({ error: 'Customer not found' });
        }

        const customerData = customerSnapshot.docs[0].data();
        req.user = {
          accountNumber: decoded.accountNumber,
          userId: customerSnapshot.docs[0].id,
          role: 'customer',
          username: customerData.fullName,
          userType: 'customer'
        };
        console.log('Authenticated customer:', req.user.accountNumber);
        return next();
      }
    } catch (jwtError) {
      // If JWT verification fails, try Firebase Auth (for employees)
      try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        
        // Check if this is an employee
        const employeeSnapshot = await db.collection('employees')
          .where('email', '==', decodedToken.email)
          .limit(1)
          .get();
        
        if (!employeeSnapshot.empty) {
          const employeeData = employeeSnapshot.docs[0].data();
          req.user = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            username: employeeData.employeeId,
            role: (employeeData.role || '').toString().trim().toLowerCase(),
            name: employeeData.name,
            userType: 'employee'
          };
          console.log('Authenticated employee:', req.user.username, 'Role:', req.user.role);
          return next();
        }
      } catch (firebaseError) {
        console.error('Firebase Auth error:', firebaseError);
      }
    }
    
    return res.status(403).json({ error: 'Invalid or expired token' });
    
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Input validation patterns
const validators = {
  register: [
    body('fullName').trim().matches(/^[a-zA-Z\s]{2,50}$/).withMessage('Invalid name format'),
    body('idNumber').trim().matches(/^\d{13}$/).withMessage('ID number must be 13 digits'),
    body('accountNumber').trim().matches(/^\d{10,16}$/).withMessage('Invalid account number'),
    body('password').matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/)
      .withMessage('Password must be at least 8 characters with uppercase, lowercase, number and special character')
  ],
  login: [
    body('accountNumber').trim().matches(/^\d{10,16}$/).withMessage('Invalid account number'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  payment: [
    body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be positive'),
    body('currency').matches(/^[A-Z]{3}$/).withMessage('Invalid currency code'),
    body('payeeAccount').trim().matches(/^\d{10,16}$/),
    body('swiftCode').trim().matches(/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/).withMessage('Invalid SWIFT code')
  ]
};

// 🔥 UPDATED: Customer Registration with Pepper + Adaptive Rounds
app.post('/api/register', validators.register, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, idNumber, accountNumber, password } = req.body;

    const accountSnapshot = await db.collection('customers')
      .where('accountNumber', '==', accountNumber)
      .get();

    if (!accountSnapshot.empty) {
      return res.status(400).json({ error: 'Account number already registered' });
    }

    const idSnapshot = await db.collection('customers')
      .where('idNumber', '==', idNumber)
      .get();

    if (!idSnapshot.empty) {
      return res.status(400).json({ error: 'ID number already registered' });
    }

    // 🔥 NEW: Add pepper to password before hashing
    const passwordWithPepper = password + PEPPER;
    
    // 🔥 NEW: Use adaptive cost factor
    const hashedPassword = await bcrypt.hash(passwordWithPepper, BCRYPT_ROUNDS);

    await db.collection('customers').add({
      fullName,
      idNumber,
      accountNumber,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log(`✅ New customer registered: ${accountNumber} (bcrypt rounds: ${BCRYPT_ROUNDS})`);
    res.status(201).json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// 🔥 UPDATED: Customer Login with Pepper
app.post('/api/login', validators.login, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { accountNumber, password } = req.body;

    // Find customer in Firestore
    const customerSnapshot = await db.collection('customers')
      .where('accountNumber', '==', accountNumber)
      .limit(1)
      .get();

    if (customerSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid account number or password' });
    }

    const customerDoc = customerSnapshot.docs[0];
    const customerData = customerDoc.data();

    // 🔥 NEW: Add pepper to password before comparison
    const passwordWithPepper = password + PEPPER;
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(passwordWithPepper, customerData.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid account number or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        accountNumber: customerData.accountNumber,
        userId: customerDoc.id,
        userType: 'customer'
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`✅ Customer logged in: ${accountNumber}`);
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        accountNumber: customerData.accountNumber,
        fullName: customerData.fullName,
        role: 'customer'
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Employee Login - Still uses Firebase Auth on frontend
app.post('/api/employee/login', async (req, res) => {
  res.status(400).json({ 
    error: 'Please use Firebase authentication. Employee login is handled on the frontend.' 
  });
});

// Submit Payment
app.post('/api/payment', authenticateToken, validators.payment, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, currency, provider, payeeAccount, swiftCode } = req.body;
    
    // Get customer details
    const customerSnapshot = await db.collection('customers')
      .where('accountNumber', '==', req.user.accountNumber)
      .limit(1)
      .get();

    if (customerSnapshot.empty) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const customerData = customerSnapshot.docs[0].data();
    
    // Store transaction with all required fields
    const transactionRef = await db.collection('transactions').add({
      customerAccount: req.user.accountNumber,
      customerName: customerData.fullName,
      userId: req.user.userId,
      amount: parseFloat(amount),
      currency,
      provider,
      payeeAccount,
      recipientAccount: payeeAccount,
      recipientName: provider || 'SWIFT Transfer',
      swiftCode,
      status: 'pending',
      verified: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log(`✅ New payment submitted: ${transactionRef.id}`);
    res.status(201).json({ 
      message: 'Payment submitted successfully',
      transactionId: transactionRef.id
    });
  } catch (error) {
    console.error('Payment error:', error);
    res.status(500).json({ error: 'Payment submission failed' });
  }
});

// Get All Transactions (Employee)
app.get('/api/employee/transactions', authenticateToken, async (req, res) => {
  try {
    // Check if user is employee or staff
    if (req.user.role !== 'employee' && req.user.role !== 'staff') {
      return res.status(403).json({ error: 'Access denied. Employee role required.' });
    }

    const snapshot = await db.collection('transactions').get();

    // Sort in memory to avoid composite index
    const allTransactions = snapshot.docs
      .map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          // Convert Firestore Timestamp to ISO string
          createdAt: data.createdAt?.toDate?.()?.toISOString() || new Date().toISOString()
        };
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    console.log(`✅ Fetched ${allTransactions.length} transactions for employee ${req.user.username}`);
    res.json(allTransactions);
  } catch (error) {
    console.error('Fetch transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions', details: error.message });
  }
});

// Verify Transaction
app.put('/api/employee/transactions/:id/verify', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'employee' && req.user.role !== 'staff') {
      return res.status(403).json({ error: 'Access denied. Employee role required.' });
    }

    const transactionRef = db.collection('transactions').doc(req.params.id);
    const doc = await transactionRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Update with verified status
    await transactionRef.update({
      verified: true,
      status: 'verified',
      verifiedBy: req.user.username,
      verifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const updatedDoc = await transactionRef.get();
    const data = updatedDoc.data();

    console.log(`✅ Transaction verified: ${req.params.id} by ${req.user.username}`);
    res.json({ 
      success: true,
      message: 'Transaction verified', 
      transaction: { 
        id: updatedDoc.id, 
        ...data,
        verifiedAt: data.verifiedAt?.toDate?.()?.toISOString()
      }
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Verification failed',
      message: error.message 
    });
  }
});

// Submit to SWIFT
app.post('/api/employee/transactions/:id/swift', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'employee' && req.user.role !== 'staff') {
      return res.status(403).json({ error: 'Access denied. Employee role required.' });
    }

    const transactionRef = db.collection('transactions').doc(req.params.id);
    const doc = await transactionRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const transaction = doc.data();

    // Check if transaction is verified
    if (!transaction.verified || transaction.status !== 'verified') {
      return res.status(400).json({ 
        success: false,
        error: 'Transaction must be verified before SWIFT submission' 
      });
    }

    // Generate SWIFT reference
    const swiftReference = `SWIFT${Date.now()}${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    // Update to completed status
    await transactionRef.update({
      status: 'completed',
      swiftReference,
      submittedBy: req.user.username,
      submittedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const updatedDoc = await transactionRef.get();
    const data = updatedDoc.data();

    console.log(`✅ Transaction ${req.params.id} submitted to SWIFT by ${req.user.username}`);
    res.json({ 
      success: true,
      message: 'Transaction submitted to SWIFT successfully',
      swiftReference,
      transaction: {
        id: updatedDoc.id,
        ...data,
        submittedAt: data.submittedAt?.toDate?.()?.toISOString()
      }
    });
  } catch (error) {
    console.error('SWIFT submission error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Submission to SWIFT failed',
      message: error.message
    });
  }
});

// Get Customer Transactions
app.get('/api/customer/transactions', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'customer') {
      return res.status(403).json({ error: 'Access denied. Customer role required.' });
    }

    const snapshot = await db.collection('transactions')
      .where('customerAccount', '==', req.user.accountNumber)
      .get();

    // Sort in memory instead of Firestore to avoid composite index requirement
    const customerTransactions = snapshot.docs
      .map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          createdAt: data.createdAt?.toDate?.()?.toISOString() || new Date().toISOString()
        };
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    console.log(`✅ Fetched ${customerTransactions.length} transactions for customer ${req.user.accountNumber}`);
    res.json(customerTransactions);
  } catch (error) {
    console.error('Fetch customer transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions', details: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running', timestamp: new Date() });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🔒 Secure server running on port ${PORT}`);
  console.log(`✅ Customer Auth: Firestore + JWT`);
  console.log(`✅ Employee Auth: Firebase Auth`);
  console.log(`✅ Password hashing: Enabled (${BCRYPT_ROUNDS} rounds + pepper)`);
  console.log(`✅ Input validation: Enabled`);
  console.log(`✅ Rate limiting: Enabled`);
  console.log(`✅ Security headers: Enabled`);
  console.log(`✅ Firestore: Connected`);
});