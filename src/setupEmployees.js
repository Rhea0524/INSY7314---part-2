const { initializeApp } = require('firebase/app');
const { getAuth, createUserWithEmailAndPassword } = require('firebase/auth');
const { getFirestore, collection, setDoc, doc } = require('firebase/firestore');
require('dotenv').config();

const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY,
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID,
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.REACT_APP_FIREBASE_APP_ID
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

const employees = [
  {
    employeeId: 'EMP001',
    email: 'emp001@bank.com',
    password: 'TestPass123!',
    name: 'John Smith',
    role: 'staff'
  },
  {
    employeeId: 'EMP002',
    email: 'emp002@bank.com',
    password: 'TestPass123!',
    name: 'Sarah Johnson',
    role: 'manager'
  }
];

async function setupEmployees() {
  console.log('\n=== Setting up Employee Accounts ===\n');
  
  for (const emp of employees) {
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, emp.email, emp.password);
      const user = userCredential.user;
      
      await setDoc(doc(db, 'employees', emp.employeeId), {
        employeeId: emp.employeeId,
        email: emp.email,
        uid: user.uid,
        name: emp.name,
        role: emp.role,
        createdAt: new Date().toISOString()
      });
      
      console.log(`✓ Created employee: ${emp.employeeId} (${emp.email})`);
      console.log(`  Password: ${emp.password}`);
      console.log(`  Name: ${emp.name}\n`);
      
    } catch (error) {
      console.error(`✗ Error creating ${emp.employeeId}:`, error.message);
    }
  }
  
  console.log('\n=== Setup Complete ===');
  console.log('You can now login with:');
  console.log('Employee ID: EMP001 or EMP002');
  console.log('Password: TestPass123!\n');
  process.exit(0);
}

setupEmployees();