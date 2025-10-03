const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Create ssl directory if it doesn't exist
const sslDir = path.join(__dirname, 'ssl');
if (!fs.existsSync(sslDir)) {
  fs.mkdirSync(sslDir);
  console.log('✅ Created ssl directory');
}

// For development only - generate self-signed certificate using Node's crypto
const forge = require('node-forge');
const pki = forge.pki;

console.log('🔐 Generating self-signed SSL certificate...');

// Generate a keypair
const keys = pki.rsa.generateKeyPair(2048);

// Create a certificate
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{
  name: 'commonName',
  value: 'localhost'
}, {
  name: 'countryName',
  value: 'ZA'
}, {
  shortName: 'ST',
  value: 'KwaZulu-Natal'
}, {
  name: 'localityName',
  value: 'Durban'
}, {
  name: 'organizationName',
  value: 'Development'
}, {
  shortName: 'OU',
  value: 'Development'
}];

cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([{
  name: 'basicConstraints',
  cA: true
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 2,
    value: 'localhost'
  }, {
    type: 7,
    ip: '127.0.0.1'
  }]
}]);

// Self-sign certificate
cert.sign(keys.privateKey, forge.md.sha256.create());

// Convert to PEM format
const pem = {
  privateKey: pki.privateKeyToPem(keys.privateKey),
  certificate: pki.certificateToPem(cert)
};

// Write files
fs.writeFileSync(path.join(sslDir, 'private.key'), pem.privateKey);
fs.writeFileSync(path.join(sslDir, 'certificate.crt'), pem.certificate);

console.log('✅ SSL certificate generated successfully!');
console.log('📁 Files created:');
console.log('   - ssl/private.key');
console.log('   - ssl/certificate.crt');
console.log('');
console.log('⚠️  NOTE: This is a self-signed certificate for DEVELOPMENT ONLY');
console.log('⚠️  Browsers will show a security warning - this is normal');
console.log('⚠️  For PRODUCTION, use a real certificate from Let\'s Encrypt or a CA');
