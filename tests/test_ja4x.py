"""
Tests for JA4X (X.509 Certificate) fingerprinting
"""

import unittest
from scapy.all import IP, TCP, Raw
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter, generate_ja4x
from ja4plus.utils.x509_utils import oid_to_hex
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

class TestJA4X(unittest.TestCase):
    """Test JA4X fingerprinting functionality"""
    
    def setUp(self):
        """Set up test environment"""
        print("\nSetting up JA4X test...")
        
        # Generate a self-signed test certificate
        self.cert_data = self.generate_test_certificate()
        print(f"Generated certificate with size {len(self.cert_data)} bytes")
        
        print("Setup complete.\n")
    
    def generate_test_certificate(self):
        """Generate a test certificate for fingerprinting"""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Prepare certificate details
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        # Time range for certificate validity
        now = datetime.datetime.now(datetime.UTC)
        valid_from = now
        valid_to = now + datetime.timedelta(days=365)
        
        # Create the certificate
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            valid_from
        ).not_valid_after(
            valid_to
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), 
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False),
            critical=True
        )
        
        # Sign the certificate
        certificate = builder.sign(
            private_key=private_key, 
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # Return DER encoded certificate
        return certificate.public_bytes(encoding=Encoding.DER)
    
    def test_ja4x_direct_certificate(self):
        """Test JA4X fingerprinting with a certificate directly."""
        print("Testing JA4X with direct certificate data...")
        
        try:
            # Parse the test certificate
            cert = x509.load_der_x509_certificate(self.cert_data, default_backend())
            print("Successfully parsed X.509 certificate:")
            print(f"  Subject: {cert.subject}")
            print(f"  Issuer: {cert.issuer}")
            
            # Extract certificate details
            cert_info = self.extract_cert_details(cert)
            print("Certificate details extracted successfully")
            print(f"  Issuer RDNs: {cert_info.get('issuer_rdns')}")
            print(f"  Subject RDNs: {cert_info.get('subject_rdns')}")
            print(f"  Extensions: {cert_info.get('extensions')}")
            
            # Manually generate JA4X fingerprint
            ja4x = generate_ja4x(cert_info)
            print(f"Manually constructed JA4X: {ja4x}")
            
            # Use fingerprinter on raw certificate data
            fingerprinter = JA4XFingerprinter()
            fingerprint = fingerprinter.fingerprint_certificate(self.cert_data)
            print(f"JA4X fingerprint from fingerprinter: {fingerprint}")
            
            self.assertIsNotNone(fingerprint, "JA4X fingerprinting failed")
            self.assertEqual(ja4x, fingerprint, "JA4X fingerprints should match")
            
        except Exception as e:
            print(f"Error in certificate processing: {e}")
            self.fail(f"Certificate processing failed: {e}")
    
    def extract_cert_details(self, cert):
        """Extract certificate details matching the fingerprinter implementation"""
        if not cert:
            return None

        try:
            issuer_rdns = []
            subject_rdns = []
            extensions = []

            # Process issuer - use hex-encoded OID (matches fingerprinter)
            for rdn in cert.issuer.rdns:
                for attr in rdn:
                    issuer_rdns.append(oid_to_hex(attr.oid.dotted_string))

            # Process subject
            for rdn in cert.subject.rdns:
                for attr in rdn:
                    subject_rdns.append(oid_to_hex(attr.oid.dotted_string))

            # Process extensions
            for ext in cert.extensions:
                extensions.append(oid_to_hex(ext.oid.dotted_string))

            return {
                'issuer_rdns': issuer_rdns,
                'subject_rdns': subject_rdns,
                'extensions': extensions
            }
        except Exception:
            return None

if __name__ == '__main__':
    unittest.main() 