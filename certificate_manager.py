# Certificate and Digital Signature Implementation
# This file implements the certificate handling and digital signature functionality

import os
import datetime
from typing import Dict, Union, Tuple, Any, List, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils

class CertificateManager:
    """Class for certificate operations and management"""
    
    @staticmethod
    def generate_self_signed_cert(
        private_key: Any,
        common_name: str,
        organization_name: str = "Example Organization",
        country_name: str = "US",
        validity_days: int = 365
    ) -> x509.Certificate:
        """
        Generate a self-signed certificate
        
        Args:
            private_key: RSA or ECC private key
            common_name: Common name for the certificate (e.g., domain name)
            organization_name: Organization name
            country_name: Country code
            validity_days: Number of days the certificate is valid
            
        Returns:
            A self-signed X.509 certificate
        """
        # Determine subject/issuer for the certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build the certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Sign the certificate with the private key
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
        
        return certificate
    
    @staticmethod
    def generate_csr(
        private_key: Any,
        common_name: str,
        organization_name: str = "Example Organization",
        country_name: str = "US",
        alt_names: List[str] = None
    ) -> x509.CertificateSigningRequest:
        """
        Generate a Certificate Signing Request (CSR)
        
        Args:
            private_key: RSA or ECC private key
            common_name: Common name for the certificate (e.g., domain name)
            organization_name: Organization name
            country_name: Country code
            alt_names: List of alternative names (typically domain names)
            
        Returns:
            A Certificate Signing Request
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Add SubjectAlternativeName if provided
        if alt_names:
            san = x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names])
            builder = builder.add_extension(san, critical=False)
        
        # Sign the CSR with the private key
        csr = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
        
        return csr
    
    @staticmethod
    def serialize_certificate(certificate: x509.Certificate, encoding: str = "PEM") -> bytes:
        """
        Serialize a certificate to PEM or DER format
        
        Args:
            certificate: X.509 certificate
            encoding: "PEM" or "DER"
            
        Returns:
            Serialized certificate
        """
        if encoding.upper() == "PEM":
            return certificate.public_bytes(serialization.Encoding.PEM)
        elif encoding.upper() == "DER":
            return certificate.public_bytes(serialization.Encoding.DER)
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    @staticmethod
    def serialize_csr(csr: x509.CertificateSigningRequest, encoding: str = "PEM") -> bytes:
        """
        Serialize a CSR to PEM or DER format
        
        Args:
            csr: Certificate Signing Request
            encoding: "PEM" or "DER"
            
        Returns:
            Serialized CSR
        """
        if encoding.upper() == "PEM":
            return csr.public_bytes(serialization.Encoding.PEM)
        elif encoding.upper() == "DER":
            return csr.public_bytes(serialization.Encoding.DER)
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    @staticmethod
    def load_certificate(cert_data: bytes) -> x509.Certificate:
        """
        Load a certificate from PEM or DER encoded data
        
        Args:
            cert_data: Certificate data
            
        Returns:
            X.509 certificate
        """
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except Exception:
            try:
                return x509.load_der_x509_certificate(cert_data)
            except Exception:
                raise ValueError("Unable to load certificate. Invalid format.")
    
    @staticmethod
    def load_csr(csr_data: bytes) -> x509.CertificateSigningRequest:
        """
        Load a CSR from PEM or DER encoded data
        
        Args:
            csr_data: CSR data
            
        Returns:
            Certificate Signing Request
        """
        try:
            return x509.load_pem_x509_csr(csr_data)
        except Exception:
            try:
                return x509.load_der_x509_csr(csr_data)
            except Exception:
                raise ValueError("Unable to load CSR. Invalid format.")
    
    @staticmethod
    def verify_certificate_signature(certificate: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
        """
        Verify a certificate was signed by the issuer
        
        Args:
            certificate: Certificate to verify
            issuer_cert: Issuer certificate
            
        Returns:
            True if signature is valid, False otherwise
        """
        issuer_public_key = issuer_cert.public_key()
        
        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(certificate.signature_hash_algorithm)
                )
            else:
                return False
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def verify_certificate_chain(cert: x509.Certificate, trusted_certs: List[x509.Certificate]) -> bool:
        """
        Verify a certificate against a list of trusted certificates
        
        Args:
            cert: Certificate to verify
            trusted_certs: List of trusted certificates
            
        Returns:
            True if certificate is trusted, False otherwise
        """
        # This is a simplified version of certificate chain verification
        # A complete implementation would validate the entire chain, check revocation status, etc.
        
        for trusted_cert in trusted_certs:
            # Check if the certificate was issued by this trusted cert
            if cert.issuer == trusted_cert.subject:
                # Verify the signature
                if CertificateManager.verify_certificate_signature(cert, trusted_cert):
                    # Check if the certificate is valid (not expired)
                    now = datetime.datetime.utcnow()
                    if cert.not_valid_before <= now <= cert.not_valid_after:
                        return True
        
        return False


class DigitalSignature:
    """Class for digital signature operations"""
    
    @staticmethod
    def sign_data(data: bytes, private_key: Any) -> Dict[str, bytes]:
        """
        Sign data with a private key
        
        Args:
            data: Data to sign
            private_key: RSA or ECC private key
            
        Returns:
            Dictionary containing the signature and metadata
        """
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return {
                'signature': signature,
                'algorithm': b'RSA-PSS-SHA256'
            }
        
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
            
            return {
                'signature': signature,
                'algorithm': b'ECDSA-SHA256'
            }
        
        else:
            raise ValueError("Unsupported private key type")
    
    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: Any, algorithm: bytes) -> bool:
        """
        Verify a signature
        
        Args:
            data: Original data
            signature: Signature to verify
            public_key: RSA or ECC public key
            algorithm: Signature algorithm
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if algorithm == b'RSA-PSS-SHA256' and isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            
            elif algorithm == b'ECDSA-SHA256' and isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            
            else:
                return False
        
        except Exception:
            return False
    
    @staticmethod
    def sign_file(file_path: str, private_key: Any, output_path: str = None) -> str:
        """
        Sign a file
        
        Args:
            file_path: Path to the file to sign
            private_key: RSA or ECC private key
            output_path: Path to save the signature (default: file_path + ".sig")
            
        Returns:
            Path to the signature file
        """
        if output_path is None:
            output_path = file_path + ".sig"
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        signature_info = DigitalSignature.sign_data(data, private_key)
        
        with open(output_path, 'wb') as f:
            f.write(signature_info['signature'])
        
        # Save algorithm information in a separate file
        with open(output_path + ".alg", 'wb') as f:
            f.write(signature_info['algorithm'])
        
        return output_path
    
    @staticmethod
    def verify_file_signature(file_path: str, signature_path: str, public_key: Any) -> bool:
        """
        Verify a file signature
        
        Args:
            file_path: Path to the file
            signature_path: Path to the signature file
            public_key: RSA or ECC public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        # Load algorithm information
        with open(signature_path + ".alg", 'rb') as f:
            algorithm = f.read()
        
        return DigitalSignature.verify_signature(data, signature, public_key, algorithm)


# Example usage
def certificate_demo():
    """Demonstrate certificate and digital signature operations"""
    
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Generate a self-signed certificate
    cert = CertificateManager.generate_self_signed_cert(
        private_key=private_key,
        common_name="example.com",
        organization_name="Example Corp",
        country_name="US",
        validity_days=365
    )
    
    # Serialize the certificate to PEM format
    cert_pem = CertificateManager.serialize_certificate(cert)
    print("Self-signed certificate generated:")
    print(cert_pem.decode())
    
    # Generate a CSR
    csr = CertificateManager.generate_csr(
        private_key=private_key,
        common_name="example.com",
        organization_name="Example Corp",
        country_name="US",
        alt_names=["www.example.com", "mail.example.com"]
    )
    
    # Serialize the CSR to PEM format
    csr_pem = CertificateManager.serialize_csr(csr)
    print("\nCertificate Signing Request generated:")
    print(csr_pem.decode())
    
    # Sign a file
    with open("example.txt", "wb") as f:
        f.write(b"This is an example file to sign.")
    
    signature_path = DigitalSignature.sign_file("example.txt", private_key)
    print(f"\nFile signed. Signature saved to: {signature_path}")
    
    # Verify the file signature
    is_valid = DigitalSignature.verify_file_signature(
        "example.txt",
        signature_path,
        private_key.public_key()
    )
    
    print(f"Signature verification: {'Valid' if is_valid else 'Invalid'}")

if __name__ == "__main__":
    certificate_demo()