using System;
using System.Collections.Generic;
using System.Security;
using System.IO;
using X509 = System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Collections;

namespace Opc.Ua
{
    public class ICertificate : X509.X509Certificate2
    {
        public ICertificate(byte[] data) : base(data)
        {
            BcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(data));
        }

        public ICertificate(byte[] data, string password, X509.X509KeyStorageFlags flags) : base(data, password, flags)
        {
        }

        public ICertificate(byte[] data, SecureString password, X509.X509KeyStorageFlags flags) : base(data, password, flags)
        {
            throw new NotSupportedException();
        }

        public ICertificate(string filePath) : base(filePath)
        {
            BcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(File.ReadAllBytes(filePath)));
        }

        public ICertificate(string fullName, string password, X509.X509KeyStorageFlags flags) : base(fullName, password, flags)
        {
        }

        public ICertificate(string fullName, SecureString password, X509.X509KeyStorageFlags flags) : base(fullName, password, flags)
        {
            throw new NotSupportedException();
        }

        public ICertificate(X509.X509Certificate2 certificate) : base(certificate)
        {
            BcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate.RawData));
        }

        public string SourceFilePath { get; set; }

        public Org.BouncyCastle.X509.X509Certificate BcCertificate { get; set; }

        public AsymmetricKeyParameter BcPrivateKey { get; set; }
    }

    public class ICertificateCollection : X509.X509Certificate2Collection, IEnumerable<ICertificate>
    {
        public ICertificateCollection()
        {
        }

        public ICertificateCollection(ICertificate certificate) : base(certificate)
        {
        }

        public ICertificateCollection(IEnumerable<ICertificate> certificates)
        {
            if (certificates != null)
            {
                foreach (var certificate in certificates)
                {
                    Add(certificate);
                }
            }
        }

        public ICertificateCollection(X509.X509Certificate2Collection certificates) : base(certificates)
        {
        }

        public new ICertificate this[int index] 
        {
            get
            {
                var certificate = base[index];

                if (certificate is ICertificate)
                {
                    return (ICertificate)certificate;
                }

                return new ICertificate(certificate);
            }

            set
            {
                base[index] = value;
            }
        }

        public new ICertificateCollection Find(X509.X509FindType findType, object findValue, bool validOnly)
        {
            return new ICertificateCollection(base.Find(findType, findValue, validOnly));
        }

        private class Enumerator : IEnumerator<ICertificate>
        {
            private X509.X509Certificate2Enumerator m_enumerator;

            public Enumerator(X509.X509Certificate2Enumerator enumerator)
            {
                m_enumerator = enumerator;
            }

            public ICertificate Current
            {
                get
                {
                    return (ICertificate)m_enumerator.Current;
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    return (ICertificate)m_enumerator.Current;
                }
            }

            public void Dispose()
            {
            }

            public bool MoveNext()
            {
                return m_enumerator.MoveNext();
            }

            public void Reset()
            {
                m_enumerator.Reset();
            }
        }

        IEnumerator<ICertificate> IEnumerable<ICertificate>.GetEnumerator()
        {
            return new Enumerator(base.GetEnumerator());
        }
    }
}
