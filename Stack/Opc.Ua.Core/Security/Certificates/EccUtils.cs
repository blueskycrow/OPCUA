/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua
{
    public class Nonce : IDisposable
    {
        #if NET47
        private ECDiffieHellmanCng m_ecdh;
        #endif

        private Nonce()
        {
            #if NET47
            m_ecdh = null;
            #endif
        }

        #region IDisposable Members
        /// <summary>
        /// Frees any unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                #if NET47
                if (m_ecdh != null)
                {
                    m_ecdh.Dispose();
                    m_ecdh = null;
                }
                #endif
            }
        }
        #endregion

        public byte[] Data { get; private set; }

        public byte[] DeriveKeyFromHmac(Nonce remoteNonce, string label, HashAlgorithmName algorithm)
        {
            #if NET47
            if (m_ecdh != null)
            {
                var nonce = new UTF8Encoding().GetBytes(label);
                return m_ecdh.DeriveKeyFromHmac(remoteNonce.m_ecdh.PublicKey, algorithm, null, nonce, null);
            }
            #endif

            return Data;
        }

        public static Nonce CreateNonce(string securityPolicyUri, uint nonceLength)
        {
            if (securityPolicyUri == null)
            {
                throw new ArgumentNullException("securityPolicyUri");
            }

            Nonce nonce = null;

            #if !NET47
            nonce = new Nonce()
            {
                Data = Utils.Nonce.CreateNonce(nonceLength)
            };

            return nonce;
            #else
            ECCurve curve;
            CngAlgorithm algorithm;

            switch (securityPolicyUri)
            {
                case SecurityPolicies.Aes128_Sha256_nistP256: { curve = ECCurve.NamedCurves.nistP256; algorithm = CngAlgorithm.Sha256; break; }
                case SecurityPolicies.Aes256_Sha384_nistP384: { curve = ECCurve.NamedCurves.nistP384; algorithm = CngAlgorithm.Sha384; break; }
                case SecurityPolicies.Aes128_Sha256_brainpoolP256r1: { curve = ECCurve.NamedCurves.brainpoolP256r1; algorithm = CngAlgorithm.Sha256; break; }
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1: { curve = ECCurve.NamedCurves.brainpoolP384r1; algorithm = CngAlgorithm.Sha384; break; }

                default:
                {
                    algorithm = CngAlgorithm.Rsa;
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
                }
            }

            if (algorithm == CngAlgorithm.Rsa)
            {
                nonce = new Nonce()
                {
                    Data = Utils.Nonce.CreateNonce(nonceLength)
                };

                return nonce;
            }

            var ecdh = (ECDiffieHellmanCng)ECDiffieHellmanCng.Create(curve);

            var data = ecdh.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            var senderNonce = new byte[data.Length - 8];
            Buffer.BlockCopy(data, 8, senderNonce, 0, senderNonce.Length);

            nonce = new Nonce()
            {
                Data = senderNonce,
                m_ecdh = ecdh
            };

            return nonce;
            #endif
        }

        public static Nonce CreateNonce(string securityPolicyUri, byte[] nonceData)
        {
            Nonce nonce = new Nonce()
            {
                Data = nonceData
            };

            #if NET47
            ECCurve curve;
            CngAlgorithm algorithm;

            switch (securityPolicyUri)
            {
                case SecurityPolicies.Aes128_Sha256_nistP256: { curve = ECCurve.NamedCurves.nistP256; algorithm = CngAlgorithm.Sha256; break; }
                case SecurityPolicies.Aes256_Sha384_nistP384: { curve = ECCurve.NamedCurves.nistP384; algorithm = CngAlgorithm.Sha384; break; }
                case SecurityPolicies.Aes128_Sha256_brainpoolP256r1: { curve = ECCurve.NamedCurves.brainpoolP256r1; algorithm = CngAlgorithm.Sha256; break; }
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1: { curve = ECCurve.NamedCurves.brainpoolP384r1; algorithm = CngAlgorithm.Sha384; break; }
    
                default:
                {
                    algorithm = CngAlgorithm.Rsa;
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
                }
            }
    
            if (algorithm != CngAlgorithm.Rsa)
            {
                int keyLength = nonceData.Length;

                using (var ostrm = new System.IO.MemoryStream())
                {
                    byte[] qx = new byte[keyLength / 2];
                    byte[] qy = new byte[keyLength / 2];
                    Buffer.BlockCopy(nonceData, 0, qx, 0, keyLength / 2);
                    Buffer.BlockCopy(nonceData, keyLength / 2, qy, 0, keyLength / 2);

                    var ecdhParameters = new ECParameters
                    {
                        Curve = curve,
                        Q = { X = qx, Y = qy }
                    };

                    nonce.m_ecdh = (ECDiffieHellmanCng)ECDiffieHellman.Create(ecdhParameters);
                }
            }
            #endif

            return nonce;
        }
    }

    /// <summary>
    /// Defines functions to implement ECC cryptography.
    /// </summary>
    public static class EccUtils
    {
        #if NET47
        public static ECDsa GetPublicKey(X509Certificate2 certificate)
        {
            if (certificate == null || certificate.GetKeyAlgorithm() != "1.2.840.10045.2.1")
            {
                return null;
            }

            const X509KeyUsageFlags SufficientFlags =
                X509KeyUsageFlags.KeyAgreement |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.CrlSign |
                X509KeyUsageFlags.KeyCertSign;

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid.Value == "2.5.29.15")
                {
                    X509KeyUsageExtension kuExt = (X509KeyUsageExtension)extension;

                    if ((kuExt.KeyUsages & SufficientFlags) == 0)
                    {
                        return null;
                    }
                }
            }

            PublicKey encodedPublicKey = certificate.PublicKey;
            string keyParameters = BitConverter.ToString(encodedPublicKey.EncodedParameters.RawData);
            byte[] keyValue = encodedPublicKey.EncodedKeyValue.RawData;

            ECParameters ecParameters = default(ECParameters);

            if (keyValue[0] != 0x04)
            {
                throw new InvalidOperationException("Only uncompressed points are supported");
            }

            byte[] x = new byte[(keyValue.Length - 1) / 2];
            byte[] y = new byte[x.Length];

            Buffer.BlockCopy(keyValue, 1, x, 0, x.Length);
            Buffer.BlockCopy(keyValue, 1 + x.Length, y, 0, y.Length);

            ecParameters.Q.X = x;
            ecParameters.Q.Y = y;

            // New values can be determined by running the dotted-decimal OID value
            // through BitConverter.ToString(CryptoConfig.EncodeOID(dottedDecimal));

            switch (keyParameters)
            {
                case "06-08-2A-86-48-CE-3D-03-01-07":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.nistP256;
                    break;
                }

                case "06-05-2B-81-04-00-22":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.nistP384;
                    break;
                }

                case "06-09-2B-24-03-03-02-08-01-01-07":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP256r1;
                    break;
                }
                case "06-09-2B-24-03-03-02-08-01-01-0B":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP384r1;
                    break;
                }

                default:
                {
                    throw new NotImplementedException(keyParameters);
                }
            }

            return ECDsa.Create(ecParameters);
        }
        #endif

        /// <summary>
        /// Returns the length of a ECSA signature of a digest.
        /// </summary>
        public static int GetSignatureLength(X509Certificate2 signingCertificate)
        {
            if (signingCertificate == null)
            {
                throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No public key for certificate.");
            }

            #if NET47
            using (var publicKey =GetPublicKey(signingCertificate))
            {
                if (publicKey == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No public key for certificate.");
                }

                return publicKey.KeySize/4;
            }
            #endif

            throw new NotImplementedException();
        }

        /// <summary>
        /// Encrypts the data using ECC based encryption.
        /// </summary>
        public static byte[] Encrypt(
            byte[] dataToEncrypt,
            X509Certificate2 encryptingCertificate)
        {
            return dataToEncrypt;
        }

        /// <summary>
        /// Encrypts the data using ECC based encryption.
        /// </summary>
        public static byte[] Decrypt(
            ArraySegment<byte> dataToDecrypt,
            X509Certificate2 encryptingCertificate)
        {
            return dataToDecrypt.Array;
        }

        /// <summary>
        /// Computes an ECDSA signature.
        /// </summary>
        public static byte[] Sign(
            ArraySegment<byte> dataToSign,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
#if NET47

            var senderPrivateKey = signingCertificate.GetECDsaPrivateKey() as ECDsaCng;

            if (senderPrivateKey == null)
            {
                throw new ServiceResultException(StatusCodes.BadCertificateInvalid, "Missing private key needed for create a signature.");
            }

            using (senderPrivateKey)
            {
                var signature = senderPrivateKey.SignData(dataToSign.Array, dataToSign.Offset, dataToSign.Count, algorithm);

#if DEBUG
                using (ECDsa ecdsa = EccUtils.GetPublicKey(new X509Certificate2(signingCertificate.RawData)))
                {
                    if (!ecdsa.VerifyData(dataToSign.Array, dataToSign.Offset, dataToSign.Count, signature, algorithm))
                    {
                        throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Could not verify signature.");
                    }
                }
#endif

                return signature;
            }

#else
            throw new NotSupportedException();
#endif
        }

        /// <summary>
        /// Verifies an ECDSA signature.
        /// </summary>
        public static bool Verify(
            ArraySegment<byte> dataToVerify,
            byte[] signature,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
#if NET47
            using (ECDsa ecdsa = EccUtils.GetPublicKey(signingCertificate))
            {
                if (!ecdsa.VerifyData(dataToVerify.Array, dataToVerify.Offset, dataToVerify.Count, signature, algorithm))
                {
                    return false;
                }
            }

            return true;
#else
            throw new NotSupportedException();
#endif
        }
    }

    public class EncryptedSecret
    {
        public X509Certificate2 SenderCertificate { get; set; }
    
        public Nonce SenderNonce { get; set; }

        public X509Certificate2 RecipientCertificate { get; set; }

        public Nonce RecipientNonce { get; set; }

        public byte[] Secret { get; set; }

        public byte[] Encrypt(string securityPolicyUri)
        {
            BinaryEncoder encoder = new BinaryEncoder(ServiceMessageContext.GlobalContext);

            encoder.WriteNodeId(null, new NodeId(100000));
            encoder.WriteByte(null, (byte)ExtensionObjectEncoding.Binary);

            int lengthPosition = encoder.Position;
            encoder.WriteUInt32(null, 0);
            encoder.WriteString(null, securityPolicyUri);
            encoder.WriteByteString(null, RecipientNonce.Data);
            encoder.WriteDateTime(null, DateTime.UtcNow);
            encoder.WriteUInt16(null, (ushort)SenderNonce.Data.Length);
            encoder.WriteByteString(null, SenderNonce.Data);

            int signingKeySize = 32;
            int encryptingKeySize = 32;
            int blockSize = 16;

            var secret = SenderNonce.DeriveKeyFromHmac(RecipientNonce, String.Empty, HashAlgorithmName.SHA256);

            var encoder2 = new BinaryEncoder(ServiceMessageContext.GlobalContext);

            encoder2.WriteByteString(null, SenderNonce.Data);
            encoder2.WriteByteString(null, Secret);

            ushort paddingSize = (ushort)((encoder2.Position + 2) % blockSize);

            for (int ii = 0; ii < paddingSize; ii++)
            {
                encoder2.WriteByte(null, (byte)(paddingSize & 0xFF));
            }

            encoder2.WriteUInt16(null, paddingSize);

            var dataToEncrypt = encoder2.CloseAndReturnBuffer();

            var keyData = Utils.PSHA256(secret, null, null, 0, signingKeySize + encryptingKeySize + blockSize);

            var signingKey = new byte[signingKeySize];
            var encryptingKey = new byte[encryptingKeySize];
            var iv = new byte[blockSize];

            Buffer.BlockCopy(keyData, 0, signingKey, 0, signingKey.Length);
            Buffer.BlockCopy(keyData, signingKeySize, encryptingKey, 0, encryptingKey.Length);
            Buffer.BlockCopy(keyData, signingKeySize + encryptingKeySize, iv, 0, iv.Length);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = encryptingKey;
                aes.IV = iv;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    if (dataToEncrypt.Length % encryptor.InputBlockSize != 0)
                    {
                        throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "Input data is not an even number of encryption blocks.");
                    }

                    encryptor.TransformBlock(dataToEncrypt, 0, dataToEncrypt.Length, dataToEncrypt, 0);
                }

                for (int ii = 0; ii < dataToEncrypt.Length; ii++)
                {
                    encoder.WriteByte(null, dataToEncrypt[ii]);
                }

                for (int ii = 0; ii < signingKeySize; ii++)
                {
                    encoder.WriteByte(null, 0);
                }
            }

            var dataToSign = encoder.CloseAndReturnBuffer();

            dataToSign[lengthPosition++] = (byte)(dataToSign.Length & 0xFF);
            dataToSign[lengthPosition++] = (byte)((dataToSign.Length & 0xFF00)>>8);
            dataToSign[lengthPosition++] = (byte)((dataToSign.Length & 0xFF0000) >> 16);
            dataToSign[lengthPosition++] = (byte)((dataToSign.Length & 0xFF000000) >> 24);

            using (var hmac = new HMACSHA256(signingKey))
            {
                using (var istrm = new MemoryStream(dataToSign, 0, dataToSign.Length, false))
                {
                    byte[] signature = hmac.ComputeHash(istrm);

                    for (int ii = dataToSign.Length - signingKeySize; ii < dataToSign.Length; ii++)
                    {
                        dataToSign[ii] = signature[dataToSign.Length - signingKeySize + ii];
                    }
                }
            }

            return dataToSign;
        }
    }
}
