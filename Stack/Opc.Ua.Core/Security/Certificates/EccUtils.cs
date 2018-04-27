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
                    curve = new ECCurve();
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
        public static bool IsEccPolicy(string securityPolicyUri)
        {
            if (securityPolicyUri != null)
            {
                switch (securityPolicyUri)
                {
                    case SecurityPolicies.Aes128_Sha256_nistP256:
                    case SecurityPolicies.Aes256_Sha384_nistP384:
                    case SecurityPolicies.Aes128_Sha256_brainpoolP256r1:
                    case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                    {
                        return true;
                    }
                }
            }

            return false;
        }

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

        private byte[] EncryptSecret(
            byte[] secret,
            byte[] nonce,
            byte[] encryptingKey,
            byte[] iv)
        {
            byte[] dataToEncrypt = null;

            using (var encoder = new BinaryEncoder(ServiceMessageContext.GlobalContext))
            {
                encoder.WriteByteString(null, nonce);
                encoder.WriteByteString(null, secret);

                int paddingSize = (iv.Length - ((encoder.Position + 2) % iv.Length));
                paddingSize %= iv.Length;

                for (int ii = 0; ii < paddingSize; ii++)
                {
                    encoder.WriteByte(null, (byte)(paddingSize & 0xFF));
                }

                encoder.WriteUInt16(null, (ushort)paddingSize);

                dataToEncrypt = encoder.CloseAndReturnBuffer();
            }

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
            }

            return dataToEncrypt;
        }

        private byte[] DecryptSecret(
            byte[] dataToDecrypt,
            int offset,
            int count,
            byte[] nonce,
            byte[] encryptingKey,
            byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = encryptingKey;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    if (count % decryptor.InputBlockSize != 0)
                    {
                        throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "Input data is not an even number of encryption blocks.");
                    }

                    decryptor.TransformBlock(dataToDecrypt, offset, count, dataToDecrypt, offset);
                }
            }

            byte[] receivedNonce = null;
            byte[] secret = null;

            using (var decoder = new BinaryDecoder(dataToDecrypt, offset, count, ServiceMessageContext.GlobalContext))
            {
                receivedNonce = decoder.ReadByteString(null);
                secret = decoder.ReadByteString(null);
            }

            int notvalid = (receivedNonce.Length == nonce.Length) ? 0 : 1;

            for (int ii = 0; ii < nonce.Length && ii < receivedNonce.Length; ii++)
            {
                notvalid |= receivedNonce[ii] ^ nonce[ii];
            }

            ushort paddingSize = dataToDecrypt[offset + count - 1];
            paddingSize <<= 8;
            paddingSize += dataToDecrypt[offset + count - 2];

            notvalid |= (count - nonce.Length - paddingSize - 8 >= 0) ? 0 : 1;

            int start = offset + count - paddingSize - 2;

            for (int ii = 0; ii < count - 2 && ii < paddingSize; ii++)
            {
                notvalid |= dataToDecrypt[start + ii] ^ (paddingSize & 0xFF);
            }

            if (notvalid != 0)
            {
                throw new ServiceResultException(StatusCodes.BadNonceInvalid);
            }

            return secret;
        }

        private byte[] CreateKeysForRsa(
            string securityPolicyUri,
            X509Certificate2 certificate,
            out byte[] signingKey,
            out byte[] encryptingKey,
            out byte[] iv)
        {
            uint signingKeySize = 32;
            uint encryptingKeySize = 32;
            uint blockSize = 16;
            var algorithmName = HashAlgorithmName.SHA256;

            byte[] plainText = null;

            using (BinaryEncoder encoder = new BinaryEncoder(ServiceMessageContext.GlobalContext))
            {
                signingKey = Utils.Nonce.CreateNonce(signingKeySize);
                encoder.WriteByteString(null, signingKey);

                encryptingKey = Utils.Nonce.CreateNonce(encryptingKeySize);
                encoder.WriteByteString(null, encryptingKey);

                iv = Utils.Nonce.CreateNonce(blockSize);
                encoder.WriteByteString(null, iv);

                plainText = encoder.CloseAndReturnBuffer();
            }

            byte[] cipherText = null;

            using (var rsa = certificate.GetRSAPublicKey())
            {
                cipherText = rsa.Encrypt(plainText, RSAEncryptionPadding.OaepSHA256);
            }

            return cipherText;
        }

        private void ExtractKeysForRsa(
            string securityPolicyUri,
            X509Certificate2 certificate,
            byte[] policyHeader,
            out byte[] signingKey,
            out byte[] encryptingKey,
            out byte[] iv,
            out HashAlgorithmName algorithmName)
        {
            int signingKeySize = 32;
            int encryptingKeySize = 32;
            int blockSize = 16;
            algorithmName = HashAlgorithmName.SHA256;

            byte[] plainText = null;

            using (var rsa = certificate.GetRSAPrivateKey())
            {
                plainText = rsa.Decrypt(policyHeader, RSAEncryptionPadding.OaepSHA256);
            }

            using (BinaryDecoder decoder = new BinaryDecoder(plainText, 0, plainText.Length, ServiceMessageContext.GlobalContext))
            {
                signingKey = decoder.ReadByteString(null);
                encryptingKey = decoder.ReadByteString(null);
                iv = decoder.ReadByteString(null);
            }

            if (signingKey.Length != signingKeySize)
            {
                throw new ServiceResultException(StatusCodes.BadDecodingError);
            }

            if (encryptingKey.Length != encryptingKeySize)
            {
                throw new ServiceResultException(StatusCodes.BadDecodingError);
            }

            if (iv.Length != blockSize)
            {
                throw new ServiceResultException(StatusCodes.BadDecodingError);
            }
        }

        private void CreateKeysForEcc(
            string securityPolicyUri,
            Nonce localNonce,
            Nonce remoteNonce,
            out byte[] signingKey,
            out byte[] encryptingKey,
            out byte[] iv,
            out HashAlgorithmName algorithmName)
        {
            int signingKeySize = 32;
            int encryptingKeySize = 32;
            int blockSize = 16;
            algorithmName = HashAlgorithmName.SHA256;

            switch (securityPolicyUri)
            {
                case SecurityPolicies.Aes128_Sha256_nistP256:
                case SecurityPolicies.Aes128_Sha256_brainpoolP256r1:
                {
                    signingKeySize = 32;
                    encryptingKeySize = 16;
                    break;
                }

                case SecurityPolicies.Aes256_Sha384_nistP384:
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                {
                    signingKeySize = 48;
                    encryptingKeySize = 32;
                    algorithmName = HashAlgorithmName.SHA384;
                    break;
                }
            }

            signingKey = new byte[signingKeySize];
            encryptingKey = new byte[encryptingKeySize];
            iv = new byte[blockSize];

            var clientSecret = localNonce.DeriveKeyFromHmac(remoteNonce, "client", algorithmName);
            var serverSecret = localNonce.DeriveKeyFromHmac(remoteNonce, "server", algorithmName);

            using (var hmac = Utils.CreateHMAC(algorithmName, clientSecret))
            {
                var keyData = Utils.PSHA(hmac, null, serverSecret, 0, signingKeySize + encryptingKeySize + blockSize);

                Buffer.BlockCopy(keyData, 0, signingKey, 0, signingKey.Length);
                Buffer.BlockCopy(keyData, signingKeySize, encryptingKey, 0, encryptingKey.Length);
                Buffer.BlockCopy(keyData, signingKeySize + encryptingKeySize, iv, 0, iv.Length);
            }
        }

        public byte[] Encrypt(string securityPolicyUri, byte[] secret)
        {
            byte[] signingKey = null;
            byte[] encryptingKey = null;
            byte[] iv = null;
            byte[] dataToSign = null;
            int lengthPosition = 0;
            HashAlgorithmName algorithmName;

            using (BinaryEncoder encoder = new BinaryEncoder(ServiceMessageContext.GlobalContext))
            {
                // write header.
                encoder.WriteNodeId(null, new NodeId(100000));
                encoder.WriteByte(null, (byte)ExtensionObjectEncoding.Binary);

                lengthPosition = encoder.Position;
                encoder.WriteUInt32(null, 0);

                encoder.WriteString(null, securityPolicyUri);
                encoder.WriteByteString(null, RecipientNonce.Data);
                encoder.WriteDateTime(null, DateTime.UtcNow);

                var senderNonce = SenderNonce.Data;
                encoder.WriteUInt16(null, (ushort)senderNonce.Length);
                
                for (int ii = 0; ii < senderNonce.Length; ii++)
                {
                    encoder.WriteByte(null, senderNonce[ii]);
                }

                // create keys.
                CreateKeysForEcc(securityPolicyUri, SenderNonce, RecipientNonce, out signingKey, out encryptingKey, out iv, out algorithmName);

                // encrypt  secret,
                var encryptedData = EncryptSecret(secret, RecipientNonce.Data, encryptingKey, iv);

                // append encrypted secret.
                for (int ii = 0; ii < encryptedData.Length; ii++)
                {
                    encoder.WriteByte(null, encryptedData[ii]);
                }

                // save space for signature.
                for (int ii = 0; ii < signingKey.Length; ii++)
                {
                    encoder.WriteByte(null, 0);
                }

                dataToSign = encoder.CloseAndReturnBuffer();
            }

            var length = dataToSign.Length - lengthPosition - 4;

            dataToSign[lengthPosition++] = (byte)((length & 0xFF));
            dataToSign[lengthPosition++] = (byte)((length & 0xFF00) >> 8);
            dataToSign[lengthPosition++] = (byte)((length & 0xFF0000) >> 16);
            dataToSign[lengthPosition++] = (byte)((length & 0xFF000000) >> 24);

            using (var hmac = Utils.CreateHMAC(algorithmName, signingKey))
            {
                using (var istrm = new MemoryStream(dataToSign, 0, dataToSign.Length - signingKey.Length, false))
                {
                    byte[] signature = hmac.ComputeHash(istrm);

                    for (int ii = 0; ii < signingKey.Length; ii++)
                    {
                        dataToSign[dataToSign.Length - signingKey.Length + ii] = signature[ii];
                    }
                }
            }

            return dataToSign;
        }

        private byte[] DecryptHeader(
            BinaryDecoder decoder,
            NodeId expectedTypeId,
            int expectedLength,
            string securityPolicyUri,
            DateTime earliestTime,
            byte[] recipientIdentifier)
        {
            var typeId = decoder.ReadNodeId(null);

            if (!NodeId.IsNull(expectedTypeId) && typeId != expectedTypeId)
            {
                throw new ServiceResultException(StatusCodes.BadDataTypeIdUnknown);
            }

            var encoding = (ExtensionObjectEncoding)decoder.ReadByte(null);

            if (encoding != ExtensionObjectEncoding.Binary)
            {
                throw new ServiceResultException(StatusCodes.BadDataEncodingUnsupported);
            }

            var length = decoder.ReadUInt32(null);

            if (expectedLength > 0 && length != expectedLength - decoder.Position)
            {
                throw new ServiceResultException(StatusCodes.BadDecodingError);
            }

            var actualSecurityPolicyUri = decoder.ReadString(null);

            if (securityPolicyUri != actualSecurityPolicyUri)
            {
                throw new ServiceResultException(StatusCodes.BadSecurityPolicyRejected);
            }

            var identifier = decoder.ReadByteString(null);

            if (recipientIdentifier.Length != identifier.Length)
            {
                throw new ServiceResultException(StatusCodes.BadNonceInvalid);
            }

            for (int ii = 0; ii < identifier.Length; ii++)
            {
                if (recipientIdentifier[ii] != identifier[ii])
                {
                    throw new ServiceResultException(StatusCodes.BadNonceInvalid);
                }
            }

            var timestamp = decoder.ReadDateTime(null);

            if (earliestTime != DateTime.MinValue && earliestTime > timestamp)
            {
                throw new ServiceResultException(StatusCodes.BadInvalidTimestamp);
            }

            var headerLength = decoder.ReadUInt16(null);

            if (headerLength > expectedLength - decoder.Position)
            {
                throw new ServiceResultException(StatusCodes.BadDecodingError);
            }

            var header = new byte[headerLength];

            for (int ii = 0; ii < header.Length; ii++)
            {
                header[ii] = decoder.ReadByte(null);
            }

            return header;

        }

        public byte[] Decrypt(string securityPolicyUri, DateTime earliestTime, byte[] dataToDecrypt, int offset, int count)
        {
            byte[] signingKey = null;
            byte[] encryptingKey = null;
            byte[] iv = null;
            byte[] secret = null;
            HashAlgorithmName algorithmName;

            using (BinaryDecoder decoder = new BinaryDecoder(dataToDecrypt, offset, count, ServiceMessageContext.GlobalContext))
            {
                bool isEcc = EccUtils.IsEccPolicy(securityPolicyUri);

                byte[] recipientIdentifier = Utils.FromHexString(RecipientCertificate.Thumbprint);

                if (isEcc)
                {
                    recipientIdentifier = RecipientNonce.Data;
                }
                else
                {
                    recipientIdentifier = Utils.FromHexString(RecipientCertificate.Thumbprint);
                }

                var policyHeader = DecryptHeader(decoder, null, count, securityPolicyUri, earliestTime, recipientIdentifier);

                if (isEcc)
                {
                    SenderNonce = Nonce.CreateNonce(securityPolicyUri, policyHeader);
                    CreateKeysForEcc(securityPolicyUri, RecipientNonce, SenderNonce, out signingKey, out encryptingKey, out iv, out algorithmName);
                }
                else
                {
                    ExtractKeysForRsa(securityPolicyUri, RecipientCertificate, policyHeader, out signingKey, out encryptingKey, out iv, out algorithmName);
                }
                
                // create keys.
                using (var hmac = Utils.CreateHMAC(algorithmName, signingKey))
                {
                    using (var istrm = new MemoryStream(dataToDecrypt, offset, count - signingKey.Length, false))
                    {
                        byte[] signature = hmac.ComputeHash(istrm);

                        int notvalid = 0;

                        for (int ii = 0; ii < signingKey.Length; ii++)
                        {
                            notvalid |= dataToDecrypt[offset + count - signingKey.Length + ii] ^ signature[ii];
                        }

                        if (notvalid != 0)
                        {
                            throw new ServiceResultException(StatusCodes.BadUserSignatureInvalid);
                        }
                    }
                }
                
                // decrypt secret.
                var localNonce = RecipientNonce.Data;
                secret = DecryptSecret(dataToDecrypt, decoder.Position, (int)(count - signingKey.Length - decoder.Position), localNonce, encryptingKey, iv);
            }
            
            return secret;
        }
    }
}
