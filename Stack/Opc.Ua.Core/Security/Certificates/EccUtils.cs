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
using System.Collections.Generic;
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

        public byte[] DeriveKey(Nonce remoteNonce, byte[] salt, HashAlgorithmName algorithm, int length)
        {
            #if NET47
            if (m_ecdh != null)
            {
                var secret = m_ecdh.DeriveKeyFromHmac(remoteNonce.m_ecdh.PublicKey, algorithm, salt, null, null);

                byte[] output = new byte[length];

                HMACSHA256 hmac = new HMACSHA256(secret);

                byte counter = 1;

                byte[] info = new byte[hmac.HashSize / 8 + salt.Length + 1];
                Buffer.BlockCopy(salt, 0, info, 0, salt.Length);
                info[salt.Length] = counter++;

                byte[] hash = hmac.ComputeHash(info, 0, salt.Length + 1);

                int pos = 0;

                for (int ii = 0; ii < hash.Length && pos < length; ii++)
                {
                    output[pos++] = hash[ii];
                }

                while (pos < length)
                {
                    Buffer.BlockCopy(hash, 0, info, 0, hash.Length);
                    Buffer.BlockCopy(salt, 0, info, hash.Length, salt.Length);
                    info[info.Length - 1] = counter++;

                    hash = hmac.ComputeHash(info, 0, info.Length);

                    for (int ii = 0; ii < hash.Length && pos < length; ii++)
                    {
                        output[pos++] = hash[ii];
                    }
                }

                return output;
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
            if (securityPolicyUri == null)
            {
                throw new ArgumentNullException("securityPolicyUri");
            }

            if (nonceData == null)
            {
                throw new ArgumentNullException("nonceData");
            }

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
        public static string[] GetSupportedSecurityPolicyUris(X509Certificate2 certificate)
        {
            string[] securityPolicyUris;

            if (GetPublicKey(certificate, out securityPolicyUris) == null)
            {
                return null;
            }

            return securityPolicyUris;
        }

        public static ECDsa GetPublicKey(X509Certificate2 certificate)
        {
            string[] securityPolicyUris;
            return GetPublicKey(certificate, out securityPolicyUris);
        }

        public static ECDsa GetPublicKey(X509Certificate2 certificate, out string[] securityPolicyUris)
        {
            securityPolicyUris = null;

            var keyAlgorithm = certificate.GetKeyAlgorithm();

            if (certificate == null || keyAlgorithm != "1.2.840.10045.2.1")
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
                    securityPolicyUris = new string[] { SecurityPolicies.Aes128_Sha256_nistP256 };
                    break;
                }

                case "06-05-2B-81-04-00-22":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.nistP384;
                    securityPolicyUris = new string[] { SecurityPolicies.Aes256_Sha384_nistP384, SecurityPolicies.Aes128_Sha256_nistP256 };
                    break;
                }

                case "06-09-2B-24-03-03-02-08-01-01-07":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP256r1;
                    securityPolicyUris = new string[] { SecurityPolicies.Aes128_Sha256_brainpoolP256r1 };
                    break;
                }
                case "06-09-2B-24-03-03-02-08-01-01-0B":
                {
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP384r1;
                    securityPolicyUris = new string[] { SecurityPolicies.Aes256_Sha384_brainpoolP384r1, SecurityPolicies.Aes128_Sha256_brainpoolP256r1 };
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
            using (var publicKey = GetPublicKey(signingCertificate))
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

        public static HashAlgorithmName GetSignatureAlgorithmName(string securityPolicyUri)
        {
            if (securityPolicyUri == null)
            {
                throw new ArgumentNullException("securityPolicyUri");
            }

            switch (securityPolicyUri)
            {
                case SecurityPolicies.Aes128_Sha256_nistP256:
                case SecurityPolicies.Aes128_Sha256_brainpoolP256r1:
                {
                    return HashAlgorithmName.SHA256;
                }

                case SecurityPolicies.Aes256_Sha384_nistP384:
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                {
                    return HashAlgorithmName.SHA384;
                }
            
                case SecurityPolicies.None:
                default:
                {
                    return HashAlgorithmName.SHA256;
                }
            }
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
            string securityPolicyUri)
        {
            var algorithm = GetSignatureAlgorithmName(securityPolicyUri);
            return Sign(dataToSign, signingCertificate, algorithm);
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
            string securityPolicyUri)
        {
            return Verify(dataToVerify, signature, signingCertificate, GetSignatureAlgorithmName(securityPolicyUri));
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

        public X509Certificate2Collection SenderIssuerCertificates { get; set; }

        public bool DoNotEncodeSenderCertificate { get; set; }

        public Nonce SenderNonce { get; set; }

        public Nonce ReceiverNonce { get; set; }

        public X509Certificate2 ReceiverCertificate { get; set; }

        public CertificateValidator Validator { get; set; }

        public string SecurityPolicyUri { get; set; }

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

        private ArraySegment<byte> DecryptSecret(
            byte[] dataToDecrypt,
            int offset,
            int count,
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

            ushort paddingSize = dataToDecrypt[offset + count - 1];
            paddingSize <<= 8;
            paddingSize += dataToDecrypt[offset + count - 2];

            int notvalid = (paddingSize < count)? 0: 1;
            int start = offset + count - paddingSize - 2;

            for (int ii = 0; ii < count - 2 && ii < paddingSize; ii++)
            {
                if (start < 0 || start + ii >= dataToDecrypt.Length)
                {
                    notvalid |= 1;
                    continue;
                }

                notvalid |= dataToDecrypt[start + ii] ^ (paddingSize & 0xFF);
            }

            if (notvalid != 0)
            {
                throw new ServiceResultException(StatusCodes.BadNonceInvalid);
            }

            return new ArraySegment<byte>(dataToDecrypt, offset, count - paddingSize);
        }

        static readonly byte[] s_Label = new UTF8Encoding().GetBytes("opcua-secret");

        private void CreateKeysForEcc(
            string securityPolicyUri,
            Nonce senderNonce,
            Nonce receiverNonce,
            bool forDecryption,
            out byte[] encryptingKey,
            out byte[] iv)
        {
            int encryptingKeySize = 32;
            int blockSize = 16;
            HashAlgorithmName algorithmName = HashAlgorithmName.SHA256;

            switch (securityPolicyUri)
            {
                case SecurityPolicies.Aes128_Sha256_nistP256:
                case SecurityPolicies.Aes128_Sha256_brainpoolP256r1:
                {
                    encryptingKeySize = 16;
                    break;
                }

                case SecurityPolicies.Aes256_Sha384_nistP384:
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                {
                    encryptingKeySize = 32;
                    algorithmName = HashAlgorithmName.SHA384;
                    break;
                }
            }

            encryptingKey = new byte[encryptingKeySize];
            iv = new byte[blockSize];

            var keyLength = BitConverter.GetBytes((ushort)(encryptingKeySize + blockSize));
            var salt = Utils.Append(keyLength, s_Label, senderNonce.Data, receiverNonce.Data);

            byte[] keyData = null;

            if (forDecryption)
            {
                keyData = receiverNonce.DeriveKey(senderNonce, salt, algorithmName, encryptingKeySize + blockSize);
            }
            else
            {
                keyData = senderNonce.DeriveKey(receiverNonce, salt, algorithmName, encryptingKeySize + blockSize);
            }

            Buffer.BlockCopy(keyData, 0, encryptingKey, 0, encryptingKey.Length);
            Buffer.BlockCopy(keyData, encryptingKeySize, iv, 0, iv.Length);
        }

        public byte[] Encrypt(byte[] secret, byte[] nonce)
        {
            byte[] encryptingKey = null;
            byte[] iv = null;
            byte[] message = null;
            int lengthPosition = 0;

            var signatureLength = EccUtils.GetSignatureLength(SenderCertificate);

            using (BinaryEncoder encoder = new BinaryEncoder(ServiceMessageContext.GlobalContext))
            {
                // write header.
                encoder.WriteNodeId(null, DataTypeIds.EccEncryptedSecret);
                encoder.WriteByte(null, (byte)ExtensionObjectEncoding.Binary);

                lengthPosition = encoder.Position;
                encoder.WriteUInt32(null, 0);

                encoder.WriteString(null, SecurityPolicyUri);

                byte[] senderCertificate = null;

                if (!DoNotEncodeSenderCertificate)
                {
                    senderCertificate = SenderCertificate.RawData;

                    if (SenderIssuerCertificates != null && SenderIssuerCertificates.Count > 0)
                    {
                        int blobSize = senderCertificate.Length;

                        foreach (var issuer in SenderIssuerCertificates)
                        {
                            blobSize += issuer.RawData.Length;
                        }

                        var blob = new byte[blobSize];
                        Buffer.BlockCopy(senderCertificate, 0, blob, 0, senderCertificate.Length);

                        int pos = senderCertificate.Length;

                        foreach (var issuer in SenderIssuerCertificates)
                        {
                            var data = issuer.RawData;
                            Buffer.BlockCopy(data, 0, blob, pos, data.Length);
                            pos += data.Length;
                        }

                        senderCertificate = blob;
                    }
                }

                encoder.WriteByteString(null, senderCertificate);
                encoder.WriteDateTime(null, DateTime.UtcNow);

                var senderNonce = SenderNonce.Data;
                var receiverNonce = ReceiverNonce.Data;

                encoder.WriteUInt16(null, (ushort)(senderNonce.Length + receiverNonce.Length + 8));
                encoder.WriteByteString(null, senderNonce);
                encoder.WriteByteString(null, receiverNonce);

                // create keys.
                if (EccUtils.IsEccPolicy(SecurityPolicyUri))
                {
                    CreateKeysForEcc(SecurityPolicyUri, SenderNonce, ReceiverNonce, false, out encryptingKey, out iv);
                }

                // encrypt  secret,
                var encryptedData = EncryptSecret(secret, nonce, encryptingKey, iv);

                // append encrypted secret.
                for (int ii = 0; ii < encryptedData.Length; ii++)
                {
                    encoder.WriteByte(null, encryptedData[ii]);
                }

                // save space for signature.
                for (int ii = 0; ii < signatureLength; ii++)
                {
                    encoder.WriteByte(null, 0);
                }

                message = encoder.CloseAndReturnBuffer();
            }

            var length = message.Length - lengthPosition - 4;

            message[lengthPosition++] = (byte)((length & 0xFF));
            message[lengthPosition++] = (byte)((length & 0xFF00) >> 8);
            message[lengthPosition++] = (byte)((length & 0xFF0000) >> 16);
            message[lengthPosition++] = (byte)((length & 0xFF000000) >> 24);

            // get the algorithm used for the signature.
            HashAlgorithmName signatureAlgorithm = HashAlgorithmName.SHA256;

            switch (SecurityPolicyUri)
            {
                case SecurityPolicies.Aes256_Sha384_nistP384:
                case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                {
                    signatureAlgorithm = HashAlgorithmName.SHA384;
                    break;
                }
            }

            #if NET47
            var senderPrivateKey = SenderCertificate.GetECDsaPrivateKey() as ECDsaCng;

            if (senderPrivateKey == null)
            {
                throw new ServiceResultException(StatusCodes.BadCertificateInvalid, "Missing private key needed for creating a signature.");
            }

            using (senderPrivateKey)
            {
                var signature = senderPrivateKey.SignData(message, 0, message.Length - signatureLength, signatureAlgorithm);

                for (int ii = 0; ii < signatureLength; ii++)
                {
                    message[ii + message.Length - signatureLength] = signature[ii];
                }
            }

            return message;
            #else
            throw new NotImplementedException();
            #endif
        }

        private ArraySegment<byte> VerifyHeaderForEcc(
            ArraySegment<byte> dataToDecrypt,
            DateTime earliestTime)
        {
            using (BinaryDecoder decoder = new BinaryDecoder(dataToDecrypt.Array, dataToDecrypt.Offset, dataToDecrypt.Count, ServiceMessageContext.GlobalContext))
            {
                var typeId = decoder.ReadNodeId(null);

                if (typeId != DataTypeIds.EccEncryptedSecret)
                {
                    throw new ServiceResultException(StatusCodes.BadDataTypeIdUnknown);
                }

                var encoding = (ExtensionObjectEncoding)decoder.ReadByte(null);

                if (encoding != ExtensionObjectEncoding.Binary)
                {
                    throw new ServiceResultException(StatusCodes.BadDataEncodingUnsupported);
                }

                var length = decoder.ReadUInt32(null);

                // get the start of data.
                int startOfData = decoder.Position + dataToDecrypt.Offset;

                SecurityPolicyUri = decoder.ReadString(null);

                if (!EccUtils.IsEccPolicy(SecurityPolicyUri))
                {
                    throw new ServiceResultException(StatusCodes.BadSecurityPolicyRejected);
                }

                // get the algorithm used for the signature.
                HashAlgorithmName signatureAlgorithm = HashAlgorithmName.SHA256;

                switch (SecurityPolicyUri)
                {
                    case SecurityPolicies.Aes256_Sha384_nistP384:
                    case SecurityPolicies.Aes256_Sha384_brainpoolP384r1:
                        {
                            signatureAlgorithm = HashAlgorithmName.SHA384;
                            break;
                        }
                }

                // extract the send certificate and any chain.
                var senderCertificate = decoder.ReadByteString(null);

                if (senderCertificate == null || senderCertificate.Length == 0)
                {
                    if (SenderCertificate == null)
                    {
                        throw new ServiceResultException(StatusCodes.BadCertificateInvalid);
                    }
                }
                else
                { 
                    var senderCertificateChain = Utils.ParseCertificateChainBlob(senderCertificate);

                    SenderCertificate = senderCertificateChain[0];
                    SenderIssuerCertificates = new X509Certificate2Collection();

                    for (int ii = 1; ii < senderCertificateChain.Count; ii++)
                    {
                        SenderIssuerCertificates.Add(senderCertificateChain[ii]);
                    }

                    // validate the sender.
                    if (Validator != null)
                    {
                        Validator.Validate(senderCertificateChain);
                    }
                }

                // extract the send certificate and any chain.
                var signingTime = decoder.ReadDateTime(null);

                if (signingTime < earliestTime)
                {
                    throw new ServiceResultException(StatusCodes.BadInvalidTimestamp);
                }

                // extract the policy header.
                var headerLength = decoder.ReadUInt16(null);

                if (headerLength == 0 || headerLength > length)
                {
                    throw new ServiceResultException(StatusCodes.BadDecodingError);
                }

                // read the policy header.
                var senderPublicKey = decoder.ReadByteString(null);
                var receiverPublicKey = decoder.ReadByteString(null);

                if (headerLength != senderPublicKey.Length + receiverPublicKey.Length + 8)
                {
                    throw new ServiceResultException(StatusCodes.BadDecodingError, "Unexpected policy header length");
                }

                var startOfEncryption = decoder.Position;

                SenderNonce = Nonce.CreateNonce(SecurityPolicyUri, senderPublicKey);

                if (!Utils.IsEqual(receiverPublicKey, ReceiverNonce.Data))
                { 
                    throw new ServiceResultException(StatusCodes.BadDecodingError, "Unexpected receiver nonce.");
                }

                // check the signature.
                int signatureLength = EccUtils.GetSignatureLength(SenderCertificate);

                if (signatureLength >= length)
                {
                    throw new ServiceResultException(StatusCodes.BadDecodingError);
                }

                byte[] signature = new byte[signatureLength];
                Buffer.BlockCopy(dataToDecrypt.Array, startOfData + (int)length - signatureLength, signature, 0, signatureLength);

                #if NET47
                using (ECDsa ecdsa = EccUtils.GetPublicKey(SenderCertificate))
                {
                    if (!ecdsa.VerifyData(dataToDecrypt.Array, dataToDecrypt.Offset, dataToDecrypt.Count - signatureLength, signature, signatureAlgorithm))
                    {
                        throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Could not verify signature.");
                    }
                }

                // extract the encrypted data.
                return new ArraySegment<byte>(dataToDecrypt.Array, startOfEncryption, (int)length - (startOfEncryption - startOfData + signatureLength));
                #else
                throw new NotImplementedException();
                #endif
            }
        }

        public byte[] Decrypt(DateTime earliestTime, byte[] expectedNonce, byte[] data, int offset, int count)
        {
            byte[] encryptingKey = null;
            byte[] iv = null;
            byte[] secret = null;

            var dataToDecrypt = VerifyHeaderForEcc(new ArraySegment<byte>(data, offset, count), earliestTime);

            CreateKeysForEcc(SecurityPolicyUri, SenderNonce, ReceiverNonce, true, out encryptingKey, out iv);
       
            var plainText = DecryptSecret(dataToDecrypt.Array, dataToDecrypt.Offset, dataToDecrypt.Count, encryptingKey, iv);

            using (BinaryDecoder decoder = new BinaryDecoder(plainText.Array, plainText.Offset, plainText.Count, ServiceMessageContext.GlobalContext))
            {
                var actualNonce = decoder.ReadByteString(null);

                if (expectedNonce != null && expectedNonce.Length > 0)
                {
                    int notvalid = (expectedNonce.Length == actualNonce.Length) ? 0 : 1;

                    for (int ii = 0; ii < expectedNonce.Length && ii < actualNonce.Length; ii++)
                    {
                        notvalid |= expectedNonce[ii] ^ actualNonce[ii];
                    }

                    if (notvalid != 0)
                    {
                        throw new ServiceResultException(StatusCodes.BadNonceInvalid);
                    }
                }

                secret = decoder.ReadByteString(null);
            }

            return secret;
        }
    }
}
