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

namespace Opc.Ua.Bindings
{
    /// <summary>
    /// Manages the server side of a UA TCP channel.
    /// </summary>
    public partial class UaSCUaBinaryChannel
    {
#if NET47

        private static ECDsa GetManualECDsaPublicKey(X509Certificate2 cert)
        {
            if (cert.GetKeyAlgorithm() != "1.2.840.10045.2.1")
            {
                return null;
            }

            const X509KeyUsageFlags SufficientFlags =
                X509KeyUsageFlags.KeyAgreement |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.CrlSign |
                X509KeyUsageFlags.KeyCertSign;

            foreach (X509Extension extension in cert.Extensions)
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

            PublicKey encodedPublicKey = cert.PublicKey;
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
                    ecParameters.Curve = ECCurve.NamedCurves.nistP256;
                    break;
                case "06-09-2B-24-03-03-02-08-01-01-07":
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP256r1;
                    break;
                default:
                    throw new NotImplementedException(keyParameters);
            }

            return ECDsa.Create(ecParameters);
        }
#endif
        /// <summary>
        /// Creates an ECDSA signature of a hash algorithm for the stream.
        /// </summary>
        private static byte[] Ecdsa_Sign(
            ArraySegment<byte> dataToSign,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
#if NET47
            var senderPrivateKey = signingCertificate.GetECDsaPrivateKey() as ECDsaCng;

            var signature = senderPrivateKey.SignData(dataToSign.Array, dataToSign.Offset, dataToSign.Count, HashAlgorithmName.SHA256);

            using (ECDsa ecdsa = GetManualECDsaPublicKey(new X509Certificate2(signingCertificate.RawData)))
            {
                if (!ecdsa.VerifyData(dataToSign.Array, dataToSign.Offset, dataToSign.Count, signature, algorithm))
                {
                    throw new Exception("Generated signature not valid.");
                }
            }

            return signature;
#else
            throw new NotSupportedException();
#endif
        }

        /// <summary>
        /// Verifies an ECDSA signature of a hash algorithm for the stream.
        /// </summary>
        private static bool Ecdsa_Verify(
            ArraySegment<byte> dataToVerify,
            byte[] signature,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
#if NET47

            using (ECDsa ecdsa = GetManualECDsaPublicKey(signingCertificate))
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

        /// <summary>
        /// Creates an RSA PKCS#1 v1.5 signature of a hash algorithm for the stream.
        /// </summary>
        private static byte[] RsaPkcs15_Sign(
            ArraySegment<byte> dataToSign,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
            RSA rsa = null;
            try
            {
                // extract the private key.
                rsa = signingCertificate.GetRSAPrivateKey();
                if (rsa == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No private key for certificate.");
                }

                // create the signature.
                return rsa.SignData(dataToSign.Array, dataToSign.Offset, dataToSign.Count, algorithm, RSASignaturePadding.Pkcs1);
            }
            finally
            {
                RsaUtils.RSADispose(rsa);
            }
        }

        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature of a hash algorithm for the stream.
        /// </summary>
        private static bool RsaPkcs15_Verify(
            ArraySegment<byte> dataToVerify,
            byte[] signature,
            X509Certificate2 signingCertificate,
            HashAlgorithmName algorithm)
        {
            RSA rsa = null;
            try
            {
                // extract the public key.
                rsa = signingCertificate.GetRSAPublicKey();
                if (rsa == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No public key for certificate.");
                }

                // verify signature.
                if (!rsa.VerifyData(dataToVerify.Array, dataToVerify.Offset, dataToVerify.Count, signature, algorithm, RSASignaturePadding.Pkcs1))
                {
                    string messageType = new UTF8Encoding().GetString(dataToVerify.Array, dataToVerify.Offset, 4);
                    int messageLength = BitConverter.ToInt32(dataToVerify.Array, dataToVerify.Offset + 4);
                    string actualSignature = Utils.ToHexString(signature);

                    Utils.Trace(
                        "Could not validate signature.\r\nCertificate={0}, MessageType={1}, Length={2}\r\nActualSignature={3}",
                        signingCertificate.Subject,
                        messageType,
                        messageLength,
                        actualSignature);

                    return false;
                }
                return true;
            }
            finally
            {
                RsaUtils.RSADispose(rsa);
            }
        }

        /// <summary>
        /// Encrypts the message using RSA PKCS#1 v1.5 encryption.
        /// </summary>
        private ArraySegment<byte> Rsa_Encrypt(
            ArraySegment<byte> dataToEncrypt,
            ArraySegment<byte> headerToCopy,
            X509Certificate2 encryptingCertificate,
            bool useOaep)
        {
            RSA rsa = null;
            try
            {
                // get the encrypting key.
                rsa = encryptingCertificate.GetRSAPublicKey();
                if (rsa == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No public key for certificate.");
                }

                int inputBlockSize = RsaUtils.GetPlainTextBlockSize(rsa, useOaep);
                int outputBlockSize = RsaUtils.GetCipherTextBlockSize(rsa, useOaep);

                // verify the input data is the correct block size.
                if (dataToEncrypt.Count % inputBlockSize != 0)
                {
                    Utils.Trace("Message is not an integral multiple of the block size. Length = {0}, BlockSize = {1}.", dataToEncrypt.Count, inputBlockSize);
                }

                byte[] encryptedBuffer = BufferManager.TakeBuffer(SendBufferSize, "Rsa_Encrypt");
                Array.Copy(headerToCopy.Array, headerToCopy.Offset, encryptedBuffer, 0, headerToCopy.Count);

                using (MemoryStream ostrm = new MemoryStream(
                    encryptedBuffer,
                    headerToCopy.Count,
                    encryptedBuffer.Length - headerToCopy.Count))
                {

                    // encrypt body.
                    byte[] input = new byte[inputBlockSize];

                    for (int ii = dataToEncrypt.Offset; ii < dataToEncrypt.Offset + dataToEncrypt.Count; ii += inputBlockSize)
                    {
                        Array.Copy(dataToEncrypt.Array, ii, input, 0, input.Length);
                        if (useOaep == true)
                        {
                            byte[] cipherText = rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA1);
                            ostrm.Write(cipherText, 0, cipherText.Length);
                        }
                        else
                        {
                            byte[] cipherText = rsa.Encrypt(input, RSAEncryptionPadding.Pkcs1);
                            ostrm.Write(cipherText, 0, cipherText.Length);
                        }
                    }
                }
                // return buffer
                return new ArraySegment<byte>(encryptedBuffer, 0, (dataToEncrypt.Count / inputBlockSize) * outputBlockSize + headerToCopy.Count);
            }
            finally
            {
                RsaUtils.RSADispose(rsa);
            }
        }

        /// <summary>
        /// Decrypts the message using RSA PKCS#1 v1.5 encryption.
        /// </summary>
        private ArraySegment<byte> Rsa_Decrypt(
            ArraySegment<byte> dataToDecrypt,
            ArraySegment<byte> headerToCopy,
            X509Certificate2 encryptingCertificate,
            bool useOaep)
        {
            RSA rsa = null;
            try
            {
                // get the encrypting key.
                rsa = encryptingCertificate.GetRSAPrivateKey();
                if (rsa == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadSecurityChecksFailed, "No private key for certificate.");
                }

                int inputBlockSize = RsaUtils.GetCipherTextBlockSize(rsa, useOaep);
                int outputBlockSize = RsaUtils.GetPlainTextBlockSize(rsa, useOaep);

                // verify the input data is the correct block size.
                if (dataToDecrypt.Count % inputBlockSize != 0)
                {
                    Utils.Trace("Message is not an integral multiple of the block size. Length = {0}, BlockSize = {1}.", dataToDecrypt.Count, inputBlockSize);
                }

                byte[] decryptedBuffer = BufferManager.TakeBuffer(SendBufferSize, "Rsa_Decrypt");
                Array.Copy(headerToCopy.Array, headerToCopy.Offset, decryptedBuffer, 0, headerToCopy.Count);

                using (MemoryStream ostrm = new MemoryStream(
                    decryptedBuffer,
                    headerToCopy.Count,
                    decryptedBuffer.Length - headerToCopy.Count))
                {

                    // decrypt body.
                    byte[] input = new byte[inputBlockSize];

                    for (int ii = dataToDecrypt.Offset; ii < dataToDecrypt.Offset + dataToDecrypt.Count; ii += inputBlockSize)
                    {
                        Array.Copy(dataToDecrypt.Array, ii, input, 0, input.Length);
                        if (useOaep == true)
                        {
                            byte[] plainText = rsa.Decrypt(input, RSAEncryptionPadding.OaepSHA1);
                            ostrm.Write(plainText, 0, plainText.Length);
                        }
                        else
                        {
                            byte[] plainText = rsa.Decrypt(input, RSAEncryptionPadding.Pkcs1);
                            ostrm.Write(plainText, 0, plainText.Length);
                        }
                    }
                }

                // return buffers.
                return new ArraySegment<byte>(decryptedBuffer, 0, (dataToDecrypt.Count / inputBlockSize) * outputBlockSize + headerToCopy.Count);
            }
            finally
            {
                RsaUtils.RSADispose(rsa);
            }
        }
    }
}
