using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MHalo.CoreFx.Helper.RSAExtensions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;

namespace MHalo.CoreFx.Helper
{
    /// <summary>
    /// RAS加密
    /// <para>公钥加密 -> 私钥解密</para>
    /// <para>私钥加密 -> 私钥解密</para>
    /// </summary>
    public static class RSAHelper
    {
        public static class XMLRSAKeyManager
        {
            private static Dictionary<string, RSAParameters> cachedRSAParameters = new();

            public static RSAParameters GetRSAPrivateParameters(string privateKeyContent)
            {
                if (cachedRSAParameters.TryGetValue(privateKeyContent, out RSAParameters rsaParams))
                {
                    return rsaParams;
                }
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(privateKeyContent);
                    rsaParams = rsa.ExportParameters(true);
                    cachedRSAParameters[privateKeyContent] = rsaParams;
                }
                return rsaParams;
            }
            public static RSAParameters GetRSAPublicParameters(string publicKeyContent)
            {
                if (cachedRSAParameters.TryGetValue(publicKeyContent, out RSAParameters rsaParams))
                {
                    return rsaParams;
                }
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKeyContent);
                    rsaParams = rsa.ExportParameters(false);
                    cachedRSAParameters[publicKeyContent] = rsaParams;
                }
                return rsaParams;
            }
        }

        /// <summary>
        /// 创建RSA
        /// </summary>
        /// <returns></returns>
        public static RSA Create()
        {
            return RSA.Create();
        }

        /// <summary>
        /// 创建RSA
        /// </summary>
        /// <param name="keySizeInBits">512/1024/2048/</param>
        /// <returns></returns>
        public static RSA Create(int keySizeInBits)
        {
            return RSA.Create(keySizeInBits);
        }

        /// <summary>
        /// 生成xml公钥/私钥
        /// </summary>
        /// <param name="keySizeInBits">长度</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        public static void ExportXMLKey(int keySizeInBits, out string publicKey, out string privateKey)
        {
            var rsa = Create(keySizeInBits);
            privateKey = rsa.ExportPrivateKey(RSAKeyType.Xml);
            publicKey = rsa.ExportPublicKey(RSAKeyType.Xml);
        }

        /// <summary>
        /// 生成Pkcs8公钥/私钥
        /// </summary>
        /// <param name="keySizeInBits">长度</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="usePemFormat">是否使用pem格式</param>
        public static void ExportPkcs8Key(int keySizeInBits, out string publicKey, out string privateKey, bool usePemFormat = false)
        {
            var rsa = Create(keySizeInBits);
            privateKey = rsa.ExportPrivateKey(RSAKeyType.Pkcs8, usePemFormat);
            publicKey = rsa.ExportPublicKey(RSAKeyType.Pkcs8, usePemFormat);
        }

        /// <summary>
        /// 生成Pkcs1公钥/私钥
        /// </summary>
        /// <param name="keySizeInBits">长度</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="usePemFormat">是否使用pem格式</param>
        public static void ExportPkcs1Key(int keySizeInBits, out string publicKey, out string privateKey, bool usePemFormat = false)
        {
            var rsa = Create(keySizeInBits);
            privateKey = rsa.ExportPrivateKey(RSAKeyType.Pkcs1, usePemFormat);
            publicKey = rsa.ExportPublicKey(RSAKeyType.Pkcs1, usePemFormat);
        }

        /// <summary>
        /// 公钥加密<para/>
        /// </summary>
        /// <param name="keyType">密钥类型</param>
        /// <param name="content">加密内容</param>
        /// <param name="publicKeyContent">公钥</param>
        /// <param name="cipherAlgorithm">
        /// 算法<para/>
        /// 支持的算法有：<para/>
        /// RSA/ECB/PKCS1Padding: 使用PKCS#1 v1.5填充方案的RSA加密。这个是最常用的填充方式。<para/>
        /// RSA/ECB/OAEPWithSHA-1AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-1，掩码生成函数是MGF1。<para/>
        /// RSA/ECB/OAEPWithSHA-256AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-256，掩码生成函数是MGF1。<para/>
        /// </param>
        /// <returns>加密后的字符</returns>
        public static string Encrypt(RSAKeyType keyType, string content, string publicKeyContent, CipherAlgorithm cipherAlgorithm = CipherAlgorithm.RSA_ECB_PKCS1Padding)
        {
            AsymmetricKeyParameter publicKeyParameter;
            if (keyType.Equals(RSAKeyType.Pkcs1))
            {
                publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                // 创建RSA公钥参数
                publicKeyParameter = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            }
            else if (keyType.Equals(RSAKeyType.Pkcs8))
            {
                publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                publicKeyParameter = PublicKeyFactory.CreateKey(keyByte);
            }
            else
            {
                // 获取RSA参数
                RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPublicParameters(publicKeyContent);
                // 创建RsaKeyParameters
                publicKeyParameter = new RsaKeyParameters(false, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.Exponent));
            }

            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(true, publicKeyParameter);
            byte[] byteData = Encoding.UTF8.GetBytes(content);
            byteData = cipher.DoFinal(byteData, 0, byteData.Length);
            return Convert.ToBase64String(byteData);
        }

        /// <summary>
        /// 私钥解密<para/>
        /// </summary>
        /// <param name="keyType">密钥类型</param>
        /// <param name="content">加密内容</param>
        /// <param name="privateKeyContent">私钥</param>
        /// <param name="cipherAlgorithm">
        /// 算法<para/>
        /// 支持的算法有：<para/>
        /// RSA/ECB/PKCS1Padding: 使用PKCS#1 v1.5填充方案的RSA加密。这个是最常用的填充方式。<para/>
        /// RSA/ECB/OAEPWithSHA-1AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-1，掩码生成函数是MGF1。<para/>
        /// RSA/ECB/OAEPWithSHA-256AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-256，掩码生成函数是MGF1。<para/>
        /// </param>
        /// <returns>解密后的原文</returns>
        public static string Decrypt(RSAKeyType keyType, string content, string privateKeyContent, CipherAlgorithm cipherAlgorithm = CipherAlgorithm.RSA_ECB_PKCS1Padding)
        {
            AsymmetricKeyParameter privateKeyParameter;
            if (keyType.Equals(RSAKeyType.Pkcs1))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);

                RsaPrivateKeyStructure privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                // 创建RSA公钥参数
                privateKeyParameter = new RsaKeyParameters(true, privateKeyStructure.Modulus, privateKeyStructure.PrivateExponent);

            }
            else if (keyType.Equals(RSAKeyType.Pkcs8))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);
                privateKeyParameter = PrivateKeyFactory.CreateKey(keyByte);
            }
            else
            {
                // 获取RSA参数
                RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPrivateParameters(privateKeyContent);
                // 创建RsaKeyParameters
                privateKeyParameter = new RsaKeyParameters(true, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.D));
            }

            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(false, privateKeyParameter);
            byte[] byteData = Convert.FromBase64String(content);
            byteData = cipher.DoFinal(byteData, 0, byteData.Length);
            return Encoding.UTF8.GetString(byteData);
        }

        /// <summary>
        /// 私钥签名
        /// <para>privateKey</para>
        /// </summary>
        /// <param name="keyType">密钥类型</param>
        /// <param name="data">签名内容</param>
        /// <param name="privateKeyContent">私钥</param>
        /// <param name="signerAlgorithm">
        /// 算法<para/>
        /// 支持的算法有：<para/>
        /// SHA1withRSA,<para/>
        /// SHA256withRSA,<para/>
        /// SHA384withRSA,<para/>
        /// SHA512withRSA,<para/>
        /// SHA1withECDSA,<para/>
        /// SHA224withECDSA,<para/>
        /// SHA256withECDSA,<para/>
        /// SHA384withECDSA,<para/>
        /// SHA512withECDSA,<para/>
        /// MD5withRSA
        /// </param>
        /// <returns></returns>
        public static string SignData(RSAKeyType keyType, string data, string privateKeyContent, SignerAlgorithm signerAlgorithm =  SignerAlgorithm.SHA256withRSA)
        {
            AsymmetricKeyParameter privateKeyParameter;
            if (keyType.Equals(RSAKeyType.Pkcs1))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);

                RsaPrivateKeyStructure privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                // 创建RSA公钥参数
                privateKeyParameter = new RsaKeyParameters(true, privateKeyStructure.Modulus, privateKeyStructure.PrivateExponent);

            }
            else if (keyType.Equals(RSAKeyType.Pkcs8))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);
                privateKeyParameter = PrivateKeyFactory.CreateKey(keyByte);
            }
            else
            {
                // 获取RSA参数
                RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPrivateParameters(privateKeyContent);
                // 创建RsaKeyParameters
                privateKeyParameter = new RsaKeyParameters(true, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.D));
            }

            var inputData = Encoding.UTF8.GetBytes(data);
            var signer = SignerUtilities.GetSigner(signerAlgorithm.ToString());
            signer.Init(true, privateKeyParameter);
            signer.BlockUpdate(inputData, 0, inputData.Length);
            return Convert.ToBase64String(signer.GenerateSignature());
        }
        /// <summary>
        /// 公钥验签
        /// <para>publicKey</para>
        /// </summary>
        /// <param name="keyType">密钥类型</param>
        /// <param name="data">验签内容</param>
        /// <param name="sign">签名</param>
        /// <param name="publicKeyContent">公钥</param>
        /// <param name="signerAlgorithm">
        /// 算法<para/>
        /// 支持的算法有：<para/>
        /// SHA1withRSA,<para/>
        /// SHA256withRSA,<para/>
        /// SHA384withRSA,<para/>
        /// SHA512withRSA,<para/>
        /// SHA1withECDSA,<para/>
        /// SHA224withECDSA,<para/>
        /// SHA256withECDSA,<para/>
        /// SHA384withECDSA,<para/>
        /// SHA512withECDSA,<para/>
        /// MD5withRSA
        /// </param>
        /// <returns></returns>
        public static bool VertifyData(RSAKeyType keyType, string data, string sign, string publicKeyContent, SignerAlgorithm signerAlgorithm = SignerAlgorithm.SHA256withRSA)
        {
            try
            {
                AsymmetricKeyParameter publicKeyParameter;
                if (keyType.Equals(RSAKeyType.Pkcs1))
                {
                    publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                    byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                    RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                    // 创建RSA公钥参数
                    publicKeyParameter = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

                }
                else if (keyType.Equals(RSAKeyType.Pkcs8))
                {
                    publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                    byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                    publicKeyParameter = PublicKeyFactory.CreateKey(keyByte);
                }
                else
                {
                    // 获取RSA参数
                    RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPublicParameters(publicKeyContent);
                    // 创建RsaKeyParameters
                    publicKeyParameter = new RsaKeyParameters(false, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.Exponent));
                }

                var signByte = Convert.FromBase64String(sign);
                var signer = SignerUtilities.GetSigner(signerAlgorithm.ToString());
                var inputData = Encoding.UTF8.GetBytes(data);
                signer.Init(false, publicKeyParameter);
                signer.BlockUpdate(inputData, 0, inputData.Length);
                return signer.VerifySignature(signByte);
            }
            catch
            {
                return false;
            }
        }

    }
}
