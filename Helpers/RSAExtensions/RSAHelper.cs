using MHalo.CoreFx.Helper.RSAExtensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MHalo.CoreFx.Helper
{
    /// <summary>
    /// RAS加密
    /// <para>公钥加密 -> 私钥解密</para>
    /// <para>私钥加密 -> 公钥解密</para>
    /// </summary>
    public static class RSAHelper
    {
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

        #region 密钥生成

        /// <summary>
        /// 生成密钥
        /// </summary>
        /// <param name="keyType">密钥类型</param>
        /// <param name="keySizeInBits">长度</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="usePemFormat">是否使用pem格式,当密钥类型为Xml时，此参数不起效</param>
        public static (string publicKey, string privateKey) ExportRSAKey(RSAKeyType keyType, int keySizeInBits, bool usePemFormat = false)
        {
            string publicKey, privateKey;
            var rsa = Create(keySizeInBits);
            if(keyType == RSAKeyType.Xml)
            {
                privateKey = rsa.ExportPrivateKey(RSAKeyType.Xml);
                publicKey = rsa.ExportPublicKey(RSAKeyType.Xml);
            }
            else if(keyType == RSAKeyType.Pkcs8)
            {
                privateKey = rsa.ExportPrivateKey(RSAKeyType.Pkcs8, usePemFormat);
                publicKey = rsa.ExportPublicKey(RSAKeyType.Pkcs8, usePemFormat);
            }
            else
            {
                privateKey = rsa.ExportPrivateKey(RSAKeyType.Pkcs1, usePemFormat);
                publicKey = rsa.ExportPublicKey(RSAKeyType.Pkcs1, usePemFormat);
            }
            return (publicKey, privateKey);
        }
        #endregion

        #region 其他
        /// <summary>
        /// 从私钥导出公钥
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="privateKeyContent"></param>
        /// <param name="usePemFormat">当密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static string ExportPublicKeyFromPrivateKey(RSAKeyType keyType, string privateKeyContent, bool usePemFormat = false)
        {
            using var rsa = RSA.Create(); 
            rsa.ImportPrivateKey(keyType, privateKeyContent, true);
            return rsa.ExportPublicKey(keyType, usePemFormat);
        }

        /// <summary>
        /// 公钥格式转换
        /// </summary>
        /// <param name="publicKeyContent"></param>
        /// <param name="outKeyType"></param>
        /// <param name="usePemFormat">当目标密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static string TransformPublicKeyFormat(string publicKeyContent, RSAKeyType outKeyType, bool usePemFormat = false)
        {
            if(RSAKeyExtensions.IsValidPublicKey(publicKeyContent, out var orginalKeyType))
            {
                using var rsa = RSA.Create();
                rsa.ImportPublicKey(orginalKeyType!.Value, publicKeyContent);
                return rsa.ExportPublicKey(outKeyType, usePemFormat);
            }
            else
            {
                throw new Exception("公钥格式错误，无法识别");
            }
        }

        /// <summary>
        /// 私钥格式转换
        /// </summary>
        /// <param name="privateKeyContent">私钥</param>
        /// <param name="targetKeyType">目标密钥类型</param>
        /// <param name="publicKey">转换后的公钥</param>
        /// <param name="privateKey">转换后的私钥</param>
        /// <param name="usePemFormat">当目标密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static bool TryTransformKeyFormat(RSAKeyType targetKeyType, string privateKeyContent, out string publicKey, out string privateKey, bool usePemFormat = false)
        {
            privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
            if (RSAKeyExtensions.IsValidPrivateKey(privateKeyContent, out var orginalKeyType))
            {
                using var rsa = RSA.Create();
                rsa.ImportPrivateKey(orginalKeyType!.Value, privateKeyContent);
                publicKey = rsa.ExportPublicKey(targetKeyType, usePemFormat);
                privateKey = rsa.ExportPrivateKey(targetKeyType, usePemFormat);
                return true;
            }
            else
            {
                publicKey = string.Empty;
                privateKey = string.Empty;
                return false;
            }
        }
        #endregion

        #region 加密/解密

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
            AsymmetricKeyParameter publicKeyParameter = RSAKeyExtensions.CreateAsymmetricPublicKeyParameter(keyType, publicKeyContent);
            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(true, publicKeyParameter);

            byte[] byteData = Encoding.UTF8.GetBytes(content);
            int blockSize = cipher.GetBlockSize();
            int inputLength = byteData.Length;
            if (inputLength <= blockSize)
            {
                byteData = cipher.DoFinal(byteData, 0, byteData.Length);
                return Convert.ToBase64String(byteData);
            }
            // 分段加密
            using MemoryStream outputStream = new MemoryStream();
            int offset = 0;
            while (inputLength - offset > 0)
            {
                int inputBlockSize = Math.Min(blockSize, inputLength - offset);
                byte[] inputBytes = new byte[inputBlockSize];
                Buffer.BlockCopy(byteData, offset, inputBytes, 0, inputBlockSize);
                byte[] encryptedBytes = cipher.DoFinal(inputBytes, 0, inputBlockSize);
                outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                offset += inputBlockSize;
            }
            byte[] encryptedData = outputStream.ToArray();
            return Convert.ToBase64String(encryptedData);
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
            AsymmetricKeyParameter privateKeyParameter = RSAKeyExtensions.CreateAsymmetricPrivateKeyParameter(keyType, privateKeyContent);
            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(false, privateKeyParameter);

            byte[] byteData = Convert.FromBase64String(content);
            int blockSize = cipher.GetBlockSize();
            int inputLength = byteData.Length;
            if(inputLength <= blockSize)
            {
                byteData = cipher.DoFinal(byteData, 0, byteData.Length);
                return Encoding.UTF8.GetString(byteData);
            }

            // 分段解密
            using MemoryStream outputStream = new MemoryStream();
            int offset = 0;
            while (inputLength - offset > 0)
            {
                int inputBlockSize = Math.Min(blockSize, inputLength - offset);
                byte[] inputBytes = new byte[inputBlockSize];
                Buffer.BlockCopy(byteData, offset, inputBytes, 0, inputBlockSize);
                byte[] decryptedBytes = cipher.DoFinal(inputBytes, 0, inputBlockSize);
                outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
                offset += inputBlockSize;
            }
            byte[] decryptedData = outputStream.ToArray();
            return Encoding.UTF8.GetString(decryptedData);
        }

        /// <summary>
        /// 私钥加密 （常规应使用公钥加密，私钥解密）
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
        /// <returns>加密后的字符</returns>
        /// <returns></returns>
        public static string EncyptByPrivateKey(RSAKeyType keyType, string content, string privateKeyContent, CipherAlgorithm cipherAlgorithm = CipherAlgorithm.RSA_ECB_PKCS1Padding)
        {
            AsymmetricKeyParameter privateKeyParameter = RSAKeyExtensions.CreateAsymmetricPrivateKeyParameter(keyType, privateKeyContent);
            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(true, privateKeyParameter);

            byte[] byteData = Encoding.UTF8.GetBytes(content);
            int blockSize = cipher.GetBlockSize();
            int inputLength = byteData.Length;
            if (inputLength <= blockSize)
            {
                byteData = cipher.DoFinal(byteData, 0, byteData.Length);
                return Convert.ToBase64String(byteData);
            }
            // 分段加密
            using MemoryStream outputStream = new MemoryStream();
            int offset = 0;
            while (inputLength - offset > 0)
            {
                int inputBlockSize = Math.Min(blockSize, inputLength - offset);
                byte[] inputBytes = new byte[inputBlockSize];
                Buffer.BlockCopy(byteData, offset, inputBytes, 0, inputBlockSize);
                byte[] encryptedBytes = cipher.DoFinal(inputBytes, 0, inputBlockSize);
                outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                offset += inputBlockSize;
            }
            byte[] encryptedData = outputStream.ToArray();
            return Convert.ToBase64String(encryptedData);
        }
        /// <summary>
        /// 公钥解密 （常规应使用公钥加密，私钥解密）
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
        /// <returns></returns>
        public static string DecryptByPublicKey(RSAKeyType keyType, string content, string publicKeyContent, CipherAlgorithm cipherAlgorithm = CipherAlgorithm.RSA_ECB_PKCS1Padding)
        {
            AsymmetricKeyParameter publicKeyParameter = RSAKeyExtensions.CreateAsymmetricPublicKeyParameter(keyType, publicKeyContent);
            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherAlgorithm.GetAlgorithm());
            cipher.Init(false, publicKeyParameter);

            byte[] byteData = Convert.FromBase64String(content);
            int blockSize = cipher.GetBlockSize();
            int inputLength = byteData.Length;
            if (inputLength <= blockSize)
            {
                byteData = cipher.DoFinal(byteData, 0, byteData.Length);
                return Encoding.UTF8.GetString(byteData);
            }

            // 分段解密
            using MemoryStream outputStream = new MemoryStream();
            int offset = 0;
            while (inputLength - offset > 0)
            {
                int inputBlockSize = Math.Min(blockSize, inputLength - offset);
                byte[] inputBytes = new byte[inputBlockSize];
                Buffer.BlockCopy(byteData, offset, inputBytes, 0, inputBlockSize);
                byte[] decryptedBytes = cipher.DoFinal(inputBytes, 0, inputBlockSize);
                outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
                offset += inputBlockSize;
            }
            byte[] decryptedData = outputStream.ToArray();
            return Encoding.UTF8.GetString(decryptedData);
        }

        #endregion

        #region  签名/验签

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
        public static string SignData(RSAKeyType keyType, string data, string privateKeyContent, SignerAlgorithm signerAlgorithm = SignerAlgorithm.SHA256withRSA)
        {
            AsymmetricKeyParameter privateKeyParameter = RSAKeyExtensions.CreateAsymmetricPrivateKeyParameter(keyType, privateKeyContent);

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
                AsymmetricKeyParameter publicKeyParameter = RSAKeyExtensions.CreateAsymmetricPublicKeyParameter(keyType, publicKeyContent);
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

        #endregion

    }
}
