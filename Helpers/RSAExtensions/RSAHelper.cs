using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MHalo.CoreFx.Helper.RSAExtensions;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace MHalo.CoreFx.Helper
{
    /// <summary>
    /// RAS加密
    /// <para>公钥加密 -> 私钥解密</para>
    /// <para>私钥加密 -> 私钥解密</para>
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
        /// 公钥加密
        /// <para>publicKeyContent请使用pkcs8密钥</para>
        /// </summary>
        /// <param name="content">加密内容</param>
        /// <param name="publicKeyContent">公钥</param>
        /// <param name="algorithm">算法</param>
        /// <returns>加密后的字符</returns>
        public static string Encrypt(string content, string publicKeyContent, string algorithm = "RSA/ECB/PKCS1Padding")
        {
            byte[] keyByte = Convert.FromBase64String(publicKeyContent);
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(keyByte);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(true, publicKey);
            byte[] byteData = Encoding.UTF8.GetBytes(content);
            byteData = cipher.DoFinal(byteData, 0, byteData.Length);
            return Convert.ToBase64String(byteData);
        }

        /// <summary>
        /// 私钥解密
        /// <para>privateKeyContent请使用pkcs8密钥</para>
        /// </summary>
        /// <param name="content">解密字符</param>
        /// <param name="privateKeyContent">私钥</param>
        /// <param name="algorithm">算法</param>
        /// <returns>解密后的原始字符</returns>
        public static string Decrypt(string content, string privateKeyContent, string algorithm = "RSA/ECB/PKCS1Padding")
        {
            byte[] keyByte = Convert.FromBase64String(privateKeyContent);
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(keyByte);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(false, privKey);
            byte[] byteData = Convert.FromBase64String(content);
            byteData = cipher.DoFinal(byteData, 0, byteData.Length);
            return Encoding.UTF8.GetString(byteData);
        }

        /// <summary>
        /// 私钥签名
        /// <para>privateKeyContent请使用pkcs8密钥</para>
        /// </summary>
        /// <param name="data">签名内容</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">算法</param>
        /// <returns></returns>
        public static string SignData(string data, string privateKey, string algorithm = "MD5withRSA")
        {
            var keyByte = Convert.FromBase64String(privateKey);
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(keyByte);
            var inputData = Encoding.UTF8.GetBytes(data);
            var signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(true, privKey);
            signer.BlockUpdate(inputData, 0, inputData.Length);
            return Convert.ToBase64String(signer.GenerateSignature());
        }
        /// <summary>
        /// 公钥验签
        /// <para>publicKeyContent请使用pkcs8密钥</para>
        /// </summary>
        /// <param name="data">验签内容</param>
        /// <param name="sign">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">算法</param>
        /// <returns></returns>
        public static bool VertifyData(string data, string sign, string publicKey, string algorithm = "MD5withRSA")
        {
            try
            {
                var keyByte = Convert.FromBase64String(publicKey);
                var signByte = Convert.FromBase64String(sign);
                var pblcKey = PublicKeyFactory.CreateKey(keyByte);
                var signer = SignerUtilities.GetSigner(algorithm);
                var inputData = Encoding.UTF8.GetBytes(data);
                signer.Init(false, pblcKey);
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
