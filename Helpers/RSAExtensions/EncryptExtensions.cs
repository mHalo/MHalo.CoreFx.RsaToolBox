using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace MHalo.CoreFx.Helper.RSAExtensions
{
    /// <summary>
    /// github: https://github.com/stulzq/RSAExtensions
    /// </summary>
    public static class EncryptExtensions
    {
        static readonly Dictionary<RSAEncryptionPadding, int> PaddingLimitDic = new()
        {
            [RSAEncryptionPadding.Pkcs1] = 11,
            [RSAEncryptionPadding.OaepSHA1] = 42,
            [RSAEncryptionPadding.OaepSHA256] = 66,
            [RSAEncryptionPadding.OaepSHA384] = 98,
            [RSAEncryptionPadding.OaepSHA512] = 130,
            [RSAEncryptionPadding.OaepSHA3_256] = 66,
            [RSAEncryptionPadding.OaepSHA3_384] = 98,
            [RSAEncryptionPadding.OaepSHA3_512] = 130,
        };

        /// <summary>
        /// 针对大量字符的加密
        /// <para>分段加密后组合</para>
        /// <example>
        /// <code>
        /// var rsa = RSAHelper.Create();
        /// rsa.ImportPublicKey(RSAKeyType.Pkcs8, publicKey);
        /// string encryptContent = rsae.EncryptData(data, RSAEncryptionPadding.Pkcs1);
        /// </code>
        /// </example>
        /// </summary>
        /// <param name="rsa">RSA</param>
        /// <param name="content">加密内容</param>
        /// <param name="padding">算法</param>
        /// <param name="connChar">连接符号</param>
        /// <returns>加密后的字符</returns>
        public static string EncryptData(this RSA rsa, string content, RSAEncryptionPadding padding, char connChar = '$')
        {
            var data = Encoding.UTF8.GetBytes(content);
            var modulusLength = rsa.KeySize / 8;
            var splitLength = modulusLength - PaddingLimitDic[padding];
            var sb = new StringBuilder();
            var splitsNumber = Convert.ToInt32(Math.Ceiling(data.Length * 1.0 / splitLength));
            var pointer = 0;
            for (int i = 0; i < splitsNumber; i++)
            {
                byte[] current = pointer + splitLength < data.Length ? data[pointer..(pointer + splitLength)] : data[pointer..];

                sb.Append(Convert.ToBase64String(rsa.Encrypt(current, padding)));
                sb.Append(connChar);
                pointer += splitLength;
            }
            return sb.ToString().TrimEnd(connChar);
        }

        /// <summary>
        /// 针对大量字符的解密
        /// <para>分段解密后组合</para>
        /// <example>
        /// <code>
        /// var rsa = RSAHelper.Create();
        /// rsa.ImportPrivateKey(RSAKeyType.Pkcs8, privateKey);
        /// string decryptContent = rsa.DecryptData(encryptContent, RSAEncryptionPadding.Pkcs1);
        /// </code>
        /// </example>
        /// </summary>
        /// <param name="rsa">RSA</param>
        /// <param name="content">待解密内容</param>
        /// <param name="padding">算法</param>
        /// <param name="connChar">连接符号</param>
        /// <returns>解密后的字符</returns>
        public static string DecryptData(this RSA rsa, string content, RSAEncryptionPadding padding, char connChar = '$')
        {
            var data = content.Split(connChar, StringSplitOptions.RemoveEmptyEntries);
            var byteList = new List<byte>();

            foreach (var item in data)
            {
                byteList.AddRange(rsa.Decrypt(Convert.FromBase64String(item), padding));
            }

            return Encoding.UTF8.GetString(byteList.ToArray());
        }

    }
}