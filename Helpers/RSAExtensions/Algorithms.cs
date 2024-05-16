using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MHalo.CoreFx.Helper.RSAExtensions
{
    public static class AlgorithmExtensions
    {
        public static string GetAlgorithm(this CipherAlgorithm cipher)
        {
            return cipher switch
            {
                CipherAlgorithm.RSA_ECB_PKCS1Padding => "RSA/ECB/PKCS1Padding",
                CipherAlgorithm.RSA_ECB_OAEPWithSHA_1AndMGF1Padding => "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                CipherAlgorithm.RSA_ECB_OAEPWithSHA_256AndMGF1Padding => "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                _ => throw new NotImplementedException()
            };
        }
        public static string GetAlgorithm(this SignerAlgorithm cipher)
        {
            return cipher.ToString();
        }
    }

    /// <summary>
    /// 签名算法
    /// </summary>
    public enum SignerAlgorithm
    {
        SHA1withRSA,
        SHA256withRSA,
        SHA384withRSA,
        SHA512withRSA,
        SHA1withECDSA,
        SHA224withECDSA,
        SHA256withECDSA,
        SHA384withECDSA,
        SHA512withECDSA,
        MD5withRSA
    }

    public enum CipherAlgorithm
    {
        /// <summary>
        /// RSA/ECB/PKCS1Padding: 使用PKCS#1 v1.5填充方案的RSA加密。这个是最常用的填充方式。
        /// </summary>
        RSA_ECB_PKCS1Padding,
        /// <summary>
        /// RSA/ECB/OAEPWithSHA-1AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-1，掩码生成函数是MGF1。
        /// </summary>
        RSA_ECB_OAEPWithSHA_1AndMGF1Padding,
        /// <summary>
        /// RSA/ECB/OAEPWithSHA-256AndMGF1Padding: 使用OAEP填充方案，哈希函数是SHA-256，掩码生成函数是MGF1。
        /// </summary>
        RSA_ECB_OAEPWithSHA_256AndMGF1Padding,
    }
}
