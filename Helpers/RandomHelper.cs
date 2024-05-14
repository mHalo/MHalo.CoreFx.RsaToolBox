using System;
using System.Linq;
using System.Security.Cryptography;

namespace MHalo.CoreFx.Helper
{
    public class RandomHelper
    {
        private static readonly RandomNumberGenerator rngp = RandomNumberGenerator.Create();
        private static readonly byte[] rb = new byte[4];
        private const string tokenChars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz-_0123456789";
        private const string noSymbolChars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789";
        /// <summary>
        /// 产生一个非负的随机数
        /// </summary>
        public static int Next()
        {
            rngp.GetBytes(rb);
            int value = BitConverter.ToInt32(rb, 0);
            if (value < 0) value = -value;
            return value;
        }
        /// <summary>
        /// 产生一个非负且最大值在 max 以下的随机数
        /// </summary>
        /// <remarks>不包含max</remarks>
        /// <param name="max">最大值</param>
        public static int Next(int max)
        {
            return RandomNumberGenerator.GetInt32(0, max);
        }
        /// <summary>
        /// 产生一个非负且最小值为 min 最大值在 max 以下的随机数
        /// </summary>
        /// <remarks>不包含max</remarks>
        /// <param name="min">最小值</param>
        /// <param name="max">最大值</param>
        public static int Next(int min, int max)
        {
            return RandomNumberGenerator.GetInt32(min, max);
        }

        /// <summary>
        /// 生成随机长度的字符串
        /// <para>不含1和L这两个字符</para>
        /// </summary>
        /// <returns></returns>
        public static string RandomCode(int length, string characters = "2346789ABCDEFGHJKMNPQRSTUVWXYZ")
        {
            if (string.IsNullOrWhiteSpace(characters))
            {
                characters = "2346789ABCDEFGHJKMNPQRSTUVWXYZ";
            }
            System.Text.StringBuilder code = new();
            Random rnd = new();
            for (int i = 0; i < length; i++)
            {
                code.Append(characters[rnd.Next(characters.Length)]);
            }
            return code.ToString();
        }

        /// <summary>
        /// 生成随机长度的数字字符串
        /// </summary>
        /// <returns></returns>
        public static string RandomNumCode(int length)
        {
            return RandomCode(length, "1234567890");
        }

        /// <summary>
        /// 生成随机长度的字符串
        /// </summary>
        /// <returns></returns>
        public static string RandomWordCode(int length)
        {
            return RandomCode(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        /// <summary>
        /// 生成随机token
        /// </summary>
        /// <param name="length">token长度</param>
        /// <param name="noSymbol">不包含符号: _-</param>
        /// <returns></returns>
        public static string RandomToken(int length, bool noSymbol = false)
        {
            string chars = noSymbol ? noSymbolChars : tokenChars;
            return new string(Enumerable.Repeat(chars, length).Select(s => s[Next(s.Length)]).ToArray());
        }
    }
}
