using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WpfApp
{
    public static class SecureChannel
    {
        private const int KeySize = 256;
        private const int IvSize = 16;
        private const int HmacSize = 32;
        private const int MaxMessageSize = 50 * 1024 * 1024 + 1024;

        public static byte[] GenerateAesKey()
        {
            byte[] key = new byte[KeySize / 8];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);
            return key;
        }

        public static byte[] EncryptAesKey(byte[] aesKey, RSA rsaPublicKey)
        {
            return rsaPublicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        }

        public static byte[] DecryptAesKey(byte[] encryptedKey, RSA rsaPrivateKey)
        {
            return rsaPrivateKey.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
        }

        private static byte[] DeriveHmacKey(byte[] aesKey)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(Encoding.UTF8.GetBytes("HMAC-" + BytesToHex(aesKey)));
        }

        private static string BytesToHex(byte[] bytes)
        {
            var sb = new System.Text.StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static async Task WriteEncryptedMessage(Stream stream, byte msgType, byte[] payload, byte[] aesKey, CancellationToken ct = default)
        {
            int payloadLen = payload?.Length ?? 0;
            int plaintextLen = 1 + payloadLen;
            byte[] plaintext = new byte[plaintextLen];
            plaintext[0] = msgType;
            if (payloadLen > 0)
                Buffer.BlockCopy(payload, 0, plaintext, 1, payloadLen);

            byte[] iv = new byte[IvSize];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(iv);

            byte[] ciphertext;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var enc = aes.CreateEncryptor())
                    ciphertext = enc.TransformFinalBlock(plaintext, 0, plaintextLen);
            }

            byte[] ivCipher = new byte[IvSize + ciphertext.Length];
            Buffer.BlockCopy(iv, 0, ivCipher, 0, IvSize);
            Buffer.BlockCopy(ciphertext, 0, ivCipher, IvSize, ciphertext.Length);

            byte[] hmacKey = DeriveHmacKey(aesKey);
            byte[] hmac;
            using (var h = new HMACSHA256(hmacKey))
                hmac = h.ComputeHash(ivCipher);

            byte[] packet = new byte[4 + ivCipher.Length + HmacSize];
            int totalLen = ivCipher.Length + HmacSize;
            packet[0] = (byte)(totalLen & 0xFF);
            packet[1] = (byte)((totalLen >> 8) & 0xFF);
            packet[2] = (byte)((totalLen >> 16) & 0xFF);
            packet[3] = (byte)((totalLen >> 24) & 0xFF);
            Buffer.BlockCopy(ivCipher, 0, packet, 4, ivCipher.Length);
            Buffer.BlockCopy(hmac, 0, packet, 4 + ivCipher.Length, HmacSize);

            await stream.WriteAsync(packet, 0, packet.Length, ct);
            await stream.FlushAsync(ct);
        }

        public static async Task<(byte msgType, byte[] payload)> ReadEncryptedMessage(Stream stream, byte[] aesKey, CancellationToken ct = default)
        {
            byte[] lenBuf = new byte[4];
            if (!await ReadExact(stream, lenBuf, 0, 4, ct))
                return (0, null);

            int totalLen = lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24);
            if (totalLen <= HmacSize || totalLen > MaxMessageSize + IvSize + HmacSize)
                return (0, null);

            byte[] data = new byte[totalLen];
            if (!await ReadExact(stream, data, 0, totalLen, ct))
                return (0, null);

            byte[] ivCipher = new byte[totalLen - HmacSize];
            byte[] receivedHmac = new byte[HmacSize];
            Buffer.BlockCopy(data, 0, ivCipher, 0, ivCipher.Length);
            Buffer.BlockCopy(data, ivCipher.Length, receivedHmac, 0, HmacSize);

            byte[] hmacKey = DeriveHmacKey(aesKey);
            byte[] computedHmac;
            using (var h = new HMACSHA256(hmacKey))
                computedHmac = h.ComputeHash(ivCipher);

            if (!CryptographicOperations.FixedTimeEquals(computedHmac, receivedHmac))
                return (0, null);

            if (ivCipher.Length < IvSize)
                return (0, null);

            byte[] iv = new byte[IvSize];
            byte[] ciphertext = new byte[ivCipher.Length - IvSize];
            Buffer.BlockCopy(ivCipher, 0, iv, 0, IvSize);
            Buffer.BlockCopy(ivCipher, IvSize, ciphertext, 0, ciphertext.Length);

            byte[] plaintext;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor())
                    plaintext = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }

            if (plaintext.Length < 1)
                return (0, null);

            byte msgType = plaintext[0];
            byte[] payload = null;
            if (plaintext.Length > 1)
            {
                payload = new byte[plaintext.Length - 1];
                Buffer.BlockCopy(plaintext, 1, payload, 0, payload.Length);
            }

            return (msgType, payload);
        }

        private static async Task<bool> ReadExact(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct);
                if (read <= 0) return false;
                totalRead += read;
            }
            return true;
        }
    }
}
