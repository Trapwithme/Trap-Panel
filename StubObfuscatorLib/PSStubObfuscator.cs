using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StubBuilder
{
    public static class PSStubObfuscator
    {
        private static readonly string _allowedChars = "abcdefghijklmnopqrstuvwxyz";

        private static string RandomString(int len)
        {
            byte[] bytes = new byte[len];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return new string(bytes.Select(b => _allowedChars[b % _allowedChars.Length]).ToArray());
        }

        private static string GenName(HashSet<string> used, int len)
        {
            string c;
            do { c = "_" + RandomString(len); } while (used.Contains(c));
            used.Add(c);
            return c;
        }

        public static string Obfuscate(string s)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Console.WriteLine($"[ps-obf] Start: {s.Length} chars");

            string nl = s.Contains("\r\n") ? "\r\n" : "\n";

            // Phase 1: Extract @"..."@" here-strings (Add-Type blocks with embedded C#)
            var hrMap = new List<KeyValuePair<string, string>>();
            int hrIdx = 0;
            s = Regex.Replace(s, @"@""[\s\S]*?""@", m =>
            {
                string key = "\x00HR" + hrIdx + "\x00";
                hrMap.Add(new KeyValuePair<string, string>(key, m.Value));
                hrIdx++;
                return key;
            });
            Console.WriteLine($"[ps-obf] Extracted {hrIdx} here-strings: {sw.ElapsedMilliseconds}ms");

            // Phase 2: Find user-defined functions
            var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var funcMap = new Dictionary<string, string>();
            foreach (Match m in Regex.Matches(s, @"function\s+([A-Za-z][\w-]*)"))
            {
                string name = m.Groups[1].Value;
                if (!funcMap.ContainsKey(name))
                    funcMap[name] = GenName(usedNames, 8);
            }
            Console.WriteLine($"[ps-obf] Found {funcMap.Count} functions: {sw.ElapsedMilliseconds}ms");

            // Phase 3: Find user-defined variables
            var varMap = new Dictionary<string, string>();
            var skipVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "true", "false", "null", "error", "LASTEXITCODE", "Host", "PID",
                "PSVersionTable", "PSBoundParameters", "PSScriptRoot", "PSCommandPath",
                "args", "input", "myInvocation", "OFS", "StackTrace", "ErrorActionPreference",
                "matches", "ForEach", "PSDebugContext", "PSCmdlet", "PSEdition",
                "ShellId", "ExecutionContext", "HOME", "PWD", "OLDPWD",
                "ConsoleFileName", "FormatEnumerationLimit", "ProgressPreference",
                "VerbosePreference", "DebugPreference", "InformationPreference",
                "WarningPreference", "WhatIfPreference", "ConfirmPreference",
                "NestedPromptLevel", "Stack"
            };

            foreach (Match m in Regex.Matches(s, @"\$(?:((?:script|global|local|env):))?(\w+)"))
            {
                string scope = m.Groups[1].Value;
                string name = m.Groups[2].Value;

                if (scope == "env:") continue;
                if (scope == "" && skipVars.Contains(name)) continue;
                if (name.Length <= 1) continue;

                string full = "$" + scope + name;
                if (!varMap.ContainsKey(full))
                    varMap[full] = "$" + scope + GenName(usedNames, 6);
            }
            Console.WriteLine($"[ps-obf] Found {varMap.Count} variables: {sw.ElapsedMilliseconds}ms");

            // Phase 3.5: Find param block parameters and map their -ParamName call-site references
            var paramMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match pm in Regex.Matches(s, @"function\s+[A-Za-z][\w-]*\s*\{[^}]*param\s*\(([^)]+)\)", RegexOptions.Singleline))
            {
                string paramBlock = pm.Groups[1].Value;
                foreach (Match pvar in Regex.Matches(paramBlock, @"\$(\w+)"))
                {
                    string paramName = pvar.Groups[1].Value;
                    string fullVar = "$" + paramName;
                    if (varMap.ContainsKey(fullVar) && !paramMap.ContainsKey(paramName))
                        paramMap[paramName] = varMap[fullVar].TrimStart('$');
                }
            }
            Console.WriteLine($"[ps-obf] Found {paramMap.Count} param names to rename: {sw.ElapsedMilliseconds}ms");

            // Phase 4: Rename functions (longest first)
            foreach (var kv in funcMap.OrderByDescending(kv => kv.Key.Length))
                s = Regex.Replace(s, @"\b" + Regex.Escape(kv.Key) + @"\b", kv.Value);
            Console.WriteLine($"[ps-obf] Functions renamed: {sw.ElapsedMilliseconds}ms");

            // Phase 5: Rename variables (longest first)
            foreach (var kv in varMap.OrderByDescending(kv => kv.Key.Length))
                s = s.Replace(kv.Key, kv.Value);
            Console.WriteLine($"[ps-obf] Variables renamed: {sw.ElapsedMilliseconds}ms");

            // Phase 5.5: Rename -ParameterName call-site references to match renamed params
            foreach (var kv in paramMap.OrderByDescending(kv => kv.Key.Length))
                s = Regex.Replace(s, @"-" + Regex.Escape(kv.Key) + @"(?=\s|$|[{}\[\](),;:])", "-" + kv.Value);
            Console.WriteLine($"[ps-obf] Param refs renamed: {sw.ElapsedMilliseconds}ms");

            // Phase 6: Encrypt string literals — line by line, only simple assignments
            var rngKey = RandomNumberGenerator.Create();
            int strCount = 0;
            string[] lines = s.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            for (int li = 0; li < lines.Length; li++)
            {
                string line = lines[li];
                // Only encrypt strings that are on assignment lines: $var = "string" or } else { "string" }
                // Skip lines that have Write-Host, -ForegroundColor, throw, return, if, while, function, Add-Type
                if (Regex.IsMatch(line, @"^\s*(Write-Host|throw|return|if|while|function|Add-Type|foreach|switch|catch|finally)\b"))
                    continue;
                if (line.Contains("-ForegroundColor") || line.Contains("-ErrorAction"))
                    continue;
                // Only encrypt if the line is a simple assignment or standalone expression
                if (!Regex.IsMatch(line, @"^\s*\$") && !Regex.IsMatch(line, @"^\s*try\s*\{") && !Regex.IsMatch(line, @"^\s*if\s*\(") && !Regex.IsMatch(line, @"\}\s*else\s*\{"))
                    continue;

                lines[li] = Regex.Replace(line, @"""([^""$]+)""", m =>
                {
                    string inner = m.Groups[1].Value;
                    if (inner.Length <= 3) return m.Value;

                    byte[] data = Encoding.UTF8.GetBytes(inner);
                    byte[] kb = new byte[1];
                    rngKey.GetBytes(kb);
                    int xorKey = kb[0] % 254 + 1;

                    byte[] enc = new byte[data.Length];
                    for (int i = 0; i < data.Length; i++)
                        enc[i] = (byte)(data[i] ^ xorKey);

                    strCount++;
                    return "(-join([char[]]@(" + string.Join(",", enc.Select(b => (int)b)) + ") | % {[char]($_ -bxor " + xorKey + ")}))";
                });
            }
            s = string.Join(nl, lines);
            Console.WriteLine($"[ps-obf] Encrypted {strCount} strings: {sw.ElapsedMilliseconds}ms");

            // Phase 7: Insert junk code
            s = InsertJunkCode(s, usedNames);
            Console.WriteLine($"[ps-obf] Junk inserted: {sw.ElapsedMilliseconds}ms");

            // Phase 8: Restore here-strings
            foreach (var kv in hrMap)
                s = s.Replace(kv.Key, kv.Value);
            Console.WriteLine($"[ps-obf] Restored here-strings: {sw.ElapsedMilliseconds}ms");

            Console.WriteLine($"[ps-obf] Done: {s.Length} chars, {sw.ElapsedMilliseconds}ms");
            return s;
        }

        private static string InsertJunkCode(string s, HashSet<string> usedNames)
        {
            var rng = RandomNumberGenerator.Create();
            byte[] seedBuf = new byte[4];
            rng.GetBytes(seedBuf);
            int seed = seedBuf[0] | (seedBuf[1] << 8) | (seedBuf[2] << 16) | (seedBuf[3] << 24);

            string nl = s.Contains("\r\n") ? "\r\n" : "\n";
            string[] lines = s.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var result = new List<string>();

            // ---- Junk variables at the top of the script ----
            for (int i = 0; i < 5; i++)
            {
                string jv = GenName(usedNames, 6);
                byte[] vBuf = new byte[2];
                rng.GetBytes(vBuf);
                int val = vBuf[0] | (vBuf[1] << 8);

                switch (i % 5)
                {
                    case 0:
                        result.Add("$" + jv + " = " + val + " -bor 0");
                        break;
                    case 1:
                        result.Add("$" + jv + " = [DateTime]::UtcNow.Ticks");
                        break;
                    case 2:
                        result.Add("$" + jv + " = @(" + (val % 77) + ", " + (val % 33) + ").Length");
                        break;
                    case 3:
                        result.Add("if ($false) { $" + jv + " = " + (val % 100) + " }");
                        break;
                    case 4:
                        result.Add("$" + jv + " = [System.Math]::Pow(" + (val % 10) + ", 2)");
                        break;
                }
            }

            // ---- Insert junk before every 3rd function declaration ----
            int funcCount = 0;
            for (int i = 0; i < lines.Length; i++)
            {
                if (Regex.IsMatch(lines[i], @"^\s*function\s+"))
                {
                    funcCount++;
                    if (funcCount % 3 == 0)
                    {
                        string jv1 = GenName(usedNames, 6);
                        string jv2 = GenName(usedNames, 6);
                        byte[] vBuf = new byte[2];
                        rng.GetBytes(vBuf);
                        int val = vBuf[0] | (vBuf[1] << 8);

                        result.Add("$" + jv1 + " = '" + RandomString(8) + "'");
                        result.Add("$" + jv2 + " = " + val + " -band 0xFFFF");
                    }
                    if (funcCount % 5 == 0)
                    {
                        string jv = GenName(usedNames, 6);
                        result.Add("if ($false) { $" + jv + " = " + (seed & 0xFFFF) + " }");
                    }
                }
                result.Add(lines[i]);
            }

            // ---- Insert junk before the main loop ----
            for (int i = 0; i < result.Count; i++)
            {
                if (Regex.IsMatch(result[i], @"^\s*while\s*\(") && i > 5)
                {
                    string jv = GenName(usedNames, 6);
                    result.Insert(i, "$" + jv + " = " + (seed & 0xFFFF));
                    break;
                }
            }

            return string.Join(nl, result);
        }
    }
}
