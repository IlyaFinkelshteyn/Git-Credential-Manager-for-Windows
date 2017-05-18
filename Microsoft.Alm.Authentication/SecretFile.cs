/**** Git Credential Manager for Windows ****
 *
 * Copyright (c) Microsoft Corporation
 * All rights reserved.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the """"Software""""), to deal
 * in the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
**/

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Alm.Authentication
{
    public sealed class SecretFile: ICredentialStore, ITokenStore
    {
        private const byte KeyValueSeparator = (byte)';';
        private const byte RecordSeparator = (byte)'\n';

        public SecretFile(string @namespace, Secret.UriNameConversion getTargetName)
        {
            if (String.IsNullOrWhiteSpace(@namespace))
                throw new ArgumentNullException(nameof(@namespace));
            if (@namespace.IndexOfAny(BaseSecureStore.IllegalCharacters) != -1)
                throw new ArgumentException("Namespace contains illegal characters.", nameof(@namespace));

            _getTargetName = getTargetName ?? Secret.UriToName;
            _namespace = @namespace;
        }

        public SecretFile(string @namespace)
            : this(@namespace, null)
        { }

        private readonly Secret.UriNameConversion _getTargetName;
        private readonly string _namespace;

        public string Namespace
        {
            get { return _namespace; }
        }

        public Secret.UriNameConversion UriNameConversion
        {
            get { return _getTargetName; }
        }

        public void DeleteCredentials(TargetUri targetUri)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);

            string targetName = _getTargetName(targetUri, _namespace);

            var records = ReadFile();
            if (records.Remove(targetName))
            {
                WriteFile(records);
            }
        }

        public void DeleteToken(TargetUri targetUri)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);

            string targetName = _getTargetName(targetUri, _namespace);

            var records = ReadFile();
            if (records.Remove(targetName))
            {
                WriteFile(records);
            }
        }

        public Credential ReadCredentials(TargetUri targetUri)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);

            string targetName = _getTargetName(targetUri, _namespace);

            var records = ReadFile();
            if (records.TryGetValue(targetName, out byte[] data))
            {
                ProtectedMemory.Unprotect(data, MemoryProtectionScope.SameProcess);
                string credentials = Encoding.UTF8.GetString(data);
                string[] parts = credentials.Split(':');

                return new Credential(parts[0], parts[1]);
            }

            return null;
        }

        public Token ReadToken(TargetUri targetUri)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);

            string targetName = _getTargetName(targetUri, _namespace);

            var records = ReadFile();
            if (records.TryGetValue(targetName, out byte[] data))
            {
                ProtectedMemory.Unprotect(data, MemoryProtectionScope.SameProcess);

                Token token;
                if (Token.Deserialize(data, TokenType.Personal, out token)
                    || Token.Deserialize(data, TokenType.Access, out token)
                    || Token.Deserialize(data, TokenType.BitbucketAccess, out token)
                    || Token.Deserialize(data, TokenType.Federated, out token))
                {
                    return token;
                }
            }

            return null;
        }

        public void WriteCredentials(TargetUri targetUri, Credential credentials)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);
            BaseSecureStore.ValidateCredential(credentials);

            string targetName = _getTargetName(targetUri, _namespace);

            string compactCredentials = String.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}:{1}", credentials.Username, credentials.Password);
            byte[] data = Encoding.UTF8.GetBytes(compactCredentials);
            ProtectedMemory.Protect(data, MemoryProtectionScope.SameProcess);

            var records = ReadFile();
            records[targetName] = data;

            WriteFile(records);
        }

        public void WriteToken(TargetUri targetUri, Token token)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);
            BaseSecureStore.ValidateToken(token);

            string targetName = _getTargetName(targetUri, _namespace);

            if (Token.Serialize(token, out byte[] data))
            {
                ProtectedMemory.Protect(data, MemoryProtectionScope.SameProcess);

                var records = ReadFile();
                records[targetName] = data;

                WriteFile(records);
            }
        }

        internal Dictionary<string, byte[]> ReadFile()
        {
            if (!Git.Where.GitDirectory(out string gitdir))
                return null;

            string credentialFile = Path.Combine(gitdir, CredentialFileName());
            if (!File.Exists(credentialFile))
                return null;

            var values = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

            using (var memory = new MemoryStream())
            {
                using (var stream = File.Open(credentialFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    stream.CopyTo(memory);
                }

                memory.Seek(0, SeekOrigin.Begin);

                var buffer = memory.ToArray();

                buffer = ProtectedData.Unprotect(buffer, null, DataProtectionScope.CurrentUser);

                int start = 0;
                for (int i = 0; i < buffer.Length; i += 1)
                {
                    if (buffer[i] == RecordSeparator)
                    {
                        var record = ParseRecord(buffer, start, i - start - 1);
                        start = i + 1;
                    }
                }
            }

            return null;
        }

        internal void WriteFile(IReadOnlyDictionary<string, byte[]> values)
        {
            if (Git.Where.GitDirectory(out string gitdir))
            {
                using (var memory = new MemoryStream())
                {
                    foreach (var pair in values)
                    {
                        byte[] nameBytes = Encoding.UTF8.GetBytes(pair.Key);
                        byte[] dataBytes = pair.Value;

                        ProtectedMemory.Unprotect(dataBytes, MemoryProtectionScope.SameProcess);

                        memory.Write(nameBytes, 0, nameBytes.Length);
                        memory.WriteByte(KeyValueSeparator);
                        memory.Write(dataBytes, 0, dataBytes.Length);
                        memory.WriteByte(RecordSeparator);
                    }

                    memory.Seek(0, SeekOrigin.Begin);

                    string credentialFile = Path.Combine(gitdir, CredentialFileName());
                    using (var stream = File.Open(credentialFile, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                    {
                        byte[] buffer = memory.ToArray();

                        buffer = ProtectedData.Protect(buffer, null, DataProtectionScope.CurrentUser);

                        stream.Write(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        private static string CredentialFileName()
        {
            return Environment.UserName.ToLower() + ".credentials";
        }

        private static KeyValuePair<string, byte[]> ParseRecord(byte[] buffer, int index, int count)
        {
            string name = null;
            byte[] data = null;

            for (int i = 0; i < count; i += 1)
            {
                if (buffer[index + i] == KeyValueSeparator)
                {
                    name = Encoding.UTF8.GetString(buffer, index, i);
                    data = new byte[count - i - 1];

                    Buffer.BlockCopy(buffer, index + i + 1, data, 0, data.Length);
                }
            }

            ProtectedMemory.Protect(data, MemoryProtectionScope.SameProcess);

            return new KeyValuePair<string, byte[]>(name, data);
        }
    }
}
