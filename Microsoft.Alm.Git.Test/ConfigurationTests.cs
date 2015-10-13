﻿using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Alm.Git.Test
{
    /// <summary>
    /// A class to test <see cref="GitConfiguration"/>.
    /// </summary>
    [TestClass]
    public class ConfigurationTests
    {
        [TestMethod]
        public void ParseGitConfig_Simple()
        {
            const string input = @"
[core]
    autocrlf = false
";

            var values = TestParseGitConfig(input);

            Assert.AreEqual("false", values["core.autocrlf"]);
        }

        [TestMethod]
        public void ParseGitConfig_OverwritesValues()
        {
            // http://thedailywtf.com/articles/What_Is_Truth_0x3f_
            const string input = @"
[core]
    autocrlf = true
    autocrlf = FileNotFound
    autocrlf = false
";

            var values = TestParseGitConfig(input);

            Assert.AreEqual("false", values["core.autocrlf"]);
        }

        [TestMethod]
        public void ParseGitConfig_PartiallyQuoted()
        {
            const string input = @"
[core ""oneQuote]
    autocrlf = ""false
";

            var values = TestParseGitConfig(input);

            Assert.AreEqual("false", values["core.oneQuote.autocrlf"]);
        }

        [TestMethod]
        public void ParseGitConfig_SampleFile()
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var me = this.GetType();
            var us = me.Assembly;

            using (var stream = us.GetManifestResourceStream(me, "sample.gitconfig"))
            using (var reader = new StreamReader(stream))
            {
                GitConfiguration.ParseGitConfig(reader, values);
            }

            Assert.AreEqual(36, values.Count);
            Assert.AreEqual("\\\"C:/Utils/Compare It!/wincmp3.exe\\\" \\\"$(cygpath -w \\\"$LOCAL\\\")\\\" \\\"$(cygpath -w \\\"$REMOTE\\\")\\\"", values["difftool.cygcompareit.cmd"], "The quotes remained.");
            Assert.AreEqual("!f() { git fetch origin && git checkout -b $1 origin/master --no-track; }; f", values["alias.cob"], "The quotes were stripped.");
        }

        private static Dictionary<string, string> TestParseGitConfig(string input)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            using (var reader = new StringReader(input))
            {
                GitConfiguration.ParseGitConfig(reader, values);
            }
            return values;
        }

        [TestMethod]
        public void ReadThroughPublicMethods()
        {
            const string input = "\n" +
                    "[core]\n" +
                    "    autocrlf = false\n" +
                    "[credential \"microsoft.visualstudio.com\"]\n" +
                    "    authority = AAD\n" +
                    "[credential \"visualstudio.com\"]\n" +
                    "    authority = MSA\n" +
                    "[credential \"https://ntlm.visualstudio.com\"]\n" +
                    "    authority = NTLM\n" +
                    "[credential]\n" +
                    "    helper = manager\n" +
                    "";
            GitConfiguration cut;

            using (var sr = new StringReader(input))
            {
                cut = new GitConfiguration(sr);
            }

            Assert.AreEqual(true, cut.ContainsKey("CoRe.AuToCrLf"));
            Assert.AreEqual("false", cut["CoRe.AuToCrLf"]);

            GitConfiguration.Entry entry;
            Assert.AreEqual(true, cut.TryGetEntry("core", (string)null, "autocrlf", out entry));
            Assert.AreEqual("false", entry.Value);

            Assert.AreEqual(true, cut.TryGetEntry("credential", new Uri("https://microsoft.visualstudio.com"), "authority", out entry));
            Assert.AreEqual("AAD", entry.Value);

            Assert.AreEqual(true, cut.TryGetEntry("credential", new Uri("https://mseng.visualstudio.com"), "authority", out entry));
            Assert.AreEqual("MSA", entry.Value);

            Assert.AreEqual(true, cut.TryGetEntry("credential", new Uri("https://ntlm.visualstudio.com"), "authority", out entry));
            Assert.AreEqual("NTLM", entry.Value);
        }
    }
}
