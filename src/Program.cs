using CliWrap;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Threading;
using System.Security.Cryptography;

namespace webauthn_fido2_key_remover
{
    class Program
    {
        // possible todo, allow user to add more well-known rp-ids?
        private static Dictionary<string, string> WELL_KNOWN = new Dictionary<string, string>() {
            {"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763", "localhost"},
            {"f1ad9ac3edf2aa5a40daf387493fd145a8a77646aa580136153d1164c7fd84ea", "passwordless.dev"},
            {"2a5eaafcc2d24a02ab39abe897c4054439bc2a9545b4b2bf705e05ea80a9cce4", "corbado.com"},    
            {"d4c9d9027326271a89ce51fcaf328ed673f17be33469ff979e8ab8dd501e664f", "google.com"},
            {"24299f39915b1fa56eba4eec3ead519614e2d132296e7983ff5925529479d934", "microsoft.com"},
            {"3aeb002460381c6f258e8395d3026f571f0d9a76488dcd837639b13aed316560", "github.com"},
            {"d3b01d60bac9f29a1f0ed069b8aea3f95370de22077c342d2ea085a8bb9ee5b1", "passkeys.eu"},
            {"74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0", "webauthn.io"},
            {"22d7842bd07e91914913eb667901347d36fd353a04b7efcf797a92ab4b6554d7", "www.passkeys.io"},
            {"4fb20856f24a6ae7dafc2781090ac8477ae6e2bd072660236cc614c6fb7c2ea0", "webauthn.passwordless.id"},
            {"dd52225b9c6e7aafc9d4091b7f97c1b20cbe27644fc1685f65639ede1232aa22", "state-of-passkeys.io"},
            {"072e130838dc358756e2f866eafab913d8e31ad6d16f9639421a0ebc7d364b47", "passkeys.io"},
            {"39786ef9f3adeceead5fbc0b2f24fef355c1d958d6d331b276671fc9e901f359", "passkeys.dev"},
            {"ebdd0bdd81f37937b732e19d0d4d44cbdef3d0215e4ffc75910e0e4f5f8d479a", "passkeys.org"},
            {"eb661e072efd6892b90365e41c6519b92b8ed42d5c16d0500e5936824c871934", "passkey.com"},
            {"d4c8fd932415016dbfd34e1c1e854ca1f19b9f3372374dea44d3d1e978513722", "fido.consent.key.microsoft"},
            {"356c9ed4a09321b9695f1eaf918203f1b55f689da61fbc96184c157dda680c81", "login.microsoft.com"},
            {"b7c0c645305f96cf8184e1f6402e34e25bdd85efeddbf364bccd274161040037", "opotonniee.github.io"}
        };

        private static void LoadDomainHashes()
        {
            string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "domains.csv");

            if (File.Exists(filePath))
            {
                foreach (string line in File.ReadAllLines(filePath))
                {
                    string domain = line.Trim().ToLower(); 
                    string hash = ComputeSha256Hash(domain);
                    WELL_KNOWN[hash] = domain;
                }
            }

        }
        private static string ComputeSha256Hash(string text)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        static async Task Main(string[] args)
        {
            LoadDomainHashes();

            AnsiConsole.Write(new FigletText("Passwordless.dev").LeftJustified().Color(Color.Yellow));
 
            AnsiConsole.Write(new Rule());
            AnsiConsole.MarkupLine("A small tool built by Anders at https://passwordless.dev to list and remove Windows 10 WebAuthn Keys");
            AnsiConsole.MarkupLine("Use the Github repo to report issues or contribute: https://github.com/passwordless/webauthn-fido2-key-remover");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Note:[/] To delete keys, you need to run this tool as administrator. If you do not want to do that, you can run `certutil -csp NGC -delkey <name>` manually.");
            AnsiConsole.Write(new Rule());

            // Load keys using certutil
            string keyString = "";
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Arc)
                .StartAsync("Loading fido2 keys", async ctx =>
                {
                    string error = "";
                    (keyString, error) = await CertUtil("-csp NGC -key");
                });

            // Parse cert util response
            var keys = new List<FidoObject>();
            using (StringReader reader = new StringReader(keyString))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("FIDO"))
                    {
                        var details = line.Split("FIDO_AUTHENTICATOR//")[1];
                        var result = details.Split("_");
                        var f = new FidoObject() { Name = line, RpIdHash = result[0], UsernameHEX = result[1], Id = keys.Count + 1 };
                        keys.Add(f);
                    }
                }
            }

            AnsiConsole.MarkupLine("[bold] " + keys.Count + " keys found.[/]");
            AnsiConsole.MarkupLine("[bold]" + WELL_KNOWN.Count + " rpID-domain sha256-hashes loaded.[/]");

            // Select keys
            var keysToBeDeleted = AnsiConsole.Prompt(

                new MultiSelectionPrompt<string>()
                    .Title("Select keys to [red]delete[/]. Username - sha256 RP ID.")
                    .NotRequired() // Not required to have a favorite fruit
                    .PageSize(18)
                    .HighlightStyle(new Style(Color.Red, null, Decoration.Underline))
                    .MoreChoicesText("[grey](Move up and down to reveal more keys)[/]")
                    .InstructionsText(
                        "[grey](Press [red]<space>[/] to toggle a key, " +
                        "[green]<enter>[/] to procceed with removal)[/]")
                    .AddChoices(keys.Select(x =>
                        (x.Id + ". " + Markup.Escape(x.Username)).PadRight(40) + " - ".PadRight(5) + GetRpID(x.RpIdHash)))
                    );


            if (keysToBeDeleted.Count > 0)
            { 
                if (IsUserAdministrator() == false) 
                {
                    AnsiConsole.MarkupLine("[underline red]You need to restart with administrative priviledges to delete keys.[/]");
                }

                // Preview selected keys
                AnsiConsole.MarkupLine("Selected keys: ");
                foreach (var k in keysToBeDeleted)
                {
                    AnsiConsole.MarkupLine(k);
                }

                // Confirm deleteion?
                if (!AnsiConsole.Confirm("Delete " + keysToBeDeleted.Count + " keys?"))
                {
                    return;
                }

                // Delete
                foreach (var key in keysToBeDeleted)
                {
                    var rule = new Rule("[red]Deleting... [/]" + key);
                    rule.Justification = Justify.Left;

                    AnsiConsole.Write(rule);

                    var id = Convert.ToInt32(key.Split(".")[0]);
                    var name = keys.Single(x => x.Id == id).Name;
                    AnsiConsole.MarkupLine("[grey]certutil -csp NGC -delkey" + name + "[/]");
                    var (res, error) = await CertUtil("-csp NGC -delkey " + name);

                    AnsiConsole.MarkupLine("[grey]{0}[/]", Markup.Escape(res));
                }
            }


            Console.WriteLine("Program done... press anything to exit.");
            Console.ReadLine();
        }

        /// <summary>
        /// Prepend source string for well known hashes to increase readability
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        static private string GetRpID(string hash)
        {
            if (WELL_KNOWN.ContainsKey(hash))
            {
                return $"({WELL_KNOWN[hash]}) {hash}";
            }

            return hash;
        }

        /// <summary>
        /// Run a command ín the cli
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        static public async Task<(string result, string error)> CertUtil(string command)
        {
            var stdOutBuffer = new StringBuilder();
            var stdErrBuffer = new StringBuilder();
            var result = await Cli.Wrap("certutil")
                .WithArguments(command)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(stdOutBuffer))
                    .WithStandardErrorPipe(PipeTarget.ToStringBuilder(stdErrBuffer))
                    .WithValidation(CommandResultValidation.None)
                .ExecuteAsync();

            return (stdOutBuffer.ToString(), stdErrBuffer.ToString());
        }


        /// <summary>
        /// Represent a WebAutn credential / fido2 key
        /// </summary>
        public class FidoObject
        {

            private static UTF8Encoding encoding = new UTF8Encoding();
            public string Name { get; set; }
            public string UsernameHEX { get; set; }
            public string Username
            {
                get
                {
                    return ConvertHexToString(UsernameHEX, Encoding.UTF8);
                }
            }
            public string RpIdHash { get; set; }
            public int Id { get; internal set; }
        }


        private static string ConvertHexToString(string hexString, Encoding encoding)
        {
            byte[] bytes = StringToByteArray(hexString);
            string convertedString = encoding.GetString(bytes);

            // Use Regex to replace non-ASCII characters with "?"
            convertedString = Regex.Replace(convertedString, "[^\x20-\x7E]", "?");

            return convertedString;
        }
        
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private static bool IsUserAdministrator()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            return isAdmin;
        }        
    }
}
