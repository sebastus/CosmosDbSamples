using System;
using McMaster.Extensions.CommandLineUtils;
using Newtonsoft.Json;

namespace CosmosHashedTokenSig
{
    class Program
    {
        static void Main(string[] args) => CommandLineApplication.Execute<Program>(args);

        [Option("-b | --verb", Description = "http verb")]
        public string Verb { get; }

        [Option("-i | --id", Description = "module id")]
        public string ModuleId { get; }

        [Option("-v | --verbose", Description = "verbose output")]
        public bool Verbose { get; }

        [Option("-d | --database", Description = "CosmosDb Database Name")]
        public string Database { get; set; } = "SoR_Core_Db";

        [Option("-c | --collection", Description = "CosmosDb Collection Name")]
        public string Collection { get; set; } = "ModuleRegistry";

        [Option("-k | --key", Description = "master key")]
        public string MasterKey { get; set; } = "";

        private void OnExecute()
        {

            string resourceLink = $"dbs/{Database}/colls/{Collection}/docs/{ModuleId}";

            string date = DateTime.UtcNow.ToString("r");
            string keyType = "master";
            string tokenVersion = "1.0";
            string resourceType = "docs";

            var token = GenerateAuthToken(Verb, resourceType, resourceLink, date, MasterKey, keyType, tokenVersion);

            if (Verbose)
            {
                Console.WriteLine("Verb: {0}", Verb);
                Console.WriteLine("id: {0}", ModuleId);
                Console.WriteLine("resourceType: {0}", resourceType);
                Console.WriteLine("resourceLink: {0}", resourceLink);
                Console.WriteLine("date: {0}", date);
                Console.WriteLine("keyType: {0}", keyType);
                Console.WriteLine("tokenVersion: {0}", tokenVersion);
                Console.WriteLine("token value: {0}", token);
            } else
            {
                var tokenOutput = new tokenOutput { date = date, token = token };

                Console.WriteLine(JsonConvert.SerializeObject(tokenOutput));
            }

        }

        public class tokenOutput
        {
            public string date { get; set; }
            public string token { get; set; }
        }

        static string GenerateAuthToken(string verb, string resourceType, string resourceId, string date, string key, string keyType, string tokenVersion)
        {
            var hmacSha256 = new System.Security.Cryptography.HMACSHA256 { Key = Convert.FromBase64String(key) };

            verb = verb ?? "";
            resourceType = resourceType ?? "";
            resourceId = resourceId ?? "";

            string payLoad = string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}\n{1}\n{2}\n{3}\n{4}\n",
                    verb.ToLowerInvariant(),
                    resourceType.ToLowerInvariant(),
                    resourceId,
                    date.ToLowerInvariant(),
                    ""
            );

            byte[] hashPayLoad = hmacSha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(payLoad));
            string signature = Convert.ToBase64String(hashPayLoad);

            return System.Web.HttpUtility.UrlEncode(String.Format(System.Globalization.CultureInfo.InvariantCulture, "type={0}&ver={1}&sig={2}",
                keyType,
                tokenVersion,
                signature));
        }
    }
}
