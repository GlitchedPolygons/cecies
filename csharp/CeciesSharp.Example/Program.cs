using System;
using System.Text;

namespace GlitchedPolygons.CeciesSharp.Example
{
    class Program
    {
        static void Main(string[] args)
        {
            using var ceciesSharp = new CeciesSharpContext();
            ceciesSharp.EnableConsoleLogging();

            Console.WriteLine("Allow fprintf: " + ceciesSharp.IsConsoleLoggingEnabled);

            (string, string) keyPair25519 = ceciesSharp.GenerateKeypairCurve25519(null);
            Console.WriteLine($"Generated Curve25519 Key Pair:\nPub: {keyPair25519.Item1}\nPrv: {keyPair25519.Item2}");

            (string, string) keyPair448 = ceciesSharp.GenerateKeypairCurve448(null);
            Console.WriteLine($"Generated Curve448 Key Pair:\nPub: {keyPair448.Item1}\nPrv: {keyPair448.Item2}");

            byte[] plaintext = Encoding.UTF8.GetBytes("Test test test FKSOGUEidbbpyqkr3dgkb 349749t43t ö ä $ _} \\ hg9\\'8gkjn ;;;");

            string ciphertextCurve25519 = Encoding.UTF8.GetString(ceciesSharp.EncryptCurve25519(plaintext, keyPair25519.Item1, true));
            string ciphertextCurve448 = Encoding.UTF8.GetString(ceciesSharp.EncryptCurve448(plaintext, keyPair448.Item1, true));

            Console.WriteLine($"Encrypt Curve25519: {ciphertextCurve25519} \n Ciphertext length: {ciphertextCurve25519.Length}");
            Console.WriteLine($"Encrypt Curve448: {ciphertextCurve448} \n Ciphertext length: {ciphertextCurve448.Length}");

            string decStr25519 = Encoding.UTF8.GetString(ceciesSharp.DecryptCurve25519(Encoding.UTF8.GetBytes(ciphertextCurve25519), true, keyPair25519.Item2));
            string decStr448 = Encoding.UTF8.GetString(ceciesSharp.DecryptCurve448(Encoding.UTF8.GetBytes(ciphertextCurve448), true, keyPair448.Item2));

            Console.WriteLine($"Decrypt Curve25519: {decStr25519}");
            Console.WriteLine($"Decrypt Curve448: {decStr448}");

            ceciesSharp.DisableConsoleLogging();

            Console.WriteLine("Allow fprintf: " + ceciesSharp.IsConsoleLoggingEnabled);
        }
    }
}
