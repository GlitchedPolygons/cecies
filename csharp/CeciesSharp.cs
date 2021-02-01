using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace GlitchedPolygons.CeciesSharp
{
    /// <summary>
    /// CeciesSharp class that wraps the native C functions from the CECIES library. <para> </para>
    /// Copy this class into your own C# project and then don't forget to
    /// copy the lib/ folder to your own project's build output directory!
    /// </summary>
    public class CeciesSharpContext : IDisposable
    {
        #region Shared library loaders (per platform implementations)

        private interface ISharedLibLoadUtils
        {
            IntPtr LoadLibrary(string fileName);
            void FreeLibrary(IntPtr handle);
            IntPtr GetProcAddress(IntPtr handle, string name);
        }

        private class SharedLibLoadUtilsWindows : ISharedLibLoadUtils
        {
            [DllImport("kernel32.dll")]
            private static extern IntPtr LoadLibrary(string fileName);

            [DllImport("kernel32.dll")]
            private static extern int FreeLibrary(IntPtr handle);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr handle, string procedureName);

            void ISharedLibLoadUtils.FreeLibrary(IntPtr handle)
            {
                FreeLibrary(handle);
            }

            IntPtr ISharedLibLoadUtils.GetProcAddress(IntPtr dllHandle, string name)
            {
                return GetProcAddress(dllHandle, name);
            }

            IntPtr ISharedLibLoadUtils.LoadLibrary(string fileName)
            {
                return LoadLibrary(fileName);
            }
        }

        private class SharedLibLoadUtilsLinux : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.so")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.so")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.so")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.so")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        private class SharedLibLoadUtilsMac : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.dylib")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        #endregion

        #region Struct mapping

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct CeciesKeyCurve25519
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64 + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CeciesKeypairCurve25519
        {
            public CeciesKeyCurve25519 publicKey;
            public CeciesKeyCurve25519 privateKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct CeciesKeyCurve448
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 112 + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CeciesKeypairCurve448
        {
            public CeciesKeyCurve448 publicKey;
            public CeciesKeyCurve448 privateKey;
        }

        #endregion

        #region Function mapping

        private delegate void CeciesFreeDelegate(IntPtr mem);

        private delegate void CeciesEnableFprintfDelegate();

        private delegate void CeciesDisableFprintfDelegate();

        private delegate byte CeciesIsFprintfEnabledDelegate();

        private delegate ulong CeciesGetVersionNumberDelegate();

        private delegate IntPtr CeciesGetVersionNumberStringDelegate();

        private delegate int CeciesGenerateKeypairCurve25519Delegate(
            ref CeciesKeypairCurve25519 output,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string additionalEntropy,
            [MarshalAs(UnmanagedType.U8)] ulong additionalEntropyLength
        );

        private delegate int CeciesEncryptCurve25519Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.I4)] int compress,
            CeciesKeyCurve25519 publicKey,
            out IntPtr output,
            ref ulong outputLength,
            [MarshalAs(UnmanagedType.Bool)] bool outputBase64
        );

        private delegate int CeciesDecryptCurve25519Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong encryptedDataLength,
            [MarshalAs(UnmanagedType.Bool)] bool encryptedDataBase64,
            CeciesKeyCurve25519 privateKey,
            out IntPtr output,
            ref ulong outputLength
        );

        private delegate int CeciesGenerateKeypairCurve448Delegate(
            ref CeciesKeypairCurve448 output,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string additionalEntropy,
            [MarshalAs(UnmanagedType.U8)] ulong additionalEntropyLength
        );

        private delegate int CeciesEncryptCurve448Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.I4)] int compress,
            CeciesKeyCurve448 publicKey,
            out IntPtr output,
            ref ulong outputLength,
            [MarshalAs(UnmanagedType.Bool)] bool outputBase64
        );

        private delegate int CeciesDecryptCurve448Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong encryptedDataLength,
            [MarshalAs(UnmanagedType.Bool)] bool encryptedDataBase64,
            CeciesKeyCurve448 privateKey,
            out IntPtr output,
            ref ulong outputLength
        );

        private CeciesFreeDelegate ceciesFreeDelegate;
        private CeciesEnableFprintfDelegate ceciesEnableFprintfDelegate;
        private CeciesDisableFprintfDelegate ceciesDisableFprintfDelegate;
        private CeciesIsFprintfEnabledDelegate ceciesIsFprintfEnabledDelegate;
        private CeciesGetVersionNumberDelegate ceciesGetVersionNumberDelegate;
        private CeciesGetVersionNumberStringDelegate ceciesGetVersionNumberStringDelegate;
        private CeciesGenerateKeypairCurve25519Delegate ceciesGenerateKeypairCurve25519Delegate;
        private CeciesEncryptCurve25519Delegate ceciesEncryptCurve25519Delegate;
        private CeciesDecryptCurve25519Delegate ceciesDecryptCurve25519Delegate;
        private CeciesGenerateKeypairCurve448Delegate ceciesGenerateKeypairCurve448Delegate;
        private CeciesEncryptCurve448Delegate ceciesEncryptCurve448Delegate;
        private CeciesDecryptCurve448Delegate ceciesDecryptCurve448Delegate;

        #endregion

        private IntPtr lib;
        private ISharedLibLoadUtils loadUtils = null;

        /// <summary>
        /// Absolute path to the CECIES shared library that is currently loaded into memory for CeciesSharp.
        /// </summary>
        public string LoadedLibraryPath { get; }

        /// <summary>
        /// Creates a new CeciesSharp instance. <para> </para>
        /// Make sure to create one only once and cache it as needed, since loading the DLLs into memory could be, well, not so performant.
        /// <param name="sharedLibPathOverride">[OPTIONAL] Don't look for a <c>lib/</c> folder and directly use this path as a pre-resolved, platform-specific shared lib/DLL file path. Pass this if you want to handle the various platform's paths yourself.</param>
        /// </summary>
        public CeciesSharpContext(string sharedLibPathOverride = null)
        {
            string os;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
                loadUtils = new SharedLibLoadUtilsWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
                loadUtils = new SharedLibLoadUtilsLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "mac";
                loadUtils = new SharedLibLoadUtilsMac();
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            if (!string.IsNullOrEmpty(sharedLibPathOverride))
            {
                LoadedLibraryPath = sharedLibPathOverride;
            }
            else
            {
                string cpu = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => "x64",
                    Architecture.X86 => "x86",
                    Architecture.Arm => "armeabi-v7a",
                    Architecture.Arm64 => "arm64-v8a",
                    _ => throw new PlatformNotSupportedException("CPU Architecture not supported!")
                };

                string path = Path.Combine(Path.GetFullPath(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location) ?? "."), "lib", cpu, os);

                if (!Directory.Exists(path))
                {
                    throw new PlatformNotSupportedException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }

                bool found = false;
                foreach (string file in Directory.GetFiles(path))
                {
                    if (file.ToLower().Contains("cecies"))
                    {
                        LoadedLibraryPath = Path.GetFullPath(Path.Combine(path, file));
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new FileLoadException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }
            }

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr free = loadUtils.GetProcAddress(lib, "cecies_free");
            if (free == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr enableFprintf = loadUtils.GetProcAddress(lib, "cecies_enable_fprintf");
            if (enableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr disableFprintf = loadUtils.GetProcAddress(lib, "cecies_disable_fprintf");
            if (disableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr isFprintfEnabled = loadUtils.GetProcAddress(lib, "cecies_is_fprintf_enabled");
            if (isFprintfEnabled == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionNr = loadUtils.GetProcAddress(lib, "cecies_get_version_nr");
            if (getVersionNr == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionStr = loadUtils.GetProcAddress(lib, "cecies_get_version_str");
            if (getVersionStr == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr gen25519 = loadUtils.GetProcAddress(lib, "cecies_generate_curve25519_keypair");
            if (gen25519 == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr enc25519 = loadUtils.GetProcAddress(lib, "cecies_curve25519_encrypt");
            if (enc25519 == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr dec25519 = loadUtils.GetProcAddress(lib, "cecies_curve25519_decrypt");
            if (dec25519 == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr gen448 = loadUtils.GetProcAddress(lib, "cecies_generate_curve448_keypair");
            if (gen448 == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr enc448 = loadUtils.GetProcAddress(lib, "cecies_curve448_encrypt");
            if (enc448 == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr dec448 = loadUtils.GetProcAddress(lib, "cecies_curve448_decrypt");
            if (dec448 == IntPtr.Zero)
            {
                goto hell;
            }

            ceciesFreeDelegate = Marshal.GetDelegateForFunctionPointer<CeciesFreeDelegate>(free);
            ceciesEnableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<CeciesEnableFprintfDelegate>(enableFprintf);
            ceciesDisableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<CeciesDisableFprintfDelegate>(disableFprintf);
            ceciesIsFprintfEnabledDelegate = Marshal.GetDelegateForFunctionPointer<CeciesIsFprintfEnabledDelegate>(isFprintfEnabled);
            ceciesGetVersionNumberDelegate = Marshal.GetDelegateForFunctionPointer<CeciesGetVersionNumberDelegate>(getVersionNr);
            ceciesGetVersionNumberStringDelegate = Marshal.GetDelegateForFunctionPointer<CeciesGetVersionNumberStringDelegate>(getVersionStr);
            ceciesGenerateKeypairCurve25519Delegate = Marshal.GetDelegateForFunctionPointer<CeciesGenerateKeypairCurve25519Delegate>(gen25519);
            ceciesEncryptCurve25519Delegate = Marshal.GetDelegateForFunctionPointer<CeciesEncryptCurve25519Delegate>(enc25519);
            ceciesDecryptCurve25519Delegate = Marshal.GetDelegateForFunctionPointer<CeciesDecryptCurve25519Delegate>(dec25519);
            ceciesGenerateKeypairCurve448Delegate = Marshal.GetDelegateForFunctionPointer<CeciesGenerateKeypairCurve448Delegate>(gen448);
            ceciesEncryptCurve448Delegate = Marshal.GetDelegateForFunctionPointer<CeciesEncryptCurve448Delegate>(enc448);
            ceciesDecryptCurve448Delegate = Marshal.GetDelegateForFunctionPointer<CeciesDecryptCurve448Delegate>(dec448);

            EnableConsoleLogging();

            return;

            hell:
            throw new Exception($"Failed to load one or more functions from the CECIES shared library \"{LoadedLibraryPath}\"!");
        }

        /// <summary>
        /// Frees unmanaged resources (unloads the CECIES shared lib/dll).
        /// </summary>
        public void Dispose()
        {
            DisableConsoleLogging();
            loadUtils.FreeLibrary(lib);
        }

        private static byte[] MarshalReadBytes(IntPtr array, ulong arrayLength, int bufferSize = 1024 * 256)
        {
            using var ms = new MemoryStream((int)arrayLength);

            IntPtr i = array;
            ulong rem = arrayLength;
            byte[] buf = new byte[bufferSize];

            while (rem != 0)
            {
                int n = (int)Math.Min(rem, (ulong)buf.LongLength);
                Marshal.Copy(i, buf, 0, n);
                i = IntPtr.Add(i, n);
                rem -= (ulong)n;
                ms.Write(buf, 0, n);
            }

            return ms.ToArray();
        }

        private static long CalcOutputBufferSize(long l)
        {
            return 4 * (long)Math.Ceiling((l + 256) / 3.0d);
        }

        /// <summary>
        /// Enables CECIES' use of fprintf(). 
        /// </summary>
        public void EnableConsoleLogging()
        {
            ceciesEnableFprintfDelegate();
        }

        /// <summary>
        /// Disables CECIES' use of fprintf().
        /// </summary>
        public void DisableConsoleLogging()
        {
            ceciesDisableFprintfDelegate();
        }

        /// <summary>
        /// Check whether CECIES is allowed to fprintf() into stdout or not.
        /// </summary>
        public bool IsConsoleLoggingEnabled()
        {
            byte r = ceciesIsFprintfEnabledDelegate();
            return r != 0;
        }

        /// <summary>
        /// Get the current CECIES version number (numeric).
        /// </summary>
        /// <returns>Unsigned integer containing the currently used CECIES version number.</returns>
        public ulong GetVersionNumber()
        {
            return ceciesGetVersionNumberDelegate();
        }

        /// <summary>
        /// Get the current CECIES version number (nicely formatted, human-readable string).
        /// </summary>
        /// <returns>CECIES version number as a nicely formatted, human-readable string.</returns>
        public string GetVersionNumberString()
        {
            IntPtr ptr = ceciesGetVersionNumberStringDelegate();
            return Marshal.PtrToStringUTF8(ptr);
        }

        /// <summary>
        /// Generates a Curve25519 key-pair for encrypting/decrypting via ECIES.
        /// </summary>
        /// <param name="additionalEntropy">[OPTIONAL] Additional entropy for the key generation.</param>
        /// <returns><c>(null,null)</c> if key generation failed; a <c>(publicKey,privateKey)</c> tuple if the operation succeeded.</returns>
        public ValueTuple<string, string> GenerateKeypairCurve25519(string additionalEntropy)
        {
            if (string.IsNullOrEmpty(additionalEntropy))
            {
                using RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                Span<byte> rnd = stackalloc byte[32];
                rng.GetBytes(rnd);
                additionalEntropy = Encoding.UTF8.GetString(rnd) + Guid.NewGuid().ToString("B");
            }

            CeciesKeypairCurve25519 kp = new CeciesKeypairCurve25519();
            int r = ceciesGenerateKeypairCurve25519Delegate(ref kp, additionalEntropy, (ulong)additionalEntropy.Length);
            return r == 0 ? (kp.publicKey.hexString, kp.privateKey.hexString) : (null, null);
        }

        /// <summary>
        /// Encrypts a given chunk of data using a Curve25519 public key (hex-formatted).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="compress">Should the <paramref name="data"/> be compressed before being encrypted? Pass any integer value between [0; 9] (where \c 0 is no compression at all and \c 9 is highest but slowest compression).</param>
        /// <param name="publicKey">The public key to encrypt the data with.</param>
        /// <param name="outputBase64">Should the output be base64-encoded UTF8 bytes? (Human-readable vs just raw binary ciphertext).</param>
        /// <returns><c>null</c> if encryption failed (check the stderr console output in this case for more details); the encrypted bytes if encryption succeeded.</returns>
        public byte[] EncryptCurve25519(byte[] data, int compress, string publicKey, bool outputBase64)
        {
            ulong olen = 0;
            CeciesKeyCurve25519 k = new CeciesKeyCurve25519 { hexString = publicKey };

            int r = ceciesEncryptCurve25519Delegate(data, (ulong)data.LongLength, compress, k, out IntPtr output, ref olen, outputBase64);
            if (r != 0) return null;

            byte[] o = MarshalReadBytes(output, olen);

            ceciesFreeDelegate(output);
            return o;
        }

        /// <summary>
        /// Decrypts a given chunk of data using a Curve25519 private key (hex-formatted).
        /// </summary>
        /// <param name="encryptedData">The data to decrypt.</param>
        /// <param name="encryptedDataBase64">Is the passed ciphertext base64-encoded or raw?.</param>
        /// <param name="privateKey">The private key to decrypt the data with (hex-formatted).</param>
        /// <returns><c>null</c> if decryption failed (check the stderr console output in this case for more details); the decrypted bytes if decryption succeeded.</returns>
        public byte[] DecryptCurve25519(byte[] encryptedData, bool encryptedDataBase64, string privateKey)
        {
            ulong olen = 0;
            CeciesKeyCurve25519 k = new CeciesKeyCurve25519 { hexString = privateKey };

            int r = ceciesDecryptCurve25519Delegate(encryptedData, (ulong)encryptedData.LongLength, encryptedDataBase64, k, out IntPtr output, ref olen);
            if (r != 0) return null;

            byte[] o = MarshalReadBytes(output, olen);

            ceciesFreeDelegate(output);
            return o;
        }

        /// <summary>
        /// Generates a Curve448 key-pair for encrypting/decrypting via ECIES.
        /// </summary>
        /// <param name="additionalEntropy">[OPTIONAL] Additional entropy for the key generation.</param>
        /// <returns><c>(null,null)</c> if key generation failed; a <c>(publicKey,privateKey)</c> tuple if the operation succeeded.</returns>
        public ValueTuple<string, string> GenerateKeypairCurve448(string additionalEntropy)
        {
            if (string.IsNullOrEmpty(additionalEntropy))
            {
                using RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                Span<byte> rnd = stackalloc byte[32];
                rng.GetBytes(rnd);
                additionalEntropy = Encoding.UTF8.GetString(rnd) + Guid.NewGuid().ToString("B");
            }

            CeciesKeypairCurve448 kp = new CeciesKeypairCurve448();
            int r = ceciesGenerateKeypairCurve448Delegate(ref kp, additionalEntropy, (ulong)additionalEntropy.Length);
            return r == 0 ? (kp.publicKey.hexString, kp.privateKey.hexString) : (null, null);
        }

        /// <summary>
        /// Encrypts a given chunk of data using a Curve448 public key (hex-formatted).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="compress">Should the <paramref name="data"/> be compressed before being encrypted? Pass any integer value between [0; 9] (where \c 0 is no compression at all and \c 9 is highest but slowest compression).</param>
        /// <param name="publicKey">The public key to encrypt the data with.</param>
        /// <param name="outputBase64">Should the output be base64-encoded UTF8 bytes? (Human-readable vs just raw binary ciphertext).</param>
        /// <returns><c>null</c> if encryption failed (check the stderr console output in this case for more details); the encrypted bytes if encryption succeeded.</returns>
        public byte[] EncryptCurve448(byte[] data, int compress, string publicKey, bool outputBase64)
        {
            ulong olen = 0;
            CeciesKeyCurve448 k = new CeciesKeyCurve448 { hexString = publicKey };

            int r = ceciesEncryptCurve448Delegate(data, (ulong)data.LongLength, compress, k, out IntPtr output, ref olen, outputBase64);
            if (r != 0) return null;

            byte[] o = MarshalReadBytes(output, olen);

            ceciesFreeDelegate(output);
            return o;
        }

        /// <summary>
        /// Decrypts a given chunk of data using a Curve448 private key (hex-formatted).
        /// </summary>
        /// <param name="encryptedData">The data to decrypt.</param>
        /// <param name="encryptedDataBase64">Is the passed ciphertext base64-encoded or raw?.</param>
        /// <param name="privateKey">The private key to decrypt the data with (hex-formatted).</param>
        /// <returns><c>null</c> if decryption failed (check the stderr console output in this case for more details); the decrypted bytes if decryption succeeded.</returns>
        public byte[] DecryptCurve448(byte[] encryptedData, bool encryptedDataBase64, string privateKey)
        {
            ulong olen = 0;
            CeciesKeyCurve448 k = new CeciesKeyCurve448 { hexString = privateKey };

            int r = ceciesDecryptCurve448Delegate(encryptedData, (ulong)encryptedData.LongLength, encryptedDataBase64, k, out IntPtr output, ref olen);
            if (r != 0) return null;

            byte[] o = MarshalReadBytes(output, olen);

            ceciesFreeDelegate(output);
            return o;
        }
    }

    //  --------------------------------------------------------------------
    //  ------------------------------> DEMO <------------------------------
    //  --------------------------------------------------------------------

    internal static class Example
    {
        // DEMO
        // This is an example Main method that shows how the various CeciesSharp wrapper functionalities can be used.
        // Don't forget to copy the CeciesSharp/src/lib folder into your output build directory, otherwise CeciesSharp doesn't know from where to load the DLL/shared lib!

        private static void Main(string[] args)
        {
            using var cecies = new CeciesSharpContext();
            cecies.EnableConsoleLogging();

            Console.WriteLine("Allow fprintf: " + cecies.IsConsoleLoggingEnabled());

            Console.WriteLine($"CECIES Version: {cecies.GetVersionNumberString()} ({cecies.GetVersionNumber()})" + Environment.NewLine);

            (string, string) keyPair25519 = cecies.GenerateKeypairCurve25519(null);
            Console.WriteLine($"Generated Curve25519 Key Pair:\nPub: {keyPair25519.Item1}\nPrv: {keyPair25519.Item2}");

            (string, string) keyPair448 = cecies.GenerateKeypairCurve448(null);
            Console.WriteLine($"Generated Curve448 Key Pair:\nPub: {keyPair448.Item1}\nPrv: {keyPair448.Item2}");

            byte[] plaintext = Encoding.UTF8.GetBytes("Test test test FKSOGUEidbbpyqkr3dgkb 349749t43t ö ä $ _} \\ hg9\\'8gkjn ;;;");

            string ciphertextCurve25519 = Encoding.UTF8.GetString(cecies.EncryptCurve25519(plaintext, 0, keyPair25519.Item1, true));
            string ciphertextCurve448 = Encoding.UTF8.GetString(cecies.EncryptCurve448(plaintext, 0, keyPair448.Item1, true));

            Console.WriteLine($"Encrypt Curve25519: {ciphertextCurve25519} \n Ciphertext length: {ciphertextCurve25519.Length}");
            Console.WriteLine($"Encrypt Curve448: {ciphertextCurve448} \n Ciphertext length: {ciphertextCurve448.Length}");

            string decStr25519 = Encoding.UTF8.GetString(cecies.DecryptCurve25519(Encoding.UTF8.GetBytes(ciphertextCurve25519), true, keyPair25519.Item2));
            string decStr448 = Encoding.UTF8.GetString(cecies.DecryptCurve448(Encoding.UTF8.GetBytes(ciphertextCurve448), true, keyPair448.Item2));

            Console.WriteLine($"Decrypt Curve25519: {decStr25519}");
            Console.WriteLine($"Decrypt Curve448: {decStr448}");

            cecies.DisableConsoleLogging();

            Console.WriteLine("Allow fprintf: " + cecies.IsConsoleLoggingEnabled());
        }
    }
}