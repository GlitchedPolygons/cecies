using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace GlitchedPolygons.CeciesSharp
{
    /// <summary>
    /// CeciesSharp class that wraps the native C functions from the CECIES library.
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

        private delegate void CeciesEnableFprintfDelegate();

        private delegate void CeciesDisableFprintfDelegate();

        private delegate bool CeciesIsFprintfEnabledDelegate();

        private delegate int CeciesGenerateKeypairCurve25519Delegate(
            ref CeciesKeypairCurve25519 output,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string additionalEntropy,
            [MarshalAs(UnmanagedType.U8)] ulong additionalEntropyLength
        );

        private delegate int CeciesEncryptCurve25519Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            CeciesKeyCurve25519 publicKey,
            [MarshalAs(UnmanagedType.LPArray)] byte[] output,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            ref ulong outputLength,
            [MarshalAs(UnmanagedType.Bool)] bool outputBase64
        );

        private delegate int CeciesDecryptCurve25519Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong encryptedDataLength,
            [MarshalAs(UnmanagedType.Bool)] bool encryptedDataBase64,
            CeciesKeyCurve25519 privateKey,
            [MarshalAs(UnmanagedType.LPArray)] byte[] output,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
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
            CeciesKeyCurve448 publicKey,
            [MarshalAs(UnmanagedType.LPArray)] byte[] output,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            ref ulong outputLength,
            [MarshalAs(UnmanagedType.Bool)] bool outputBase64
        );

        private delegate int CeciesDecryptCurve448Delegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong encryptedDataLength,
            [MarshalAs(UnmanagedType.Bool)] bool encryptedDataBase64,
            CeciesKeyCurve448 privateKey,
            [MarshalAs(UnmanagedType.LPArray)] byte[] output,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            ref ulong outputLength
        );

        private CeciesEnableFprintfDelegate ceciesEnableFprintfDelegate;
        private CeciesDisableFprintfDelegate ceciesDisableFprintfDelegate;
        private CeciesIsFprintfEnabledDelegate ceciesIsFprintfEnabledDelegate;
        private CeciesGenerateKeypairCurve25519Delegate ceciesGenerateKeypairCurve25519Delegate;
        private CeciesEncryptCurve25519Delegate ceciesEncryptCurve25519Delegate;
        private CeciesDecryptCurve25519Delegate ceciesDecryptCurve25519Delegate;
        private CeciesGenerateKeypairCurve448Delegate ceciesGenerateKeypairCurve448Delegate;
        private CeciesEncryptCurve448Delegate ceciesEncryptCurve448Delegate;
        private CeciesDecryptCurve448Delegate ceciesDecryptCurve448Delegate;

        #endregion

        private IntPtr lib;
        private ISharedLibLoadUtils loadUtils = null;

        public string LoadedLibraryPath { get; }

        /// <summary>
        /// Creates a new CeciesSharp instance. <para> </para>
        /// Make sure to create one only once and cache it as needed, since loading the DLLs into memory could be, well, not so performant.
        /// </summary>
        public CeciesSharpContext()
        {
            StringBuilder pathBuilder = new StringBuilder(256);
            pathBuilder.Append("lib/");

            switch (RuntimeInformation.ProcessArchitecture)
            {
                case Architecture.X64:
                    pathBuilder.Append("x64/");
                    break;
                case Architecture.X86:
                    pathBuilder.Append("x86/");
                    break;
                case Architecture.Arm:
                    pathBuilder.Append("armeabi-v7a/");
                    break;
                case Architecture.Arm64:
                    pathBuilder.Append("arm64-v8a/");
                    break;
            }

            if (!Directory.Exists(pathBuilder.ToString()))
            {
                throw new PlatformNotSupportedException($"CECIES shared library not found in {pathBuilder.ToString()} or unsupported CPU architecture");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                loadUtils = new SharedLibLoadUtilsWindows();
                pathBuilder.Append("windows/");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                loadUtils = new SharedLibLoadUtilsLinux();
                pathBuilder.Append("linux/");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                loadUtils = new SharedLibLoadUtilsMac();
                pathBuilder.Append("mac/");
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            string[] l = Directory.GetFiles(pathBuilder.ToString());
            if (l == null || l.Length != 1)
            {
                throw new FileLoadException("There should only be exactly one CECIES shared library file per supported platform!");
            }

            pathBuilder.Append(Path.GetFileName(l[0]));

            LoadedLibraryPath = Path.GetFullPath(pathBuilder.ToString());

            pathBuilder.Clear();

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
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

            ceciesEnableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<CeciesEnableFprintfDelegate>(enableFprintf);
            ceciesDisableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<CeciesDisableFprintfDelegate>(disableFprintf);
            ceciesIsFprintfEnabledDelegate = Marshal.GetDelegateForFunctionPointer<CeciesIsFprintfEnabledDelegate>(isFprintfEnabled);
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

        public void Dispose()
        {
            DisableConsoleLogging();
            loadUtils.FreeLibrary(lib);
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
        public bool IsConsoleLoggingEnabled
        {
            get => ceciesIsFprintfEnabledDelegate();
        }

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

        public byte[] EncryptCurve25519(byte[] data, string publicKey, bool outputBase64)
        {
            ulong olen = 0;
            byte[] o = new byte[CalcOutputBufferSize(data.LongLength)];
            CeciesKeyCurve25519 k = new CeciesKeyCurve25519 { hexString = publicKey };
            int r = ceciesEncryptCurve25519Delegate(data, (ulong)data.LongLength, k, o, (ulong)o.LongLength, ref olen, outputBase64);
            if (r != 0) return null;
            byte[] _o = new byte[olen];
            for (ulong i = 0; i < olen; i++)
            {
                _o[i] = o[i];
            }

            return _o;
        }

        public byte[] DecryptCurve25519(byte[] encryptedData, bool encryptedDataBase64, string privateKey)
        {
            ulong olen = 0;
            byte[] o = new byte[encryptedData.LongLength];
            CeciesKeyCurve25519 k = new CeciesKeyCurve25519 { hexString = privateKey };
            int r = ceciesDecryptCurve25519Delegate(encryptedData, (ulong)encryptedData.LongLength, encryptedDataBase64, k, o, (ulong)o.LongLength, ref olen);
            if (r != 0) return null;
            byte[] _o = new byte[olen];
            for (ulong i = 0; i < olen; i++)
            {
                _o[i] = o[i];
            }

            return _o;
        }

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

        public byte[] EncryptCurve448(byte[] data, string publicKey, bool outputBase64)
        {
            ulong olen = 0;
            byte[] o = new byte[CalcOutputBufferSize(data.LongLength)];
            CeciesKeyCurve448 k = new CeciesKeyCurve448 { hexString = publicKey };
            if (ceciesEncryptCurve448Delegate(data, (ulong)data.LongLength, k, o, (ulong)o.LongLength, ref olen, outputBase64) != 0) return null;
            byte[] _o = new byte[olen];
            for (ulong i = 0; i < olen; i++)
            {
                _o[i] = o[i];
            }

            return _o;
        }

        public byte[] DecryptCurve448(byte[] encryptedData, bool encryptedDataBase64, string privateKey)
        {
            ulong olen = 0;
            byte[] o = new byte[encryptedData.LongLength];
            CeciesKeyCurve448 k = new CeciesKeyCurve448 { hexString = privateKey };
            int r = ceciesDecryptCurve448Delegate(encryptedData, (ulong)encryptedData.LongLength, encryptedDataBase64, k, o, (ulong)o.LongLength, ref olen);
            if (r != 0) return null;
            byte[] _o = new byte[olen];
            for (ulong i = 0; i < olen; i++)
            {
                _o[i] = o[i];
            }

            return _o;
        }

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