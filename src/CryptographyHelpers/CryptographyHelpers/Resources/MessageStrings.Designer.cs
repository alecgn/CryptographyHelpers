﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace CryptographyHelpers.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "16.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class MessageStrings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal MessageStrings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("CryptographyHelpers.Resources.MessageStrings", typeof(MessageStrings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input bytes cannot be null or empty..
        /// </summary>
        internal static string Bytes_InvalidInputBytes {
            get {
                return ResourceManager.GetString("Bytes.InvalidInputBytes", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid AES IV (null or wrong size)..
        /// </summary>
        internal static string Cryptography_InvalidAESIV {
            get {
                return ResourceManager.GetString("Cryptography.InvalidAESIV", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid AES key (null or wrong size)..
        /// </summary>
        internal static string Cryptography_InvalidAESKey {
            get {
                return ResourceManager.GetString("Cryptography.InvalidAESKey", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Encoded input text to decode required..
        /// </summary>
        internal static string Decoding_InputEncodedTextRequired {
            get {
                return ResourceManager.GetString("Decoding.InputEncodedTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Data succesfully decrypted..
        /// </summary>
        internal static string Decryption_DataDecryptionSuccess {
            get {
                return ResourceManager.GetString("Decryption.DataDecryptionSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to File succesfully decrypted..
        /// </summary>
        internal static string Decryption_FileDecryptionSuccess {
            get {
                return ResourceManager.GetString("Decryption.FileDecryptionSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input bytes to decrypt required..
        /// </summary>
        internal static string Decryption_InputBytesRequired {
            get {
                return ResourceManager.GetString("Decryption.InputBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input text to decrypt required..
        /// </summary>
        internal static string Decryption_InputTextRequired {
            get {
                return ResourceManager.GetString("Decryption.InputTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input text to encode required..
        /// </summary>
        internal static string Encoding_InputTextRequired {
            get {
                return ResourceManager.GetString("Encoding.InputTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Data encrypted succesfully..
        /// </summary>
        internal static string Encryption_DataEncryptionSuccess {
            get {
                return ResourceManager.GetString("Encryption.DataEncryptionSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to File encrypted succesfully..
        /// </summary>
        internal static string Encryption_FileEncryptionSuccess {
            get {
                return ResourceManager.GetString("Encryption.FileEncryptionSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input bytes to encrypt required..
        /// </summary>
        internal static string Encryption_InputBytesRequired {
            get {
                return ResourceManager.GetString("Encryption.InputBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input text to encrypt required..
        /// </summary>
        internal static string Encryption_InputTextRequired {
            get {
                return ResourceManager.GetString("Encryption.InputTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to File not found:.
        /// </summary>
        internal static string File_PathNotFound {
            get {
                return ResourceManager.GetString("File.PathNotFound", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Source and destination file paths cannot be equal..
        /// </summary>
        internal static string File_SourceAndDestinationPathsEqual {
            get {
                return ResourceManager.GetString("File.SourceAndDestinationPathsEqual", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Hash computed succesfully..
        /// </summary>
        internal static string Hash_ComputeSuccess {
            get {
                return ResourceManager.GetString("Hash.ComputeSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input data and verification hash does not match..
        /// </summary>
        internal static string Hash_DoesNotMatch {
            get {
                return ResourceManager.GetString("Hash.DoesNotMatch", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input bytes to compute hash required..
        /// </summary>
        internal static string Hash_InputBytesRequired {
            get {
                return ResourceManager.GetString("Hash.InputBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input text to compute/verify hash required..
        /// </summary>
        internal static string Hash_InputTextRequired {
            get {
                return ResourceManager.GetString("Hash.InputTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input data and verification hash does match..
        /// </summary>
        internal static string Hash_Match {
            get {
                return ResourceManager.GetString("Hash.Match", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Verification hash bytes required..
        /// </summary>
        internal static string Hash_VerificationHashBytesRequired {
            get {
                return ResourceManager.GetString("Hash.VerificationHashBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Verification hash string required..
        /// </summary>
        internal static string Hash_VerificationHashStringRequired {
            get {
                return ResourceManager.GetString("Hash.VerificationHashStringRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to HMAC computed succesfully..
        /// </summary>
        internal static string HMAC_ComputeSuccess {
            get {
                return ResourceManager.GetString("HMAC.ComputeSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input data and verification HMAC does not match..
        /// </summary>
        internal static string HMAC_DoesNotMatch {
            get {
                return ResourceManager.GetString("HMAC.DoesNotMatch", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input bytes to compute/verify HMAC required..
        /// </summary>
        internal static string HMAC_InputBytesRequired {
            get {
                return ResourceManager.GetString("HMAC.InputBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input encoded key string to compute/verify HMAC required..
        /// </summary>
        internal static string HMAC_InputEncodedKeyStringRequired {
            get {
                return ResourceManager.GetString("HMAC.InputEncodedKeyStringRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input text to compute/verify HMAC required..
        /// </summary>
        internal static string HMAC_InputTextRequired {
            get {
                return ResourceManager.GetString("HMAC.InputTextRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input data and verification HMAC does match..
        /// </summary>
        internal static string HMAC_Match {
            get {
                return ResourceManager.GetString("HMAC.Match", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Verification HMAC bytes required..
        /// </summary>
        internal static string HMAC_VerificationHMACBytesRequired {
            get {
                return ResourceManager.GetString("HMAC.VerificationHMACBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Verification HMAC string required..
        /// </summary>
        internal static string HMAC_VerificationHMACStringRequired {
            get {
                return ResourceManager.GetString("HMAC.VerificationHMACStringRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Key derived succesfully..
        /// </summary>
        internal static string KeyDerivation_DerivationSuccess {
            get {
                return ResourceManager.GetString("KeyDerivation.DerivationSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Number of bytes requested from key derivation required (must be greater than 0)..
        /// </summary>
        internal static string KeyDerivation_InvalidBytesRequested {
            get {
                return ResourceManager.GetString("KeyDerivation.InvalidBytesRequested", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input key bytes required for key verification..
        /// </summary>
        internal static string KeyDerivation_KeyBytesRequired {
            get {
                return ResourceManager.GetString("KeyDerivation.KeyBytesRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input password string required for key derivation..
        /// </summary>
        internal static string KeyDerivation_PasswordStringRequired {
            get {
                return ResourceManager.GetString("KeyDerivation.PasswordStringRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid base64 input string..
        /// </summary>
        internal static string Strings_InvalidBase64InputString {
            get {
                return ResourceManager.GetString("Strings.InvalidBase64InputString", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid hexadecimal input string..
        /// </summary>
        internal static string Strings_InvalidHexadecimalInputString {
            get {
                return ResourceManager.GetString("Strings.InvalidHexadecimalInputString", resourceCulture);
            }
        }
    }
}
