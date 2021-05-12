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
        ///   Looks up a localized string similar to Input byte array cannot be null or empty..
        /// </summary>
        internal static string ByteArray_InvalidInputByteArray {
            get {
                return ResourceManager.GetString("ByteArray.InvalidInputByteArray", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input file cannot be empty (0 bytes)..
        /// </summary>
        internal static string File_EmptyInputFile {
            get {
                return ResourceManager.GetString("File.EmptyInputFile", resourceCulture);
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
        ///   Looks up a localized string similar to Input hash computed succesfully..
        /// </summary>
        internal static string Hash_ComputeSuccess {
            get {
                return ResourceManager.GetString("Hash.ComputeSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input hash and verification hash does not match..
        /// </summary>
        internal static string Hash_DoesNotMatch {
            get {
                return ResourceManager.GetString("Hash.DoesNotMatch", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input to compute hash required..
        /// </summary>
        internal static string Hash_InputRequired {
            get {
                return ResourceManager.GetString("Hash.InputRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input hash and verification hash match..
        /// </summary>
        internal static string Hash_Match {
            get {
                return ResourceManager.GetString("Hash.Match", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Verification hash required..
        /// </summary>
        internal static string Hash_VerificationHashRequired {
            get {
                return ResourceManager.GetString("Hash.VerificationHashRequired", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid base64 input string..
        /// </summary>
        internal static string Strings_InvalidInputBase64String {
            get {
                return ResourceManager.GetString("Strings.InvalidInputBase64String", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid hexadecimal input string..
        /// </summary>
        internal static string Strings_InvalidInputHexadecimalString {
            get {
                return ResourceManager.GetString("Strings.InvalidInputHexadecimalString", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Input string cannot be null, empty or white-space(s)..
        /// </summary>
        internal static string Strings_InvalidInputString {
            get {
                return ResourceManager.GetString("Strings.InvalidInputString", resourceCulture);
            }
        }
    }
}
