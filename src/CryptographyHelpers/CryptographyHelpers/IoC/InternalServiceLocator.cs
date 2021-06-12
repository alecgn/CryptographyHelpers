using CryptographyHelpers.Encoding;
using CryptographyHelpers.Hash;
using CryptographyHelpers.HMAC;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;

namespace CryptographyHelpers.IoC
{
    internal sealed class InternalServiceLocator
    {
        internal static InternalServiceLocator Instance { get { return _lazyInstance.Value; } }
        
        private static readonly Lazy<InternalServiceLocator> _lazyInstance = new(() => new InternalServiceLocator());
        private IDictionary<Type, Type> _servicesType;
        private IDictionary<Type, object> _instantiatedServices;

        private InternalServiceLocator()
        {
            this._servicesType = new ConcurrentDictionary<Type, Type>();
            this._instantiatedServices = new ConcurrentDictionary<Type, object>();

            this.BuildServiceTypesMap();
        }

        internal T GetService<T>()
        {
            if (this._instantiatedServices.ContainsKey(typeof(T)))
            {
                return (T)this._instantiatedServices[typeof(T)];
            }
            else
            {
                try
                {
                    ConstructorInfo constructor = _servicesType[typeof(T)].GetConstructor(Array.Empty<Type>());

                    if (constructor is null)
                    {
                        throw new ApplicationException($"Cannot find a suitable constructor for {typeof(T)}.");
                    }

                    T service = (T)constructor.Invoke(null);
                    _instantiatedServices.Add(typeof(T), service);

                    return service;
                }
                catch (KeyNotFoundException)
                {
                    throw new ApplicationException("The requested service is not registered");
                }
            }
        }

        private void BuildServiceTypesMap()
        {
            _servicesType.Add(typeof(IBase64), typeof(Base64));
            _servicesType.Add(typeof(IHexadecimal), typeof(Hexadecimal));
            _servicesType.Add(typeof(IMD5), typeof(MD5));
            _servicesType.Add(typeof(ISHA1), typeof(SHA1));
            _servicesType.Add(typeof(ISHA256), typeof(SHA256));
            _servicesType.Add(typeof(ISHA384), typeof(SHA384));
            _servicesType.Add(typeof(ISHA512), typeof(SHA512));
            _servicesType.Add(typeof(IHMACMD5), typeof(HMACMD5));
            _servicesType.Add(typeof(IHMACSHA1), typeof(HMACSHA1));
            _servicesType.Add(typeof(IHMACSHA256), typeof(HMACSHA256));
            _servicesType.Add(typeof(IHMACSHA384), typeof(HMACSHA384));
            _servicesType.Add(typeof(IHMACSHA512), typeof(HMACSHA512));
        }
    }
}