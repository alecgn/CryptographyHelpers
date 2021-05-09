using CryptographyHelpers.Encoding;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;

namespace CryptographyHelpers.IoC
{
    internal sealed class ServiceLocator
    {
        internal static ServiceLocator Instance { get { return _lazyInstance.Value; } }
        
        private static readonly Lazy<ServiceLocator> _lazyInstance = new(() => new ServiceLocator());
        private IDictionary<Type, Type> _servicesType;
        private IDictionary<Type, object> _instantiatedServices;

        private ServiceLocator()
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
                    Debug.Assert(constructor != null, $"Cannot find a suitable constructor for {typeof(T)}.");
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
        }
    }
}