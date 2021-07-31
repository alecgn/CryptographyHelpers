using CryptographyHelpers.Text.Encoding;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;

namespace CryptographyHelpers.IoC
{
    // Yeah, I know ServiceLocator is an anti-pattern, but we don't want our user to resolve our internal dependencies do we ?
    internal sealed class InternalServiceLocator
    {
        internal static InternalServiceLocator Instance { get { return _lazyInstance.Value; } }

        private static readonly Lazy<InternalServiceLocator> _lazyInstance = new Lazy<InternalServiceLocator>(() => new InternalServiceLocator());
        private IDictionary<Type, Type> _servicesType;
        private IDictionary<Type, object> _instantiatedServices;

        private InternalServiceLocator()
        {
            _servicesType = new ConcurrentDictionary<Type, Type>();
            _instantiatedServices = new ConcurrentDictionary<Type, object>();

            BuildServiceTypesMap();
        }

        internal T GetService<T>()
        {
            if (_instantiatedServices.ContainsKey(typeof(T)))
            {
                return (T)_instantiatedServices[typeof(T)];
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
            _servicesType.Add(typeof(IBase64Encoder), typeof(Base64Encoder));
            _servicesType.Add(typeof(IHexadecimalEncoder), typeof(HexadecimalEncoder));
        }
    }
}