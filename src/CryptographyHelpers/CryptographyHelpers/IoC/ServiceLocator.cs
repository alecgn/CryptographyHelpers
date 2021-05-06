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
        private IDictionary<Type, Type> servicesType;
        private IDictionary<Type, object> instantiatedServices;

        private ServiceLocator()
        {
            this.servicesType = new ConcurrentDictionary<Type, Type>();
            this.instantiatedServices = new ConcurrentDictionary<Type, object>();

            this.BuildServiceTypesMap();
        }

        internal T GetService<T>()
        {
            if (this.instantiatedServices.ContainsKey(typeof(T)))
            {
                return (T)this.instantiatedServices[typeof(T)];
            }
            else
            {
                try
                {
                    ConstructorInfo constructor = servicesType[typeof(T)].GetConstructor(Array.Empty<Type>());
                    Debug.Assert(constructor != null, "Cannot find a suitable constructor for " + typeof(T));
                    T service = (T)constructor.Invoke(null);
                    instantiatedServices.Add(typeof(T), service);

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
            //servicesType.Add(typeof(IService),
            //    typeof(Service));
        }
    }
}