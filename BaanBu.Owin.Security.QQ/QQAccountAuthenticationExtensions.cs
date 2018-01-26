// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Owin;

namespace BaanBu.Owin.Security.QQ
{
    /// <summary>
    /// Extension methods for using <see cref="QQAccountAuthenticationMiddleware"/>
    /// </summary>
    public static class QQAccountAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using QQ Account
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseQQAccountAuthentication(this IAppBuilder app, QQAccountAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(QQAccountAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using QQ Account
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The application client ID assigned by the QQ authentication service</param>
        /// <param name="appSecret">The application client secret assigned by the QQ authentication service</param>
        /// <returns></returns>
        public static IAppBuilder UseQQAccountAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseQQAccountAuthentication(
                app,
                new QQAccountAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,
                });
        }
    }
}
