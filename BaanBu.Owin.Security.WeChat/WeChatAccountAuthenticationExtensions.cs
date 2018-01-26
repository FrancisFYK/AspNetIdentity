// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Owin;

namespace BaanBu.Owin.Security.WeChat
{
    /// <summary>
    /// Extension methods for using <see cref="WeChatAccountAuthenticationMiddleware"/>
    /// </summary>
    public static class WeChatAccountAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using WeChat
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseWeChatAccountAuthentication(this IAppBuilder app, WeChatAccountAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WeChatAccountAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using WeChat Account
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The application client ID assigned by the WeChat authentication service</param>
        /// <param name="appSecret">The application client secret assigned by the WeChat authentication service</param>
        /// <returns></returns>
        public static IAppBuilder UseWeChatAccountAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseWeChatAccountAuthentication(
                app,
                new WeChatAccountAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,
                });
        }
    }
}
