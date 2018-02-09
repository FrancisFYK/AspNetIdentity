// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;

namespace BaanBu.Owin.Security.WeChat
{
    /// <summary>
    /// Configuration options for <see cref="WeChatAccountAuthenticationMiddleware"/>
    /// </summary>
    public class WeChatAccountAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new <see cref="WeChatAccountAuthenticationOptions"/>.
        /// </summary>
        public WeChatAccountAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-wechat");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            CookieManager = new CookieManager();

            AuthorizationEndpoint = Constants.AuthorizationEndpoint;
            TokenEndpoint = Constants.TokenEndpoint;
            UserInformationEndpoint = Constants.UserInformationEndpoint;
        }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to WeChat Account.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        /// <remarks>
        /// The default value is 'WeChat'
        /// </remarks>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The application client ID assigned by the WeChat authentication service.
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// The application client secret assigned by the WeChat authentication service.
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Gets or sets the URI where the client will be redirected to authenticate.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the OAuth token.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to obtain the user information.
        /// </summary>
        public string UserInformationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with WeChat.
        /// </summary>
        /// <value>
        /// The back channel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with WeChat.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-microsoft".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IWeChatAccountAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IWeChatAccountAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// An abstraction for reading and setting cookies during the authentication process.
        /// </summary>
        public ICookieManager CookieManager { get; set; }
    }
}
