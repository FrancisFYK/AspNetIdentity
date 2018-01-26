// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace BaanBu.Owin.Security.QQ
{
    internal class QQAccountAuthenticationHandler : AuthenticationHandler<QQAccountAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public QQAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(Options.CookieManager, properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                var requestContent = new FormUrlEncodedContent(tokenRequestParameters);
                HttpResponseMessage response = await _httpClient.PostAsync(Options.TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                var oauthTokenResponse = await response.Content.ReadAsStringAsync();

                var tokenParams = oauthTokenResponse.Split('&');
                var oauth2Token = new Dictionary<string, string>();
                foreach (var tokenParam in tokenParams)
                {
                    oauth2Token.Add(tokenParam.Split('=')[0], tokenParam.Split('=')[1]);
                }

                var accessToken = oauth2Token["access_token"];
                // Refresh token is only available when wl.offline_access is request.
                // Otherwise, it is null.
                var refreshToken = oauth2Token["refresh_token"];
                var expire = oauth2Token["expires_in"];

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                #region  Get OpenId
                //https://graph.qq.com/oauth2.0/me?access_token=
                var opneIdRequest = new HttpRequestMessage(HttpMethod.Get, Options.OpenIdEndpoint + "?access_token=" + accessToken);
                var openIdResponse = await _httpClient.SendAsync(opneIdRequest, Request.CallCancelled);
                openIdResponse.EnsureSuccessStatusCode();
                string openIdString = await openIdResponse.Content.ReadAsStringAsync();
                //callback( {"client_id":"","openid":""} );

                Regex reg = new Regex("^callback\\( (.*) \\);$");
                //例如我想提取记录中的NAME值
                Match match = reg.Match(openIdString);
                string callbackObj = match.Groups[1].Value;

                JObject openIdInfo = JObject.Parse(callbackObj);
                var openId = openIdInfo["openid"].Value<string>();
                var clientId = openIdInfo["client_id"].Value<string>();

                if (string.IsNullOrWhiteSpace(openId))
                {
                    var description = openIdInfo["error_description"].Value<string>();
                    _logger.WriteWarning(description);
                    return new AuthenticationTicket(null, properties);
                }
                #endregion

                #region Get UserInfo
                //https://graph.qq.com/user/get_user_info?access_token=415AC27295DF33B910826DC38C610798&oauth_consumer_key=101452737&openid=DCCB58B2D6FCDECF53C600702C7A5269

                var graphRequest = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint + $"?access_token={accessToken}&oauth_consumer_key={clientId}&openid={openId}");
                var graphResponse = await _httpClient.SendAsync(graphRequest, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                string accountString = await graphResponse.Content.ReadAsStringAsync();
                JObject accountInformation = JObject.Parse(accountString);
                var ret = accountInformation.Value<string>("ret");
                if (ret != "0")
                {
                    var msg = accountInformation.Value<string>("msg");
                    _logger.WriteWarning(msg);
                    return new AuthenticationTicket(null, properties);
                }
                #endregion
                var context = new QQAccountAuthenticatedContext(Context, openId, accountInformation, accessToken,
                    refreshToken, expire);

                context.Identity = new ClaimsIdentity(
                    new[]
                    {
                        //Private Key
                        new Claim(ClaimTypes.NameIdentifier, context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.NickName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:openid", context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:nickname", context.NickName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:gender", context.Gender, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:province", context.Province, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:city", context.City, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:year", context.Year, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:figureurl", context.FigureUrl, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:figureurl_1", context.FigureUrl_1, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:figureurl_2", context.FigureUrl_2, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:figureurl_qq_1", context.Figureurl_Qq_1, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:figureurl_qq_2", context.Figureurl_Qq_2, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:is_yellow_vip", context.IsYellowVip, "http://www.w3.org/2001/XMLSchema#bool", Options.AuthenticationType),
                        new Claim("qqaccount:vip", context.Vip, "http://www.w3.org/2001/XMLSchema#bool", Options.AuthenticationType),
                        new Claim("qqaccount:yellow_vip_level", context.YellowVipLevel, "http://www.w3.org/2001/XMLSchema#int", Options.AuthenticationType),
                        new Claim("qqaccount:level", context.Level, "http://www.w3.org/2001/XMLSchema#int", Options.AuthenticationType),
                        new Claim("qqaccount:is_yellow_year_vip", context.IsYellowYearVip, "http://www.w3.org/2001/XMLSchema#bool", Options.AuthenticationType),

                    }, Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                context.Properties = properties;
                await Options.Provider.Authenticated(context);
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;

                string currentUri = baseUri + Request.Path + Request.QueryString;

                string redirectUri = baseUri + Options.CallbackPath;

                AuthenticationProperties extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(Options.CookieManager, extra);

                // OAuth2 3.3 space separated                
                string scope = string.Join(" ", Options.Scope);
                // LiveID requires a scope string, so if the user didn't set one we go for the least possible.
                if (string.IsNullOrWhiteSpace(scope))
                {
                    scope = "";
                }

                //https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=[YOUR_APPID]&redirect_uri=[YOUR_REDIRECT_URI]&scope=[THE_SCOPE]

                string state = Options.StateDataFormat.Protect(extra);

                string authorizationEndpoint =
                    Options.AuthorizationEndpoint +
                    "?client_id=" + Uri.EscapeDataString(Options.AppId) +
                    "&scope=" + Uri.EscapeDataString(scope) +
                    "&response_type=code" +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
                + "&state=" + Uri.EscapeDataString(state);

                var redirectContext = new QQAccountApplyRedirectContext(
                    Context, Options,
                    extra, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await AuthenticateAsync();
            if (model == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new QQAccountReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));            
            return redirectUri;
        }
    }
}
