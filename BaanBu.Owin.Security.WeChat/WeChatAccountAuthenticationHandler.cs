// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace BaanBu.Owin.Security.WeChat
{
    internal class WeChatAccountAuthenticationHandler : AuthenticationHandler<WeChatAccountAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeChatAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
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
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };
                var queryString = tokenRequestParameters.Aggregate("", (current, tokenRequestParameter) => current + (tokenRequestParameter.Key + "=" + tokenRequestParameter.Value + "&"));

                queryString = queryString.Remove(queryString.Length - 1, 1);

                HttpResponseMessage response = await _httpClient.GetAsync(Options.TokenEndpoint + "?" + queryString);
                response.EnsureSuccessStatusCode();
                var oauthTokenResponse = await response.Content.ReadAsStringAsync();

                JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                var accessToken = oauth2Token.Value<string>("access_token");
                var refreshToken = oauth2Token.Value<string>("refresh_token");
                var expire = oauth2Token.Value<string>("expires_in");
                var scope = oauth2Token.Value<string>("scope");
                var openId = oauth2Token.Value<string>("openid");
                var unionId = oauth2Token.Value<string>("unionid");

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                #region Get UserInfo

                var graphRequest = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint + $"?access_token={accessToken}&openid={openId}");
                var graphResponse = await _httpClient.SendAsync(graphRequest, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                string accountString = await graphResponse.Content.ReadAsStringAsync();
                JObject accountInformation = JObject.Parse(accountString);

                var errcode = accountInformation.Value<string>("errcode");
                if (!string.IsNullOrWhiteSpace(errcode))
                {
                    var errmsg = accountInformation.Value<string>("errmsg");
                    _logger.WriteWarning(errmsg);
                    return new AuthenticationTicket(null, properties);
                }
                #endregion
                var context = new WeChatAccountAuthenticatedContext(Context, accountInformation, accessToken,
                    refreshToken, expire);

                context.Identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.NickName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:openid", context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:nickname", context.NickName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:sex", context.Sex, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:headimgurl", context.HeadImgUrl, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:country", context.Country, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:province", context.Province, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("wechataccount:city", context.City, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:unionid", context.UnionId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("qqaccount:privilege", context.Privilege, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
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
                    scope = "snsapi_login";
                }

                //https://open.weixin.qq.com/connect/qrconnect?appid=wxc03b938685ab0b74&redirect_uri=http://jiayuan.sunnyroofs.cn&response_type=code&scope=snsapi_login&state=STATE#wechat_redirect

                string state = Options.StateDataFormat.Protect(extra);

                string authorizationEndpoint =
                    Options.AuthorizationEndpoint +
                    "?appid=" + Uri.EscapeDataString(Options.AppId) +
                    "&scope=" + Uri.EscapeDataString(scope) +
                    "&response_type=code" +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
                + "&state=" + Uri.EscapeDataString(state);

                var redirectContext = new WeChatAccountApplyRedirectContext(
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

            var context = new WeChatAccountReturnEndpointContext(Context, model);
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
