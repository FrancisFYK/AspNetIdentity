// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace BaanBu.Owin.Security.WeChat
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class WeChatAccountAuthenticatedContext : BaseContext
    {

        #region Info

        //openid 普通用户的标识，对当前开发者帐号唯一
        //nickname    普通用户昵称
        //sex 普通用户性别，1为男性，2为女性
        //province    普通用户个人资料填写的省份
        //city    普通用户个人资料填写的城市
        //country 国家，如中国为CN
        //headimgurl  用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
        //privilege   用户特权信息，json数组，如微信沃卡用户为（chinaunicom）
        //unionid 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。

        #endregion

        /// <summary>
        /// Initializes a <see cref="WeChatAccountAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">The access token provided by the WeChat authentication service</param>
        /// <param name="refreshToken">The refresh token provided by WeChat authentication service</param>
        /// <param name="expires">Seconds until expiration</param>
        public WeChatAccountAuthenticatedContext(IOwinContext context, JObject user, string accessToken,
            string refreshToken, string expires)
            : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            IDictionary<string, JToken> userAsDictionary = user;

            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            OpenId = PropertyValueIfExists("openid", userAsDictionary);
            NickName = PropertyValueIfExists("nickname", userAsDictionary);
            Sex = PropertyValueIfExists("sex", userAsDictionary);
            HeadImgUrl = PropertyValueIfExists("headimgurl", userAsDictionary);
            Country = PropertyValueIfExists("country", userAsDictionary);
            Province = PropertyValueIfExists("province", userAsDictionary);
            City = PropertyValueIfExists("city", userAsDictionary);
            Privilege = PropertyValueIfExists("privilege", userAsDictionary);
            UnionId = PropertyValueIfExists("unionid", userAsDictionary);
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the access token provided by the WeChat authentication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the refresh token provided by WeChat authentication service
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the WeChat access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the user name
        /// </summary>
        public string NickName { get; private set; }

        /// <summary>
        /// 国家
        /// </summary>
        public string Country { get; set; }

        /// <summary>
        /// 省份
        /// </summary>
        public string Province { get; set; }

        /// <summary>
        ///  城市
        /// </summary>
        public string City { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string OpenId { get; set; }

        /// <summary>
        /// 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        public string UnionId { get; set; }

        /// <summary>
        /// 用户特权信息，json数组，如微信沃卡用户为（chinaunicom）
        /// </summary>
        public string Privilege { get; set; }

        /// <summary>
        /// 性别 如果获取不到则默认返回"男" 1为男性，2为女性
        /// </summary>
        public string Sex { get; set; }

        /// <summary>
        /// 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
        /// </summary>
        public string HeadImgUrl { get; set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string PropertyValueIfExists(string property, IDictionary<string, JToken> dictionary)
        {
            return dictionary.ContainsKey(property) ? dictionary[property].ToString() : null;
        }
    }
}
