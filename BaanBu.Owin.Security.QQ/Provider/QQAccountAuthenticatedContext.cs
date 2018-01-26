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
using static System.Int32;

namespace BaanBu.Owin.Security.QQ
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class QQAccountAuthenticatedContext : BaseContext
    {

        #region Info
        //{
        //    "ret": 0,
        //    "msg": "",
        //    "is_lost":0,
        //    "nickname": "Francis Fu",
        //    "gender": "男",
        //    "province": "江苏",
        //    "city": "徐州",
        //    "year": "1997",
        //    "figureurl": "http:\/\/qzapp.qlogo.cn\/qzapp\/101452737\/DCCB58B2D6FCDECF53C600702C7A5269\/30",
        //    "figureurl_1": "http:\/\/qzapp.qlogo.cn\/qzapp\/101452737\/DCCB58B2D6FCDECF53C600702C7A5269\/50",
        //    "figureurl_2": "http:\/\/qzapp.qlogo.cn\/qzapp\/101452737\/DCCB58B2D6FCDECF53C600702C7A5269\/100",
        //    "figureurl_qq_1": "http:\/\/q.qlogo.cn\/qqapp\/101452737\/DCCB58B2D6FCDECF53C600702C7A5269\/40",
        //    "figureurl_qq_2": "http:\/\/q.qlogo.cn\/qqapp\/101452737\/DCCB58B2D6FCDECF53C600702C7A5269\/100",
        //    "is_yellow_vip": "0",
        //    "vip": "0",
        //    "yellow_vip_level": "0",
        //    "level": "0",
        //    "is_yellow_year_vip": "0"
        //} 
        #endregion

        /// <summary>
        /// Initializes a <see cref="QQAccountAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="openId"></param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">The access token provided by the QQ authentication service</param>
        /// <param name="refreshToken">The refresh token provided by QQ authentication service</param>
        /// <param name="expires">Seconds until expiration</param>
        public QQAccountAuthenticatedContext(IOwinContext context, string openId, JObject user, string accessToken,
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

            if (TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            OpenId = openId;
            NickName = PropertyValueIfExists("nickname", userAsDictionary);
            Gender = PropertyValueIfExists("gender", userAsDictionary);
            FigureUrl = PropertyValueIfExists("figureurl", userAsDictionary);
            FigureUrl_1 = PropertyValueIfExists("figureurl_1", userAsDictionary);
            FigureUrl_2 = PropertyValueIfExists("figureurl_2", userAsDictionary);
            Figureurl_Qq_1 = PropertyValueIfExists("figureurl_qq_1", userAsDictionary);
            Figureurl_Qq_2 = PropertyValueIfExists("figureurl_qq_2", userAsDictionary);
            Province = PropertyValueIfExists("province", userAsDictionary);
            City = PropertyValueIfExists("city", userAsDictionary);
            Year = PropertyValueIfExists("year", userAsDictionary);
            IsYellowVip = PropertyValueIfExists("is_yellow_vip", userAsDictionary);
            Vip = PropertyValueIfExists("vip", userAsDictionary);
            YellowVipLevel = PropertyValueIfExists("yellow_vip_level", userAsDictionary);
            Level = PropertyValueIfExists("level", userAsDictionary);
            IsYellowYearVip = PropertyValueIfExists("is_yellow_year_vip", userAsDictionary);
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the access token provided by the QQ authentication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the refresh token provided by QQ authentication service
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the QQ access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the user name
        /// </summary>
        public string NickName { get; private set; }

        /// <summary>
        /// 省份
        /// </summary>
        public string Province { get; set; }

        /// <summary>
        /// 城市
        /// </summary>
        public string City { get; set; }

        /// <summary>
        /// 出生年月
        /// </summary>
        public string Year { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string OpenId { get; set; }

        /// <summary>
        /// 性别。 如果获取不到则默认返回"男"
        /// </summary>
        public string Gender { get; set; }

        /// <summary>
        /// 大小为30×30像素的QQ空间头像URL
        /// </summary>
        public string FigureUrl { get; set; }

        /// <summary>
        /// 大小为50×50像素的QQ空间头像URL
        /// </summary>
        public string FigureUrl_1 { get; set; }
        /// <summary>
        /// 大小为100×100像素的QQ空间头像URL
        /// </summary>
        public string FigureUrl_2 { get; set; }

        /// <summary>
        /// 大小为40×40像素的QQ头像URL
        /// </summary>
        public string Figureurl_Qq_1 { get; set; }

        /// <summary>
        /// 大小为100×100像素的QQ头像URL。需要注意，不是所有的用户都拥有QQ的100x100的头像，但40x40像素则是一定会有
        /// </summary>
        public string Figureurl_Qq_2 { get; set; }

        /// <summary>
        /// 标识用户是否为黄钻用户（0：不是；1：是）
        /// </summary>
        public string IsYellowVip { get; set; }
        /// <summary>
        /// 标识用户是否为黄钻用户（0：不是；1：是）
        /// </summary>
        public string Vip { get; set; }

        /// <summary>
        /// 黄钻等级
        /// </summary>
        public string YellowVipLevel { get; set; }

        /// <summary>
        /// 黄钻等级
        /// </summary>
        public string Level { get; set; }

        /// <summary>
        /// 标识是否为年费黄钻用户（0：不是； 1：是）
        /// </summary>
        public string IsYellowYearVip { get; set; }

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
