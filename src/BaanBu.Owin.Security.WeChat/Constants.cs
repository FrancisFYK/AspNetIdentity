// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace BaanBu.Owin.Security.WeChat
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "WeChat";
        //https://open.weixin.qq.com/connect/qrconnect?appid=wxc03b938685ab0b74&redirect_uri=http://jiayuan.sunnyroofs.cn&response_type=code&scope=snsapi_login&state=STATE#wechat_redirect
        /// <summary>
        /// 
        /// </summary>
        internal const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        /// <summary>
        /// 
        /// </summary>
        internal const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";

        /// <summary>
        /// 
        /// </summary>
        internal const string UserInformationEndpoint = "https://api.weixin.qq.com/sns/userinfo";
    }
}
