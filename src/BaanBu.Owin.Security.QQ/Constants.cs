namespace BaanBu.Owin.Security.QQ
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "QQ";
        //https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=101452737&redirect_uri=http://qq.baanbu.com&scope=
        /// <summary>
        /// 
        /// </summary>
        internal const string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";
        /// <summary>
        /// 
        /// </summary>
        internal const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";

        /// <summary>
        /// 
        /// </summary>
        internal const string UserInformationEndpoint = "https://graph.qq.com/user/get_user_info";

        /// <summary>
        /// 
        /// </summary>
        internal const string OpenIdEndpoint = "https://graph.qq.com/oauth2.0/me";
    }
}
