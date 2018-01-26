using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.Remoting.Contexts;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using BaanBu.Owin.Security.QQ;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace BaanBu.Owin.Security.QQ.Test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
        }
        [TestMethod]
        public async Task RequestTest()
        {
            HttpClient _httpClient = new HttpClient();
            var opneIdRequest = new HttpRequestMessage(HttpMethod.Get, "https://graph.qq.com/oauth2.0/me?access_token=415AC27295DF33B910826DC38C610798");
            var openIdResponse = await _httpClient.SendAsync(opneIdRequest);
            openIdResponse.EnsureSuccessStatusCode();
            string openIdString = await openIdResponse.Content.ReadAsStringAsync();
            Console.WriteLine(openIdString);
            Assert.IsNotNull(openIdString);
        }

        [TestMethod]
        public void JsonParse()
        {
            var str = "access_token=415AC27295DF33B910826DC38C610798&expires_in=7776000&refresh_token=8A7850822E1891376DE4CD65B85500B5";
            var tokenParams = str.Split('&');
            var oauth2Token = new Dictionary<string, string>();
            foreach (var tokenParam in tokenParams)
            {
                oauth2Token.Add(tokenParam.Split('=')[0], tokenParam.Split('=')[1]);
            }

            var accessToken = oauth2Token["access_token"];
            Assert.IsNotNull(accessToken);
        }

        [TestMethod]
        public void RegexOpenId()
        {
            var str = "callback( {\"client_id\":\"101452737\",\"openid\":\"DCCB58B2D6FCDECF53C600702C7A5269\"} );";
            Regex reg = new Regex("^callback\\( (.*) \\);$");
            //例如我想提取记录中的NAME值
            Match match = reg.Match(str);
            string value = match.Groups[1].Value;
            JObject openIdInfo = JObject.Parse(value);
            var openId = openIdInfo["openid"].Value<string>();
            var clientId = openIdInfo["client_id"].Value<string>();
            Console.WriteLine(openId);
            Console.WriteLine(clientId);
            Assert.IsNotNull(openId);
        }

        [TestMethod]
        public async Task QqGetUserInfo()
        {
            var graphRequest = new HttpRequestMessage(HttpMethod.Get, $"https://graph.qq.com/user/get_user_info?access_token=415AC27295DF33B910826DC38C610798&oauth_consumer_key=101452737&openid=DCCB58B2D6FCDECF53C600702C7A5269");
            HttpClient _httpClient = new HttpClient();
            var graphResponse = await _httpClient.SendAsync(graphRequest);
            graphResponse.EnsureSuccessStatusCode();
            string accountString = await graphResponse.Content.ReadAsStringAsync();
            JObject accountInformation = JObject.Parse(accountString);
            var ret = accountInformation.Value<string>("ret");
            if (ret != "0")
            {
                var msg = accountInformation.Value<string>("msg");
            }
            var context = new QQAccountAuthenticatedContext(null, "DCCB58B2D6FCDECF53C600702C7A5269", accountInformation, "415AC27295DF33B910826DC38C610798",
                "DCCB58B2D6FCDECF53C600702C7A5269", "DCCB58B2D6FCDECF53C600702C7A5269");
        
            Assert.IsNotNull(context);
        }
    }
}
