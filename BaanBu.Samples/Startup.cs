using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(IdentityWeb.Startup))]
namespace IdentityWeb
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
