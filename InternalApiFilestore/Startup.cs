using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web.Http;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin;
using NLog.Owin.Logging;
using Owin;

[assembly: OwinStartup(typeof(InternalApiFilestore.Startup))]

namespace InternalApiFilestore
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            /*
             * To API reprezentuje "najniższy poziom" w łańcuchu wywołań. Nie ma ono już żadnych dalszych powiązań.
             * Jest to najprostszy przykład, reprezentujący już API operujące na konkretnym zasobie - raczej nie przeznaczone
             * do bezpośredniego odpytwania przez użytkowników.
             * Wymaga odpowiedniego Scope'a by w ogóle dostać się do niego oraz definiuje x Claimów precyzujących dostęp.
             * Nic nie stoi na przeszkodzie by pojedynczy Claim na wzór Scope'a również był wymagany w celu ogólnego dostępu.
             */

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseNLog();

            var httpConfiguration = new HttpConfiguration();

            httpConfiguration.Formatters.Where(f => f != httpConfiguration.Formatters.JsonFormatter).ToList().ForEach(f => httpConfiguration.Formatters.Remove(f));
            httpConfiguration.MapHttpAttributeRoutes();

            app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                RequiredScopes = new[] { "api_filestore" }
            });

            app.UseWebApi(httpConfiguration);
        }
    }
}
