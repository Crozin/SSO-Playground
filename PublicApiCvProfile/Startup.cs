using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web.Http;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using NLog.Owin.Logging;
using Owin;

[assembly: OwinStartup(typeof(PublicApiCvProfile.Startup))]

namespace PublicApiCvProfile
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            /*
             * To API reprezentuje "bezpośredni kontakt z użytkownikiem" w łańcuchu wywołań. Pod spodem będzie ono wykonywało
             * żądania do innych, wewnętrznych API-ów uwierzytelniając jako "użytkownik X przy wykorzystaniu aplikacji".
             * Ten scenariusz będzie realizować w następujący sposób: https://identityserver4.readthedocs.io/en/release/topics/extension_grants.html
             * 
             * Ważna informacja: dane cv-profilowe to zasób użytkownika jak pliki czy zdjęcia (ResourceType), nie dane n/t użytkownika (IdentityType)
             * dlatego standardowo korzystamy z access_tokena, nie identity_tokena.
             */

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseNLog();

            var httpConfiguration = new HttpConfiguration();

            httpConfiguration.Formatters.Where(f => f != httpConfiguration.Formatters.JsonFormatter).ToList().ForEach(f => httpConfiguration.Formatters.Remove(f));
            httpConfiguration.MapHttpAttributeRoutes();

            app.UseCors(CorsOptions.AllowAll);

            app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                PreserveAccessToken = true,
                RequiredScopes = new[] { "api_cv_profile" }
            });

            app.UseWebApi(httpConfiguration);
        }
    }
}
