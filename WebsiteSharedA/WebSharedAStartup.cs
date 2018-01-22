using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NLog.Owin.Logging;
using Owin;

[assembly: OwinStartup(typeof(WebsiteSharedA.WebsiteSharedAStartup))]

namespace WebsiteSharedA
{
    public class WebsiteSharedAStartup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websiteshareda",
                RedirectUri = "http://website-a.shared.sso.com/",
                ResponseType = "id_token",
                SignInAsAuthenticationType = "Cookies",
                Scope = "openid profile",
                UseTokenLifetime = true,
                PostLogoutRedirectUri = "http://website-a.shared.sso.com/",
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = n =>
                    {
                        var ci = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType, "name", "role");

                        ci.AddClaims(n.AuthenticationTicket.Identity.Claims);

                        // keep for logout
                        ci.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        ci.AddClaim(new Claim("session_state", n.ProtocolMessage.SessionState));

                        n.AuthenticationTicket = new AuthenticationTicket(ci, n.AuthenticationTicket.Properties);

                        return Task.CompletedTask;
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            n.ProtocolMessage.IdTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                        }

                        return Task.CompletedTask;
                    }
                }
            });

            app.Use(async (ctx, next) =>
            {
                var cp = ctx.Authentication.User;
                var cookie = ctx.Request.Cookies["idsrv.frontchannelsso"];

                if (cp == null || !cp.Identity.IsAuthenticated && !string.IsNullOrEmpty(cookie))
                {
                    ctx.Response.Redirect(ctx.Request.PathBase + "/Home/OidcSignIn");
                }

                await next();
            });
        }
    }
}
